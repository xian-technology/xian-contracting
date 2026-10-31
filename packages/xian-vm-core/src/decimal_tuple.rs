//! The immutable named tuple returned by Decimal.as_tuple().

use crate::{VmExecutionError, VmValue};

/// Decimal's exponent field is an integer or a special-value marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmDecimalExponent {
    Finite(i32),
    Infinity,
    QuietNaN,
    SignalingNaN,
}

impl VmDecimalExponent {
    fn as_value(self) -> VmValue {
        match self {
            Self::Finite(value) => VmValue::Int(value.into()),
            Self::Infinity => VmValue::String("F".into()),
            Self::QuietNaN => VmValue::String("n".into()),
            Self::SignalingNaN => VmValue::String("N".into()),
        }
    }
}

/// Validated Decimal components with ordinary tuple-field identity.
/// The heap captures fields once; `as_values` clones their shared references.
#[derive(Debug, Clone, PartialEq)]
pub struct VmDecimalTuple {
    fields: Box<[VmValue; 3]>,
}

impl VmDecimalTuple {
    pub fn new(
        sign: bool,
        digits: Vec<u8>,
        exponent: VmDecimalExponent,
    ) -> Result<Self, VmExecutionError> {
        if digits.iter().any(|digit| *digit > 9) {
            return Err(VmExecutionError::new(
                "DecimalTuple digits must be between 0 and 9",
            ));
        }
        Ok(Self {
            fields: Box::new([
                VmValue::Int(u8::from(sign).into()),
                VmValue::Tuple(
                    digits
                        .into_iter()
                        .map(|digit| VmValue::Int(digit.into()))
                        .collect(),
                ),
                exponent.as_value(),
            ]),
        })
    }

    /// Consume the finite/special components provided by the decimal backend.
    pub fn from_parts(
        sign: bool,
        digits: Vec<u8>,
        finite_exponent: Option<i32>,
        special: Option<char>,
    ) -> Result<Self, VmExecutionError> {
        let exponent = match (finite_exponent, special) {
            (Some(value), None) => VmDecimalExponent::Finite(value),
            (None, Some('F')) => VmDecimalExponent::Infinity,
            (None, Some('n')) => VmDecimalExponent::QuietNaN,
            (None, Some('N')) => VmDecimalExponent::SignalingNaN,
            _ => return Err(VmExecutionError::new("invalid DecimalTuple exponent")),
        };
        Self::new(sign, digits, exponent)
    }

    pub fn as_values(&self) -> Vec<VmValue> {
        self.fields.to_vec()
    }

    pub(crate) fn fields(&self) -> &[VmValue] {
        self.fields.as_slice()
    }

    pub(crate) fn map_fields(
        self,
        mut map: impl FnMut(VmValue) -> Result<VmValue, VmExecutionError>,
    ) -> Result<Self, VmExecutionError> {
        let [sign, digits, exponent] = *self.fields;
        Ok(Self {
            fields: Box::new([map(sign)?, map(digits)?, map(exponent)?]),
        })
    }

    pub(crate) fn allocation_bytes(&self) -> usize {
        std::mem::size_of::<[VmValue; 3]>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finite_fields_and_repr_preserve_digits_and_exponent() {
        let tuple = VmDecimalTuple::from_parts(false, vec![2, 5, 0, 0], Some(-3), None).unwrap();
        assert_eq!(
            tuple.as_values(),
            vec![
                VmValue::Int(0.into()),
                VmValue::Tuple(vec![
                    VmValue::Int(2.into()),
                    VmValue::Int(5.into()),
                    VmValue::Int(0.into()),
                    VmValue::Int(0.into())
                ]),
                VmValue::Int((-3).into()),
            ]
        );
        let value = VmValue::DecimalTuple(tuple);
        assert_eq!(value.type_name(), "DecimalTuple");
        assert_eq!(
            value.python_repr(),
            "DecimalTuple(sign=0, digits=(2, 5, 0, 0), exponent=-3)"
        );
        assert!(value.truthy());
        assert_eq!(value.storage_value().unwrap(), value);
    }

    #[test]
    fn special_values_keep_python_exponent_tokens() {
        for (digits, token, expected) in [
            (
                vec![0],
                'F',
                "DecimalTuple(sign=1, digits=(0,), exponent='F')",
            ),
            (vec![], 'n', "DecimalTuple(sign=1, digits=(), exponent='n')"),
            (
                vec![4, 2],
                'N',
                "DecimalTuple(sign=1, digits=(4, 2), exponent='N')",
            ),
        ] {
            let value = VmValue::DecimalTuple(
                VmDecimalTuple::from_parts(true, digits, None, Some(token)).unwrap(),
            );
            assert_eq!(value.python_repr(), expected);
            assert_eq!(
                VmValue::List(vec![value]).python_repr(),
                format!("[{expected}]")
            );
        }
    }

    #[test]
    fn tuple_iteration_preserves_field_types() {
        let tuple = VmDecimalTuple::from_parts(false, vec![3, 1], Some(-1), None).unwrap();
        let expected = tuple.as_values();
        let heap = crate::heap::VmHeap::default();
        let source = heap.capture(VmValue::DecimalTuple(tuple)).unwrap();
        let actual =
            crate::iteration::collect(&source, &heap, &mut |_, _| panic!("unexpected callback"))
                .unwrap();
        let actual = actual
            .iter()
            .map(|item| item.detached().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }

    #[test]
    fn named_tuple_rendering_obeys_output_limit() {
        let tuple = VmDecimalTuple::from_parts(false, vec![1; 50_000], Some(0), None).unwrap();
        assert!(VmValue::DecimalTuple(tuple).try_python_repr().is_err());
    }

    #[test]
    fn captured_tuple_fields_keep_identity() {
        let tuple = VmDecimalTuple::from_parts(false, vec![2, 5], Some(-1), None).unwrap();
        let heap = crate::heap::VmHeap::default();
        let source = heap.capture(VmValue::DecimalTuple(tuple)).unwrap();
        let VmValue::DecimalTuple(tuple) = source.snapshot() else {
            panic!("wrong value type")
        };
        let first = tuple.as_values();
        let second = tuple.as_values();
        assert!(first[1].identical(&second[1]));
        let iterated =
            crate::iteration::collect(&source, &heap, &mut |_, _| panic!("unexpected callback"))
                .unwrap();
        assert!(first[1].identical(&iterated[1]));
        let VmValue::DecimalTuple(detached) = source.detached().unwrap() else {
            panic!("wrong detached type")
        };
        assert_eq!(detached.as_values()[1], first[1].detached().unwrap());
    }

    #[test]
    fn malformed_components_are_rejected() {
        assert!(VmDecimalTuple::from_parts(false, vec![10], Some(0), None).is_err());
        assert!(VmDecimalTuple::from_parts(false, vec![1], None, None).is_err());
        assert!(VmDecimalTuple::from_parts(false, vec![1], Some(0), Some('n')).is_err());
        assert!(VmDecimalTuple::from_parts(false, vec![1], None, Some('x')).is_err());
    }
}
