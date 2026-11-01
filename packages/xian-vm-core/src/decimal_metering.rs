//! Additional comparison work admitted by exact Decimal constructors.
//!
//! The historical <=91-digit domain keeps its exact chi. Profiles borrow heap
//! values, memoize shared subgraphs, and bound traversal independently of work
//! estimates. Logical multiplicities remain in the estimate: a repeated value
//! can still participate in every pair of a quadratic container operation.
use crate::{VmExecutionError, VmHost, VmValue};
use num_bigint::BigInt;
use std::collections::{HashMap, HashSet};

type Result<T> = std::result::Result<T, VmExecutionError>;
const MAX_DEPTH: usize = 128;
const MAX_PROFILE_NODES: usize = 1024 * 1024;

#[derive(Clone, Copy, Default)]
struct Profile {
    raw: bool,
    work: u64,
    nodes: u64,
    cyclic: bool,
    truncated: bool,
}

impl Profile {
    fn add(&mut self, other: Self) {
        self.raw |= other.raw;
        self.cyclic |= other.cyclic;
        self.truncated |= other.truncated;
        self.work = self.work.saturating_add(other.work);
        self.nodes = self.nodes.saturating_add(other.nodes);
    }
    fn pair(self, other: Self) -> u64 {
        if !self.raw && !other.raw {
            return 0;
        }
        let work = self
            .work
            .saturating_mul(other.nodes)
            .saturating_add(other.work.saturating_mul(self.nodes));
        if self.cyclic || other.cyclic {
            work.saturating_mul(MAX_DEPTH as u64)
        } else {
            work
        }
    }
}

#[derive(Default)]
struct Walker {
    memo: HashMap<usize, Profile>,
    active: HashSet<usize>,
    visited: usize,
}

impl Walker {
    fn reference(&mut self, reference: &crate::VmReference, depth: usize) -> Result<Profile> {
        let id = reference.id();
        if let Some(profile) = self.memo.get(&id) {
            return Ok(*profile);
        }
        if !self.active.insert(id) {
            return Ok(Profile {
                nodes: 1,
                cyclic: true,
                ..Profile::default()
            });
        }
        let profile = reference.with_value(|value| self.value(value, depth))?;
        self.active.remove(&id);
        if !profile.truncated {
            self.memo.insert(id, profile);
        }
        Ok(profile)
    }

    fn value(&mut self, value: &VmValue, depth: usize) -> Result<Profile> {
        if let VmValue::Reference(reference) = value {
            return self.reference(reference, depth);
        }
        // Comparators reject deeper recursion themselves. Do not preempt their
        // shallow mismatches or identity shortcuts merely because a graph is deep.
        if depth > MAX_DEPTH {
            return Ok(Profile {
                truncated: true,
                ..Profile::default()
            });
        }
        self.visited += 1;
        if self.visited > MAX_PROFILE_NODES {
            return Err(VmExecutionError::new(
                "comparison profile resource limit exceeded",
            ));
        }
        if let Some(profile) = scalar(value) {
            return Ok(profile);
        }
        self.container(value, depth)
    }

    fn container(&mut self, value: &VmValue, depth: usize) -> Result<Profile> {
        let mut profile = Profile {
            nodes: 1,
            ..Profile::default()
        };
        match value {
            VmValue::List(values)
            | VmValue::Tuple(values)
            | VmValue::Set(values) | VmValue::BuiltinSet(values)
            | VmValue::FrozenSet(values) => profile.add(self.values(values, depth + 1)?),
            VmValue::DecimalTuple(value) => profile.add(self.values(value.fields(), depth + 1)?),
            VmValue::Dict(entries) => {
                for (key, value) in entries {
                    profile.add(self.value(key, depth + 1)?);
                    profile.add(self.value(value, depth + 1)?);
                }
            }
            _ => {}
        }
        Ok(profile)
    }
    fn values(&mut self, values: &[VmValue], depth: usize) -> Result<Profile> {
        let mut profile = Profile::default();
        for value in values {
            profile.add(self.value(value, depth)?);
        }
        Ok(profile)
    }
}

fn scalar(value: &VmValue) -> Option<Profile> {
    let mut profile = Profile {
        nodes: 1,
        ..Profile::default()
    };
    match value {
        VmValue::RawDecimal(value) => {
            profile.raw = true;
            profile.work = coefficient_work(&value.coefficient);
        }
        VmValue::Int(value) => profile.work = coefficient_work(value),
        // Binary64 conversion is independently bounded (at most751 digits).
        VmValue::Float(value) => {
            if let Ok(exact) = crate::VmRawDecimal::from_float(*value) {
                profile.work = coefficient_work(&exact.coefficient);
            }
        }
        _ => return None,
    }
    Some(profile)
}

fn coefficient_work(value: &BigInt) -> u64 {
    let bits = value.bits();
    // Only a 303-bit boundary coefficient needs a short decimal conversion to
    // distinguish 91 from 92 digits. Large coefficients are never formatted here.
    if bits < 303 || (bits == 303 && value.to_str_radix(10).trim_start_matches('-').len() <= 91) {
        return 0;
    }
    // Allow for repeated coefficient conversion/normalization in comparison.
    bits.saturating_mul(bits.div_ceil(64)).saturating_mul(4)
}

fn charge(host: &mut dyn VmHost, work: u64) -> Result<()> {
    if work != 0 {
        host.charge_execution_cost(work)?;
    }
    Ok(())
}

pub(crate) fn comparison(
    host: &mut dyn VmHost,
    left: &VmValue,
    right: &VmValue,
    identity_shortcut: bool,
) -> Result<()> {
    if identity_shortcut && left.identical(right) {
        return Ok(());
    }
    let mut walker = Walker::default();
    let left = walker.value(left, 0)?;
    let right = walker.value(right, 0)?;
    charge(host, left.pair(right))
}

pub(crate) fn normalization(host: &mut dyn VmHost, values: &[VmValue]) -> Result<()> {
    let profile = Walker::default().values(values, 0)?;
    charge(host, profile.pair(profile))
}

/// A native set method may consume several lazy operands. Charge before each
/// normalization and all new comparisons with the receiver/earlier operands.
#[derive(Default)]
pub(crate) struct SetInputs {
    previous: Profile,
}
impl SetInputs {
    pub(crate) fn new(receiver: &VmValue) -> Result<Self> {
        Ok(Self {
            previous: Walker::default().value(receiver, 0)?,
        })
    }
    pub(crate) fn collected(&mut self, host: &mut dyn VmHost, values: &[VmValue]) -> Result<()> {
        let next = Walker::default().values(values, 0)?;
        charge(
            host,
            next.pair(next).saturating_add(self.previous.pair(next)),
        )?;
        self.previous.add(next);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{heap::VmHeap, VmRawDecimal};
    #[derive(Default)]
    struct Host(u64);
    impl VmHost for Host {
        fn charge_execution_cost(&mut self, cost: u64) -> Result<()> {
            self.0 = self.0.saturating_add(cost);
            Ok(())
        }
    }
    fn raw(digits: usize) -> VmValue {
        VmValue::RawDecimal(VmRawDecimal::parse(&format!("1{}", "0".repeat(digits - 1))).unwrap())
    }
    #[test]
    fn historical_coefficients_and_identical_cycles_keep_zero_cost() {
        let heap = VmHeap::default();
        let mut host = Host::default();
        comparison(&mut host, &raw(91), &raw(91), false).unwrap();
        let cycle = heap.capture(VmValue::List(vec![])).unwrap();
        let VmValue::Reference(reference) = &cycle else {
            unreachable!()
        };
        reference
            .replace(VmValue::List(vec![cycle.clone(), raw(2000)]))
            .unwrap();
        comparison(&mut host, &cycle, &cycle, true).unwrap();
        assert_eq!(host.0, 0);
    }
    #[test]
    fn ninety_one_digit_boundary_and_large_integer_only_work_keep_legacy_cost() {
        let mut host = Host::default();
        let largest = VmValue::RawDecimal(VmRawDecimal::parse(&"9".repeat(91)).unwrap());
        comparison(&mut host, &largest, &raw(91), false).unwrap();
        let integer = VmValue::Int(BigInt::from(10u8).pow(2000));
        comparison(&mut host, &integer, &integer, false).unwrap();
        normalization(&mut host, &[integer]).unwrap();
        assert_eq!(host.0, 0);
        comparison(&mut host, &raw(92), &largest, false).unwrap();
        assert!(host.0 > 0);
    }

    #[test]
    fn a_deep_first_reference_cannot_hide_a_shallower_wide_value() {
        let heap = VmHeap::default();
        let wide = heap.capture(raw(2000)).unwrap();
        let shallow = heap.capture(VmValue::List(vec![wide])).unwrap();
        let mut deep = shallow.clone();
        for _ in 0..MAX_DEPTH {
            deep = heap.capture(VmValue::List(vec![deep])).unwrap();
        }
        let profile = Walker::default().values(&[deep, shallow], 0).unwrap();
        assert!(profile.work > 0);
    }

    #[test]
    fn shared_graphs_are_memoized_but_pairs_remain_charged() {
        let heap = VmHeap::default();
        let value = heap.capture(raw(2000)).unwrap();
        let mut host = Host::default();
        normalization(&mut host, &[value.clone()]).unwrap();
        let one = host.0;
        host.0 = 0;
        normalization(&mut host, &vec![value.clone(); 16]).unwrap();
        assert_eq!(host.0, one * 256);
        let cycle = heap.capture(VmValue::List(vec![])).unwrap();
        let VmValue::Reference(reference) = &cycle else {
            unreachable!()
        };
        reference
            .replace(VmValue::List(vec![cycle.clone(), value.clone()]))
            .unwrap();
        comparison(&mut host, &cycle, &value, false).unwrap();
    }
}
