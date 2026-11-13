//! Execution-local, consumable iterators. Callback evaluation belongs to the VM;
//! cursors never borrow a call frame or expose host pointers to contracts.
use crate::heap::VmHeap;
use crate::{VmExecutionError, VmValue};
use num_bigint::BigInt;
use num_traits::{Signed, Zero};

type Result<T> = std::result::Result<T, VmExecutionError>;
pub(crate) type Callback<'a> = dyn FnMut(VmValue, Vec<VmValue>) -> Result<VmValue> + 'a;
const MAX_ITEMS: usize = 128 * 1024;

#[derive(Clone, Debug, PartialEq)]
pub struct VmRange {
    pub(crate) start: BigInt,
    pub(crate) stop: BigInt,
    pub(crate) step: BigInt,
}

impl VmRange {
    pub(crate) fn allocation_bytes(&self) -> usize {
        ((self.start.bits() + self.stop.bits() + self.step.bits()).div_ceil(8)) as usize
    }

    pub(crate) fn sliced(
        &self,
        lower: Option<BigInt>,
        upper: Option<BigInt>,
        step: Option<BigInt>,
    ) -> Result<Self> {
        let (start, stop, step) = slice_indices(&self.len(), lower, upper, step)?;
        Ok(Self {
            start: &self.start + start * &self.step,
            stop: &self.start + stop * &self.step,
            step: step * &self.step,
        })
    }

    pub(crate) fn equivalent(&self, other: &Self) -> bool {
        let length = self.len();
        length == other.len()
            && (length.is_zero()
                || (self.start == other.start
                    && (length == BigInt::from(1) || self.step == other.step)))
    }

    pub(crate) fn len(&self) -> BigInt {
        let distance = if self.step.is_positive() {
            &self.stop - &self.start
        } else {
            &self.start - &self.stop
        };
        if distance <= BigInt::zero() {
            return BigInt::zero();
        }
        (distance - 1) / self.step.abs() + 1
    }

    pub(crate) fn get(&self, index: &BigInt) -> Option<VmValue> {
        let length = self.len();
        let index = if index.is_negative() {
            index + &length
        } else {
            index.clone()
        };
        if index.is_negative() || index >= length {
            return None;
        }
        Some(VmValue::Int(&self.start + index * &self.step))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ViewMode {
    Keys,
    Values,
    Items,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VmDictView {
    pub(crate) source: VmValue,
    pub(crate) mode: ViewMode,
}

impl VmDictView {
    pub(crate) fn len(&self) -> usize {
        match &self.source {
            VmValue::Reference(reference) => reference.with_value(|value| match value {
                VmValue::Dict(entries) => entries.len(),
                _ => 0,
            }),
            VmValue::Dict(entries) => entries.len(),
            _ => 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct VmIterator {
    kind: Kind,
    exhausted: bool,
    running: bool,
    execution_stack: crate::execution_stack::ExecutionStack,
}

impl VmIterator {
    pub(crate) fn visit_children(
        &self,
        visit: &mut impl FnMut(&VmValue) -> Result<()>,
    ) -> Result<()> {
        match &self.kind {
            Kind::View { view, .. } => visit(&view.source),
            Kind::Sequence { source, .. } => visit(source),
            Kind::Map { function, inputs } => {
                visit(function)?;
                inputs.iter().try_for_each(visit)
            }
            Kind::Filter { function, input } => {
                visit(function)?;
                visit(input)
            }
            Kind::Zip { inputs, .. } => inputs.iter().try_for_each(visit),
            Kind::Range { .. } => Ok(()),
        }
    }

    pub(crate) fn matches_public_class(&self, name: &str) -> bool {
        match &self.kind {
            Kind::Map { .. } => name == "map",
            Kind::Filter { .. } => name == "filter",
            Kind::Zip { .. } => name == "zip",
            Kind::Sequence {
                source,
                reverse: true,
                ..
            } if name == "reversed" => {
                // list.__reversed__ returns its own iterator class. Generic
                // reversed(str/tuple/bytes/bytearray) instances use reversed.
                match source {
                    VmValue::Reference(reference) => {
                        reference.with_value(|value| !matches!(value, VmValue::List(_)))
                    }
                    value => !matches!(value, VmValue::List(_)),
                }
            }
            _ => false,
        }
    }

    pub(crate) fn allocation_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + match &self.kind {
                Kind::Map { inputs, .. } | Kind::Zip { inputs, .. } => {
                    inputs.len() * std::mem::size_of::<VmValue>()
                }
                Kind::Range { range, index } => {
                    range.allocation_bytes() + index.bits().div_ceil(8) as usize
                }
                _ => 0,
            }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Kind {
    View {
        view: VmDictView,
        index: usize,
        size: usize,
        remaining: usize,
        reverse: bool,
    },
    Sequence {
        source: VmValue,
        index: usize,
        reverse: bool,
        expected_size: Option<usize>,
    },
    Range {
        range: VmRange,
        index: BigInt,
    },
    Map {
        function: VmValue,
        inputs: Vec<VmValue>,
    },
    Filter {
        function: VmValue,
        input: VmValue,
    },
    Zip {
        inputs: Vec<VmValue>,
        strict: bool,
    },
}

fn store(kind: Kind, heap: &VmHeap) -> Result<VmValue> {
    heap.capture(VmValue::Iterator(Box::new(VmIterator {
        kind,
        exhausted: false,
        running: false,
        execution_stack: heap.execution_stack(),
    })))
}

pub(crate) fn iter(source: &VmValue, heap: &VmHeap) -> Result<VmValue> {
    let value = source.snapshot();
    match value {
        VmValue::Iterator(_) => Ok(source.clone()),
        VmValue::MappingProxy(mapping) => iter(&mapping, heap),
        VmValue::View(view) => dictionary_cursor(*view, false, heap),
        VmValue::Range(range) => store(
            Kind::Range {
                range,
                index: BigInt::zero(),
            },
            heap,
        ),
        _ => sequence(source, false, heap),
    }
}

pub(crate) fn sequence(source: &VmValue, reverse: bool, heap: &VmHeap) -> Result<VmValue> {
    let value = source.snapshot();
    match &value {
        VmValue::MappingProxy(mapping) => return sequence(mapping, reverse, heap),
        VmValue::View(view) => return dictionary_cursor(*view.clone(), reverse, heap),
        VmValue::Dict(_) => {
            return dictionary_cursor(
                VmDictView {
                    source: source.clone(),
                    mode: ViewMode::Keys,
                },
                reverse,
                heap,
            )
        }
        VmValue::Range(range) if reverse => {
            let length = range.len();
            return store(
                Kind::Range {
                    range: VmRange {
                        start: &range.start + (&length - 1) * &range.step,
                        stop: &range.start - &range.step,
                        step: -&range.step,
                    },
                    index: BigInt::zero(),
                },
                heap,
            );
        }
        _ => {}
    }
    let (source, length, expected_size) = sequence_shape(source, &value, reverse, heap)?;
    store(
        Kind::Sequence {
            source,
            index: if reverse { length } else { 0 },
            reverse,
            expected_size,
        },
        heap,
    )
}

fn dictionary_cursor(mut view: VmDictView, reverse: bool, heap: &VmHeap) -> Result<VmValue> {
    view.source = heap.capture(view.source)?;
    let VmValue::Reference(reference) = &view.source else {
        unreachable!()
    };
    let size = view.len();
    let index = if reverse {
        reference.dictionary_slots(|slots| slots.end)
    } else {
        0
    };
    store(
        Kind::View {
            view,
            index,
            size,
            remaining: size,
            reverse,
        },
        heap,
    )
}

fn sequence_shape(
    source: &VmValue,
    value: &VmValue,
    reverse: bool,
    heap: &VmHeap,
) -> Result<(VmValue, usize, Option<usize>)> {
    Ok(match value {
        VmValue::List(v) | VmValue::Tuple(v) => (source.clone(), v.len(), None),
        VmValue::DecimalTuple(v) => (heap.capture(VmValue::Tuple(v.as_values()))?, 3, None),
        VmValue::Bytes(v) | VmValue::ByteArray(v) => (source.clone(), v.len(), None),
        VmValue::Dict(v) => (source.clone(), v.len(), Some(v.len())),
        VmValue::Set(v) | VmValue::BuiltinSet(v) | VmValue::FrozenSet(v) if !reverse => {
            (source.clone(), v.len(), Some(v.len()))
        }
        VmValue::String(v) => {
            let chars = v
                .chars()
                .map(|ch| VmValue::String(ch.to_string()))
                .collect::<Vec<_>>();
            let length = chars.len();
            (heap.capture(VmValue::Tuple(chars))?, length, None)
        }
        _ => {
            return Err(VmExecutionError::new(format!(
                "{} is not iterable",
                value.type_name()
            )))
        }
    })
}

pub(crate) fn lazy(
    name: &str,
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
    heap: &VmHeap,
) -> Result<VmValue> {
    validate_lazy_arguments(name, args.len(), kwargs)?;
    match name {
        "map" => store(
            Kind::Map {
                function: args[0].clone(),
                inputs: inputs(&args[1..], heap)?,
            },
            heap,
        ),
        "filter" => store(
            Kind::Filter {
                function: args[0].clone(),
                input: iter(&args[1], heap)?,
            },
            heap,
        ),
        "zip" => store(
            Kind::Zip {
                inputs: inputs(args, heap)?,
                strict: zip_strict(kwargs),
            },
            heap,
        ),
        "reversed" => sequence(&args[0], true, heap),
        _ => Err(VmExecutionError::new(format!(
            "invalid arguments to {name}()"
        ))),
    }
}

fn zip_strict(kwargs: &[(String, VmValue)]) -> bool {
    kwargs.first().is_some_and(|(_, value)| value.truthy())
}

fn validate_lazy_arguments(name: &str, count: usize, kwargs: &[(String, VmValue)]) -> Result<()> {
    let valid = if name == "zip" {
        valid_zip_keywords(kwargs)
    } else {
        let allowed = match name {
            "map" => 2..=usize::MAX,
            "filter" => 2..=2,
            "reversed" => 1..=1,
            _ => 1..=0,
        };
        allowed.contains(&count) && kwargs.is_empty()
    };
    if valid {
        return Ok(());
    }
    Err(VmExecutionError::new(format!(
        "invalid arguments to {name}()"
    )))
}

fn valid_zip_keywords(kwargs: &[(String, VmValue)]) -> bool {
    kwargs.len() <= 1 && kwargs.iter().all(|(key, _)| key == "strict")
}

fn inputs(args: &[VmValue], heap: &VmHeap) -> Result<Vec<VmValue>> {
    args.iter().map(|value| iter(value, heap)).collect()
}

pub(crate) fn next(iterator: &VmValue, callback: &mut Callback<'_>) -> Result<Option<VmValue>> {
    next_at(iterator, callback, 0)
}

fn next_at(
    iterator: &VmValue,
    callback: &mut Callback<'_>,
    depth: usize,
) -> Result<Option<VmValue>> {
    if depth > 128 {
        return Err(VmExecutionError::new("VM iterator nesting limit exceeded"));
    }
    let VmValue::Reference(reference) = iterator else {
        return Err(VmExecutionError::new("invalid iterator"));
    };
    let VmValue::Iterator(mut state) = reference.value() else {
        return Err(VmExecutionError::new("invalid iterator"));
    };
    let _frame = state.execution_stack.enter()?;
    if state.running {
        return Err(VmExecutionError::new("iterator is already executing"));
    }
    if state.exhausted {
        return Ok(None);
    }
    state.running = true;
    reference.replace(VmValue::Iterator(state.clone()))?;
    let result = advance(&mut state.kind, callback, depth + 1)?;
    state.running = false;
    state.exhausted = result.is_none();
    reference.replace(VmValue::Iterator(state))?;
    Ok(result)
}

fn advance(kind: &mut Kind, callback: &mut Callback<'_>, depth: usize) -> Result<Option<VmValue>> {
    match kind {
        Kind::View {
            view,
            index,
            size,
            remaining,
            reverse,
        } => view_item(view, index, *size, remaining, *reverse),
        Kind::Sequence {
            source,
            index,
            reverse,
            expected_size,
        } => next_index(index, *reverse)
            .map(|index| sequence_item(source, index, *expected_size))
            .transpose()
            .map(Option::flatten),
        Kind::Range { range, index } => {
            let result = range.get(index);
            *index += 1;
            Ok(result)
        }
        Kind::Map { function, inputs } => next_row(inputs, false, callback, depth)?
            .map(|row| callback(function.clone(), row))
            .transpose(),
        Kind::Zip { inputs, strict } => {
            Ok(next_row(inputs, *strict, callback, depth)?.map(VmValue::Tuple))
        }
        Kind::Filter { function, input } => next_filtered(function, input, callback, depth),
    }
}

fn next_index(index: &mut usize, reverse: bool) -> Option<usize> {
    if reverse {
        *index = index.checked_sub(1)?;
        return Some(*index);
    }
    let current = *index;
    *index += 1;
    Some(current)
}

fn next_filtered(
    function: &VmValue,
    input: &VmValue,
    callback: &mut Callback<'_>,
    depth: usize,
) -> Result<Option<VmValue>> {
    while let Some(value) = next_at(input, callback, depth)? {
        let keep = if matches!(function, VmValue::None) {
            value.truthy()
        } else {
            callback(function.clone(), vec![value.clone()])?.truthy()
        };
        if keep {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

fn next_row(
    inputs: &[VmValue],
    strict: bool,
    callback: &mut Callback<'_>,
    depth: usize,
) -> Result<Option<Vec<VmValue>>> {
    if inputs.is_empty() {
        return Ok(None);
    }
    let mut row = Vec::with_capacity(inputs.len());
    for (index, input) in inputs.iter().enumerate() {
        match next_at(input, callback, depth)? {
            Some(value) => row.push(value),
            None => {
                if strict {
                    check_zip_end(inputs, index, callback, depth)?;
                }
                return Ok(None);
            }
        }
    }
    Ok(Some(row))
}

fn check_zip_end(
    inputs: &[VmValue],
    index: usize,
    callback: &mut Callback<'_>,
    depth: usize,
) -> Result<()> {
    let mismatch = || VmExecutionError::new("zip() arguments have different lengths");
    if index != 0 {
        return Err(mismatch());
    }
    for remainder in &inputs[1..] {
        if next_at(remainder, callback, depth)?.is_some() {
            return Err(mismatch());
        }
    }
    Ok(())
}

fn sequence_item(
    source: &VmValue,
    index: usize,
    expected_size: Option<usize>,
) -> Result<Option<VmValue>> {
    match source {
        VmValue::Reference(reference) => {
            reference.with_value(|value| item(value, index, expected_size))
        }
        value => item(value, index, expected_size),
    }
}

fn item(value: &VmValue, index: usize, expected_size: Option<usize>) -> Result<Option<VmValue>> {
    let (length, result) = match value {
        VmValue::List(v)
        | VmValue::Tuple(v)
        | VmValue::Set(v)
        | VmValue::BuiltinSet(v)
        | VmValue::FrozenSet(v) => (v.len(), v.get(index).cloned()),
        VmValue::Dict(v) => (v.len(), v.get(index).map(|(key, _)| key.clone())),
        VmValue::Bytes(v) | VmValue::ByteArray(v) => (
            v.len(),
            v.get(index).map(|byte| VmValue::Int((*byte).into())),
        ),
        _ => return Err(VmExecutionError::new("invalid iterable source")),
    };
    if expected_size.is_some_and(|expected| expected != length) {
        return Err(VmExecutionError::new(
            "collection changed size during iteration",
        ));
    }
    Ok(result)
}

pub(crate) fn collect(
    source: &VmValue,
    heap: &VmHeap,
    callback: &mut Callback<'_>,
) -> Result<Vec<VmValue>> {
    let iterator = iter(source, heap)?;
    // A range is created in constant time at any length: refuse one that
    // cannot fit before producing (unmetered) the items that would.
    if range_items_left(&iterator).is_some_and(|left| left > BigInt::from(MAX_ITEMS)) {
        return Err(VmExecutionError::new("iterable exceeds allocation limit"));
    }
    let mut result = Vec::new();
    while let Some(value) = next(&iterator, callback)? {
        if result.len() >= MAX_ITEMS {
            return Err(VmExecutionError::new("iterable exceeds allocation limit"));
        }
        result.push(heap.capture(value)?);
    }
    Ok(result)
}

/// The items a range iterator still yields; `None` for other iterators,
/// whose sources were allocated (and charged) item by item.
fn range_items_left(iterator: &VmValue) -> Option<BigInt> {
    let left = |value: &VmValue| match value {
        VmValue::Iterator(iterator) if !iterator.exhausted => match &iterator.kind {
            Kind::Range { range, index } => Some((range.len() - index).max(BigInt::zero())),
            _ => None,
        },
        _ => None,
    };
    match iterator {
        VmValue::Reference(reference) => reference.with_value(left),
        other => left(other),
    }
}

fn view_item(
    view: &VmDictView,
    index: &mut usize,
    size: usize,
    remaining: &mut usize,
    reverse: bool,
) -> Result<Option<VmValue>> {
    let VmValue::Reference(reference) = &view.source else {
        unreachable!()
    };
    reference.with_value(|value| {
        let VmValue::Dict(entries) = value else {
            unreachable!()
        };
        if entries.len() != size {
            return Err(VmExecutionError::new(
                "dictionary changed size during iteration",
            ));
        }
        let selected = reference.dictionary_slots(|slots| {
            if reverse {
                slots
                    .positions
                    .partition_point(|slot| *slot < *index)
                    .checked_sub(1)
            } else {
                let position = slots.positions.partition_point(|slot| *slot < *index);
                (position < slots.positions.len()).then_some(position)
            }
            .map(|position| (position, slots.positions[position]))
        });
        let Some((position, slot)) = selected else {
            return Ok(None);
        };
        if !reverse && *remaining == 0 {
            return Err(VmExecutionError::new(
                "dictionary keys changed during iteration",
            ));
        }
        *remaining = remaining.saturating_sub(1);
        *index = if reverse { slot } else { slot + 1 };
        let (key, value) = &entries[position];
        Ok(Some(match view.mode {
            ViewMode::Keys => key.clone(),
            ViewMode::Values => value.clone(),
            ViewMode::Items => VmValue::Tuple(vec![key.clone(), value.clone()]),
        }))
    })
}

pub(crate) fn slice_indices(
    length: &BigInt,
    lower: Option<BigInt>,
    upper: Option<BigInt>,
    step: Option<BigInt>,
) -> Result<(BigInt, BigInt, BigInt)> {
    let step = step.unwrap_or_else(|| BigInt::from(1));
    if step.is_zero() {
        return Err(VmExecutionError::new("slice step cannot be zero"));
    }
    let negative = step.is_negative();
    let minimum = BigInt::from(if negative { -1 } else { 0 });
    let maximum = if negative { length - 1 } else { length.clone() };
    let start = normalize_slice_bound(
        lower,
        length,
        &minimum,
        &maximum,
        if negative { &maximum } else { &minimum },
    );
    let stop = normalize_slice_bound(
        upper,
        length,
        &minimum,
        &maximum,
        if negative { &minimum } else { &maximum },
    );
    Ok((start, stop, step))
}

fn normalize_slice_bound(
    value: Option<BigInt>,
    length: &BigInt,
    minimum: &BigInt,
    maximum: &BigInt,
    default: &BigInt,
) -> BigInt {
    let Some(mut value) = value else {
        return default.clone();
    };
    if value.is_negative() {
        value += length;
    }
    value.max(minimum.clone()).min(maximum.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_callback(_: VmValue, _: Vec<VmValue>) -> Result<VmValue> {
        panic!("unexpected callback")
    }

    fn range(start: i64, stop: i64, step: i64) -> VmValue {
        VmValue::Range(VmRange {
            start: start.into(),
            stop: stop.into(),
            step: step.into(),
        })
    }

    #[test]
    fn a_range_collects_up_to_the_item_limit_and_is_refused_beyond_it() {
        let heap = VmHeap::default();
        let limit = MAX_ITEMS as i64;
        let collected = |source: &VmValue| collect(source, &heap, &mut no_callback);
        assert_eq!(collected(&range(0, limit, 1)).unwrap().len(), MAX_ITEMS);
        assert_eq!(collected(&range(limit, 0, -1)).unwrap().len(), MAX_ITEMS);
        for source in [
            range(0, limit + 1, 1),
            range(0, i64::MAX, 1),
            range(i64::MAX, 0, -2),
        ] {
            let error = collected(&source).unwrap_err();
            assert_eq!(error.to_string(), "iterable exceeds allocation limit");
        }
        // A started range iterator counts what it still yields.
        let cursor = iter(&range(0, limit + 1, 1), &heap).unwrap();
        next(&cursor, &mut no_callback).unwrap();
        assert_eq!(collected(&cursor).unwrap().len(), MAX_ITEMS);
        assert_eq!(collected(&cursor).unwrap().len(), 0);
    }

    #[test]
    fn list_cursor_observes_appends_and_stays_exhausted() {
        let heap = VmHeap::default();
        let list = heap
            .capture(VmValue::List(vec![VmValue::Bool(false)]))
            .unwrap();
        let cursor = iter(&list, &heap).unwrap();
        assert_eq!(
            next(&cursor, &mut no_callback).unwrap(),
            Some(VmValue::Bool(false))
        );
        let VmValue::Reference(reference) = &list else {
            panic!()
        };
        reference.append_sequence(VmValue::Bool(true)).unwrap();
        assert_eq!(
            next(&cursor, &mut no_callback).unwrap(),
            Some(VmValue::Bool(true))
        );
        assert_eq!(next(&cursor, &mut no_callback).unwrap(), None);
        reference.append_sequence(VmValue::None).unwrap();
        assert_eq!(next(&cursor, &mut no_callback).unwrap(), None);
    }

    #[test]
    fn strict_zip_fails_on_either_shorter_input() {
        for lengths in [(1, 2), (2, 1)] {
            let heap = VmHeap::default();
            let args = [lengths.0, lengths.1].map(|length| {
                heap.capture(VmValue::List(vec![VmValue::Bool(true); length]))
                    .unwrap()
            });
            let cursor = lazy(
                "zip",
                &args,
                &[("strict".into(), VmValue::Bool(true))],
                &heap,
            )
            .unwrap();
            assert!(next(&cursor, &mut no_callback).unwrap().is_some());
            assert!(next(&cursor, &mut no_callback)
                .unwrap_err()
                .to_string()
                .contains("different lengths"));
        }
    }

    #[test]
    fn map_defers_calls_and_consumes_once() {
        let heap = VmHeap::default();
        let source = heap
            .capture(VmValue::List(vec![VmValue::Bool(true)]))
            .unwrap();
        let cursor = lazy(
            "map",
            &[VmValue::Builtin("bool".into()), source],
            &[],
            &heap,
        )
        .unwrap();
        let mut calls = 0;
        let mut callback = |_, args: Vec<VmValue>| {
            calls += 1;
            Ok(args[0].clone())
        };
        assert_eq!(
            next(&cursor, &mut callback).unwrap(),
            Some(VmValue::Bool(true))
        );
        assert_eq!(next(&cursor, &mut callback).unwrap(), None);
        assert_eq!(next(&cursor, &mut callback).unwrap(), None);
        assert_eq!(calls, 1);
    }
}
