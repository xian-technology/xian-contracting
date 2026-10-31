//! Execution-local object identity. Only detached values cross storage and public
//! host boundaries. The heap breaks container cycles when execution ends.
use crate::{VmExecutionError, VmValue};
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::fmt;
use std::rc::Rc;

const MAX_HEAP_BYTES: usize = 128 * 1024 * 1024;
const MAX_HEAP_OBJECTS: usize = 1024 * 1024;
const MAX_VALUE_DEPTH: usize = 128;
const MAX_VALUE_NODES: usize = 1024 * 128;

#[derive(Default)]
struct Usage {
    bytes: usize,
    objects: usize,
}

struct Object {
    value: RefCell<VmValue>,
    bytes: Cell<usize>,
    immutable_depth: usize,
    usage: Rc<RefCell<Usage>>,
}

impl Drop for Object {
    fn drop(&mut self) {
        let mut usage = self.usage.borrow_mut();
        usage.bytes -= self.bytes.get();
        usage.objects -= 1;
    }
}

#[derive(Clone)]
pub struct VmReference(Rc<Object>);

impl PartialEq for VmReference {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

impl fmt::Debug for VmReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<vm object>")
    }
}

impl VmReference {
    pub(crate) fn value(&self) -> VmValue {
        self.0.value.borrow().clone()
    }

    pub(crate) fn replace(&self, value: VmValue) -> Result<(), VmExecutionError> {
        let bytes = shallow_bytes(&value);
        let mut usage = self.0.usage.borrow_mut();
        let total = usage.bytes - self.0.bytes.get() + bytes;
        if total > MAX_HEAP_BYTES {
            return Err(VmExecutionError::new("VM heap byte limit exceeded"));
        }
        usage.bytes = total;
        self.0.bytes.set(bytes);
        drop(usage);
        *self.0.value.borrow_mut() = value;
        Ok(())
    }

    pub(crate) fn id(&self) -> usize {
        Rc::as_ptr(&self.0) as usize
    }
}

#[derive(Default)]
struct HeapStorage {
    containers: RefCell<Vec<VmReference>>,
    usage: Rc<RefCell<Usage>>,
}

impl Drop for HeapStorage {
    fn drop(&mut self) {
        // Every cycle contains a mutable container. Clearing these edges also
        // releases tuples and immutable objects reachable only through cycles.
        for object in self.containers.get_mut().iter() {
            *object.0.value.borrow_mut() = VmValue::None;
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct VmHeap(Rc<HeapStorage>);

impl VmHeap {
    pub(crate) fn capture(&self, value: VmValue) -> Result<VmValue, VmExecutionError> {
        self.capture_at(value, 0)
    }

    fn capture_at(&self, value: VmValue, depth: usize) -> Result<VmValue, VmExecutionError> {
        if depth > MAX_VALUE_DEPTH {
            return Err(VmExecutionError::new("VM value depth limit exceeded"));
        }
        let value = map_children(value, |item| self.capture_at(item, depth + 1))?;
        if matches!(
            value,
            VmValue::Reference(_)
                | VmValue::None
                | VmValue::Bool(_)
                | VmValue::Builtin(_)
                | VmValue::FunctionRef(_)
                | VmValue::TypeMarker(_)
                | VmValue::ContractHandle(_)
                | VmValue::StorageRef(_)
                | VmValue::ForeignStorageRef(_)
                | VmValue::EventRef(_)
        ) {
            return Ok(value);
        }
        let immutable_depth = immutable_depth(&value);
        if immutable_depth > MAX_VALUE_DEPTH {
            return Err(VmExecutionError::new(
                "VM immutable value depth limit exceeded",
            ));
        }
        let bytes = shallow_bytes(&value);
        let mut usage = self.0.usage.borrow_mut();
        if usage.objects >= MAX_HEAP_OBJECTS || usage.bytes + bytes > MAX_HEAP_BYTES {
            return Err(VmExecutionError::new("VM heap allocation limit exceeded"));
        }
        usage.objects += 1;
        usage.bytes += bytes;
        drop(usage);
        let mutable = matches!(
            value,
            VmValue::List(_) | VmValue::Dict(_) | VmValue::Set(_) | VmValue::ByteArray(_)
        );
        let object = VmReference(Rc::new(Object {
            value: RefCell::new(value),
            bytes: Cell::new(bytes),
            immutable_depth,
            usage: self.0.usage.clone(),
        }));
        if mutable {
            self.0.containers.borrow_mut().push(object.clone());
        }
        Ok(VmValue::Reference(object))
    }
}

// Bound recursive Rc destruction even when nested tuples are built one at a
// time. Mutable containers are retained and cleared iteratively by the heap.
fn immutable_depth(value: &VmValue) -> usize {
    match value {
        VmValue::Reference(reference) => reference.0.immutable_depth,
        VmValue::Tuple(items) | VmValue::FrozenSet(items) => {
            1 + items.iter().map(immutable_depth).max().unwrap_or(0)
        }
        VmValue::Exception(exception) => {
            1 + exception
                .args
                .iter()
                .map(immutable_depth)
                .max()
                .unwrap_or(0)
        }
        _ => 0,
    }
}

fn shallow_bytes(value: &VmValue) -> usize {
    let base = std::mem::size_of::<Object>();
    base + match value {
        VmValue::List(v) | VmValue::Tuple(v) | VmValue::Set(v) | VmValue::FrozenSet(v) => {
            v.len() * std::mem::size_of::<VmValue>()
        }
        VmValue::Dict(v) => v.len() * std::mem::size_of::<(VmValue, VmValue)>(),
        VmValue::String(v) => v.len(),
        VmValue::Bytes(v) | VmValue::ByteArray(v) => v.len(),
        VmValue::Int(v) => v.bits().div_ceil(8) as usize,
        _ => 0,
    }
}

fn map_children(
    value: VmValue,
    mut map: impl FnMut(VmValue) -> Result<VmValue, VmExecutionError>,
) -> Result<VmValue, VmExecutionError> {
    Ok(match value {
        VmValue::List(v) => VmValue::List(map_items(v, &mut map)?),
        VmValue::Tuple(v) => VmValue::Tuple(map_items(v, &mut map)?),
        VmValue::Set(v) => VmValue::Set(map_items(v, &mut map)?),
        VmValue::FrozenSet(v) => VmValue::FrozenSet(map_items(v, &mut map)?),
        VmValue::Dict(v) => VmValue::Dict(
            v.into_iter()
                .map(|(k, v)| Ok((map(k)?, map(v)?)))
                .collect::<Result<_, VmExecutionError>>()?,
        ),
        VmValue::Exception(mut exception) => {
            exception.args = exception
                .args
                .into_iter()
                .map(&mut map)
                .collect::<Result<_, _>>()?;
            VmValue::Exception(exception)
        }
        other => other,
    })
}

fn map_items(
    items: Vec<VmValue>,
    map: &mut impl FnMut(VmValue) -> Result<VmValue, VmExecutionError>,
) -> Result<Vec<VmValue>, VmExecutionError> {
    items.into_iter().map(map).collect()
}

impl VmValue {
    /// Resolve one object without copying the objects held in its container.
    pub(crate) fn snapshot(&self) -> Self {
        match self {
            Self::Reference(reference) => reference.value(),
            other => other.clone(),
        }
    }

    pub(crate) fn identical(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Reference(left), Self::Reference(right)) => left == right,
            (Self::None, Self::None) => true,
            (Self::Bool(left), Self::Bool(right)) => left == right,
            (Self::Builtin(left), Self::Builtin(right))
            | (Self::FunctionRef(left), Self::FunctionRef(right))
            | (Self::TypeMarker(left), Self::TypeMarker(right)) => left == right,
            _ => false,
        }
    }

    pub(crate) fn detached(&self) -> Result<Self, VmExecutionError> {
        detach(self, &mut HashSet::new(), 0, &mut 0)
    }
}

fn detach(
    value: &VmValue,
    path: &mut HashSet<usize>,
    depth: usize,
    nodes: &mut usize,
) -> Result<VmValue, VmExecutionError> {
    *nodes += 1;
    if depth > MAX_VALUE_DEPTH || *nodes > MAX_VALUE_NODES {
        return Err(VmExecutionError::new("VM value traversal limit exceeded"));
    }
    let id = match value {
        VmValue::Reference(reference) => Some(reference.id()),
        _ => None,
    };
    if let Some(id) = id {
        if !path.insert(id) {
            return Err(VmExecutionError::new(
                "cyclic value cannot cross a VM boundary",
            ));
        }
    }
    let result = map_children(value.snapshot(), |item| {
        detach(&item, path, depth + 1, nodes)
    });
    if let Some(id) = id {
        path.remove(&id);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_distinguishes_equal_objects_and_preserves_singletons() {
        let heap = VmHeap::default();
        let a = heap.capture(VmValue::List(vec![])).unwrap();
        let b = heap.capture(VmValue::List(vec![])).unwrap();
        assert!(a.identical(&a.clone()));
        assert!(!a.identical(&b));
        assert!(!a.identical(&VmValue::None));
        assert!(VmValue::None.identical(&VmValue::None));
        assert!(VmValue::Bool(true).identical(&VmValue::Bool(true)));
        assert!(!VmValue::Bool(true).identical(&VmValue::Bool(false)));
        assert!(VmValue::Builtin("str".into()).identical(&VmValue::Builtin("str".into())));
        assert!(!VmValue::Builtin("str".into()).identical(&VmValue::Builtin("int".into())));
    }

    #[test]
    fn execution_end_releases_cycles_through_immutable_containers() {
        let heap = VmHeap::default();
        let VmValue::Reference(list) = heap.capture(VmValue::List(vec![])).unwrap() else {
            panic!()
        };
        let tuple = heap
            .capture(VmValue::Tuple(vec![VmValue::Reference(list.clone())]))
            .unwrap();
        list.replace(VmValue::List(vec![tuple])).unwrap();
        let weak = Rc::downgrade(&list.0);
        drop(list);
        assert!(weak.upgrade().is_some());
        drop(heap);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn quota_failure_preserves_original_object_and_accounting() {
        let heap = VmHeap::default();
        let VmValue::Reference(list) = heap.capture(VmValue::List(vec![])).unwrap() else {
            panic!()
        };
        heap.0.usage.borrow_mut().bytes = MAX_HEAP_BYTES;
        assert!(list.replace(VmValue::List(vec![VmValue::None])).is_err());
        assert_eq!(list.value(), VmValue::List(vec![]));
        assert_eq!(heap.0.usage.borrow().bytes, MAX_HEAP_BYTES);
        assert!(heap.capture(VmValue::String("too much".into())).is_err());
        heap.0.usage.borrow_mut().bytes = list.0.bytes.get();
    }

    #[test]
    fn exceptions_detach_nested_arguments() {
        let heap = VmHeap::default();
        let exception = VmValue::Exception(crate::VmException {
            name: "Exception".into(),
            args: vec![VmValue::List(vec![VmValue::Bool(true)])],
        });
        let captured = heap.capture(exception.clone()).unwrap();
        assert_eq!(captured.detached().unwrap(), exception);
    }
}
