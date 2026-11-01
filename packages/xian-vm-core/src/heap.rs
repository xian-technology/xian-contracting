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
    dict_slots: RefCell<Option<crate::dict_slots::DictSlots>>,
    bytes: Cell<usize>,
    immutable_depth: usize,
    version: Cell<u64>,
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
    pub(crate) fn with_value<T>(&self, read: impl FnOnce(&VmValue) -> T) -> T {
        read(&self.0.value.borrow())
    }

    pub(crate) fn value(&self) -> VmValue {
        self.0.value.borrow().clone()
    }

    pub(crate) fn replace(&self, value: VmValue) -> Result<(), VmExecutionError> {
        let slots = self.0.dict_slots.borrow().as_ref().map(|slots| {
            self.with_value(|old| match (old, &value) {
                (VmValue::Dict(old), VmValue::Dict(new)) => slots.updated(old, new),
                _ => unreachable!("dictionary reference changed type"),
            })
        });
        let bytes = shallow_bytes(&value);
        let mut usage = self.0.usage.borrow_mut();
        let total = usage.bytes - self.0.bytes.get() + bytes;
        if total > MAX_HEAP_BYTES {
            return Err(VmExecutionError::new("VM heap byte limit exceeded"));
        }
        usage.bytes = total;
        self.0.bytes.set(bytes);
        drop(usage);
        *self.0.dict_slots.borrow_mut() = slots;
        *self.0.value.borrow_mut() = value;
        self.0.version.set(self.0.version.get().saturating_add(1));
        Ok(())
    }

    pub(crate) fn append_sequence(&self, item: VmValue) -> Result<(), VmExecutionError> {
        let mut value = self.0.value.borrow_mut();
        let (length, growth) = match &*value {
            VmValue::List(items) => (items.len(), std::mem::size_of::<VmValue>()),
            VmValue::ByteArray(bytes) => (bytes.len(), 1),
            _ => return Err(VmExecutionError::new("expected a mutable sequence")),
        };
        let mut usage = self.0.usage.borrow_mut();
        if length >= crate::interpreter::MAX_SEQUENCE_LENGTH
            || usage.bytes + growth > MAX_HEAP_BYTES
        {
            return Err(VmExecutionError::new("sequence allocation limit exceeded"));
        }
        match &mut *value {
            VmValue::List(items) => items.push(item),
            VmValue::ByteArray(bytes) => {
                if !matches!(item.snapshot(), VmValue::Int(_) | VmValue::Bool(_)) {
                    return Err(VmExecutionError::new("byte requires an integer"));
                }
                let byte = u8::try_from(item.as_i64()?)
                    .map_err(|_| VmExecutionError::new("byte must be in range(0, 256)"))?;
                bytes.push(byte);
            }
            _ => unreachable!(),
        }
        self.0.version.set(self.0.version.get().saturating_add(1));
        usage.bytes += growth;
        self.0.bytes.set(self.0.bytes.get() + growth);
        Ok(())
    }

    pub(crate) fn dictionary_slots<T>(
        &self,
        read: impl FnOnce(&crate::dict_slots::DictSlots) -> T,
    ) -> T {
        read(
            self.0
                .dict_slots
                .borrow()
                .as_ref()
                .expect("dictionary slots"),
        )
    }

    pub(crate) fn clear_dictionary_slots(&self) {
        if self.0.dict_slots.borrow().is_some() {
            *self.0.dict_slots.borrow_mut() = Some(crate::dict_slots::DictSlots::new(&[]));
        }
    }

    pub(crate) fn version(&self) -> u64 {
        self.0.version.get()
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
                | VmValue::HostCallable(_)
                | VmValue::Builtin(_)
                | VmValue::FunctionRef(_)
                | VmValue::TypeMarker(_)
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
            VmValue::List(_)
                | VmValue::Dict(_)
                | VmValue::Set(_)
                | VmValue::BuiltinSet(_)
                | VmValue::ByteArray(_)
                | VmValue::Iterator(_)
                | VmValue::InterfaceDescriptor(_)
        );
        let dict_slots = match &value {
            VmValue::Dict(entries) => Some(crate::dict_slots::DictSlots::new(entries)),
            _ => None,
        };
        let object = VmReference(Rc::new(Object {
            dict_slots: RefCell::new(dict_slots),
            value: RefCell::new(value),
            bytes: Cell::new(bytes),
            immutable_depth,
            version: Cell::new(0),
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
        VmValue::DecimalTuple(tuple) => {
            1 + tuple
                .fields()
                .iter()
                .map(immutable_depth)
                .max()
                .unwrap_or(0)
        }
        VmValue::BoundMethod(bound) => 1 + immutable_depth(&bound.receiver),
        VmValue::MappingProxy(value) => 1 + immutable_depth(value),
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
        VmValue::List(v)
        | VmValue::Tuple(v)
        | VmValue::Set(v)
        | VmValue::BuiltinSet(v)
        | VmValue::FrozenSet(v) => v.len() * std::mem::size_of::<VmValue>(),
        VmValue::Dict(v) => {
            v.len() * (std::mem::size_of::<(VmValue, VmValue)>() + std::mem::size_of::<usize>())
        }
        VmValue::DecimalTuple(v) => v.allocation_bytes(),
        VmValue::ContractHandle(v) => v.module.len() + v.origin.len(),
        VmValue::String(v) => v.len(),
        VmValue::Bytes(v) | VmValue::ByteArray(v) => v.len(),
        VmValue::Int(v) => v.bits().div_ceil(8) as usize,
        VmValue::Decimal(v) => v.scaled.bits().div_ceil(8) as usize,
        VmValue::RawDecimal(v) => v.coefficient.bits().div_ceil(8) as usize,
        VmValue::Iterator(v) => v.allocation_bytes(),
        VmValue::Range(v) => v.allocation_bytes(),
        VmValue::View(_) => std::mem::size_of::<crate::VmDictView>(),
        VmValue::BoundMethod(bound) => {
            std::mem::size_of::<crate::VmBoundMethod>() + bound.method.len()
        }
        VmValue::MappingProxy(_) => std::mem::size_of::<VmValue>(),
        VmValue::InterfaceDescriptor(descriptor) => descriptor.allocation_bytes(),
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
        VmValue::DecimalTuple(v) => VmValue::DecimalTuple(v.map_fields(map)?),
        VmValue::Set(v) => VmValue::Set(map_items(v, &mut map)?),
        VmValue::BuiltinSet(v) => VmValue::BuiltinSet(map_items(v, &mut map)?),
        VmValue::FrozenSet(v) => VmValue::FrozenSet(map_items(v, &mut map)?),
        VmValue::Dict(v) => VmValue::Dict(
            v.into_iter()
                .map(|(k, v)| Ok((map(k)?, map(v)?)))
                .collect::<Result<_, VmExecutionError>>()?,
        ),
        VmValue::InterfaceDescriptor(mut descriptor) => {
            descriptor.attributes = descriptor
                .attributes
                .into_iter()
                .map(|(name, value)| Ok((name, map(value)?)))
                .collect::<Result<_, VmExecutionError>>()?;
            VmValue::InterfaceDescriptor(descriptor)
        }
        VmValue::BoundMethod(mut bound) => {
            bound.receiver = map(bound.receiver)?;
            VmValue::BoundMethod(bound)
        }
        VmValue::MappingProxy(value) => VmValue::MappingProxy(Box::new(map(*value)?)),
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
    pub(crate) fn is_mutable_sequence(&self) -> bool {
        match self {
            Self::Reference(reference) => reference.with_value(VmValue::is_mutable_sequence),
            Self::List(_) | Self::ByteArray(_) => true,
            _ => false,
        }
    }

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
            (Self::HostCallable(left), Self::HostCallable(right)) => left == right,
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
    if matches!(value.snapshot(), VmValue::BuiltinSet(_)) {
        return Err(VmExecutionError::new(
            "builtin sets cannot cross the VM boundary; convert with set() first",
        ));
    }
    if matches!(value.snapshot(), VmValue::InterfaceDescriptor(_)) {
        return Err(VmExecutionError::new(
            "interface descriptors cannot cross the VM boundary",
        ));
    }
    if matches!(value.snapshot(), VmValue::BoundMethod(_)) {
        return Err(VmExecutionError::new(
            "bound methods cannot cross the VM boundary",
        ));
    }
    if matches!(value.snapshot(), VmValue::MappingProxy(_)) {
        return Err(VmExecutionError::new(
            "mapping proxies cannot cross the VM boundary; copy them first",
        ));
    }
    if let Some(kind) =
        execution_local_capability(&value.snapshot()).filter(|kind| *kind != "callables")
    {
        return Err(VmExecutionError::new(format!(
            "{kind} cannot cross the VM boundary"
        )));
    }
    if matches!(
        value.snapshot(),
        VmValue::Iterator(_) | VmValue::Range(_) | VmValue::View(_)
    ) {
        return Err(VmExecutionError::new(
            "iterators and ranges cannot cross the VM boundary; materialize them first",
        ));
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
    fn descriptor_heap_budget_covers_entry_payload_and_tree_links() {
        let heap = VmHeap::default();
        // A stored field necessarily owns its key, value slot and tree link.
        // Reserve one byte less than that independent minimum; the descriptor
        // must fail before capture even if its values allocate no child objects.
        let minimum = std::mem::size_of::<Object>()
            + 5
            + std::mem::size_of::<(String, VmValue)>()
            + std::mem::size_of::<usize>();
        heap.0.usage.borrow_mut().bytes = MAX_HEAP_BYTES - minimum + 1;
        let value = VmValue::InterfaceDescriptor(Box::new(crate::VmInterfaceDescriptor {
            kind: crate::VmInterfaceKind::Func,
            attributes: std::collections::BTreeMap::from([("field".into(), VmValue::None)]),
        }));
        assert!(heap
            .capture(value)
            .unwrap_err()
            .to_string()
            .contains("heap allocation"));
    }

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

    #[test]
    fn bound_receiver_cycles_are_broken_and_methods_count_toward_heap_limits() {
        let heap = VmHeap::default();
        let VmValue::Reference(items) = heap.capture(VmValue::List(vec![])).unwrap() else {
            panic!()
        };
        let weak = Rc::downgrade(&items.0);
        let method = heap
            .capture(VmValue::BoundMethod(Box::new(crate::VmBoundMethod {
                receiver: VmValue::Reference(items.clone()),
                method: "append".into(),
            })))
            .unwrap();
        assert_eq!(
            method.try_python_repr().unwrap(),
            "<bound method list.append>"
        );
        items.append_sequence(method.clone()).unwrap();
        assert!(method.detached().is_err());
        drop(method);
        drop(items);
        drop(heap);
        assert!(weak.upgrade().is_none());

        let heap = VmHeap::default();
        heap.0.usage.borrow_mut().bytes = MAX_HEAP_BYTES - 1;
        assert!(heap
            .capture(VmValue::BoundMethod(Box::new(crate::VmBoundMethod {
                receiver: VmValue::Builtin("str".into()),
                method: "maketrans".into(),
            })))
            .is_err());
    }
}

fn execution_local_capability(value: &VmValue) -> Option<&'static str> {
    match value {
        VmValue::HostCallable(_) => Some("host callables"),
        VmValue::Builtin(_) | VmValue::TypeMarker(_) => Some("callables"),
        VmValue::BoundMethod(_) => Some("bound methods"),
        VmValue::MappingProxy(_) => Some("mapping proxies"),
        VmValue::StorageRef(_) => Some("global storage references"),
        VmValue::FunctionRef(_) => Some("local functions"),
        VmValue::EventRef(_) => Some("event definitions"),
        _ => None,
    }
}

/// Shared contract calls retain ordinary object identity, but must not transfer
/// execution-local capabilities whose meaning belongs to the originating VM.
pub(crate) fn validate_contract_values<'a>(
    values: impl Iterator<Item = &'a VmValue>,
) -> Result<(), VmExecutionError> {
    validate_boundary_values(values, "contract boundaries")
}
pub(crate) fn validate_external_values<'a>(
    values: impl Iterator<Item = &'a VmValue>,
) -> Result<(), VmExecutionError> {
    validate_boundary_values(values, "the VM boundary")
}
fn validate_boundary_values<'a>(
    values: impl Iterator<Item = &'a VmValue>,
    boundary: &'static str,
) -> Result<(), VmExecutionError> {
    let mut visitor = ContractValueVisitor {
        seen: HashSet::new(),
        nodes: 0,
        boundary,
    };
    for value in values {
        visitor.visit(value, 0)?;
    }
    Ok(())
}
struct ContractValueVisitor {
    boundary: &'static str,
    seen: HashSet<usize>,
    nodes: usize,
}
impl ContractValueVisitor {
    fn visit(&mut self, value: &VmValue, depth: usize) -> Result<(), VmExecutionError> {
        self.nodes += 1;
        if self.nodes > MAX_VALUE_NODES || depth > MAX_VALUE_DEPTH {
            return Err(VmExecutionError::new(
                "shared contract value traversal limit exceeded",
            ));
        }
        if let VmValue::Reference(reference) = value {
            if !self.seen.insert(reference.id()) {
                return Ok(());
            }
            return reference.with_value(|value| self.contents(value, depth));
        }
        self.contents(value, depth)
    }
    fn contents(&mut self, value: &VmValue, depth: usize) -> Result<(), VmExecutionError> {
        if let Some(kind) = execution_local_capability(value) {
            return Err(VmExecutionError::new(format!(
                "{kind} cannot cross {}",
                self.boundary
            )));
        }
        match value {
            VmValue::InterfaceDescriptor(descriptor) => {
                if self.boundary != "contract boundaries" {
                    return Err(VmExecutionError::new(
                        "interface descriptors cannot cross the VM boundary",
                    ));
                }
                for (name, value) in &descriptor.attributes {
                    if !descriptor.safe_storage_type(name, value) {
                        self.visit(value, depth + 1)?;
                    }
                }
                Ok(())
            }
            VmValue::Dict(entries) => {
                for (key, value) in entries {
                    self.visit(key, depth + 1)?;
                    self.visit(value, depth + 1)?;
                }
                Ok(())
            }
            VmValue::List(items)
            | VmValue::Tuple(items)
            | VmValue::Set(items)
            | VmValue::BuiltinSet(items)
            | VmValue::FrozenSet(items) => self.items(items, depth),
            VmValue::Exception(exception) => self.items(&exception.args, depth),
            VmValue::DecimalTuple(tuple) => self.items(&tuple.as_values(), depth),
            VmValue::View(view) => self.visit(&view.source, depth + 1),
            VmValue::Iterator(iterator) => {
                iterator.visit_children(&mut |value| self.visit(value, depth + 1))
            }
            _ => Ok(()),
        }
    }
    fn items(&mut self, items: &[VmValue], depth: usize) -> Result<(), VmExecutionError> {
        for item in items {
            self.visit(item, depth + 1)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod contract_boundary_tests {
    use super::*;

    fn bound_storage_get() -> VmValue {
        VmValue::BoundMethod(Box::new(crate::VmBoundMethod {
            receiver: VmValue::StorageRef(crate::VmStorageRef {
                binding: "state".into(),
                storage_type: "Variable".into(),
            }),
            method: "get".into(),
        }))
    }

    #[test]
    fn methods_proxies_and_hidden_iterator_callbacks_are_rejected() {
        let values = [
            VmValue::StorageRef(crate::VmStorageRef {
                binding: "state".into(),
                storage_type: "Variable".into(),
            }),
            VmValue::FunctionRef("private_helper".into()),
            VmValue::EventRef(Box::new(crate::VmEventDefinition {
                binding: "event".into(),
                event_name: "Notice".into(),
                params: VmValue::Dict(vec![]),
            })),
            bound_storage_get(),
            VmValue::List(vec![bound_storage_get()]),
            VmValue::Dict(vec![(VmValue::String("f".into()), bound_storage_get())]),
            VmValue::MappingProxy(Box::new(VmValue::Dict(vec![]))),
        ];
        for value in values {
            assert!(validate_contract_values(std::iter::once(&value)).is_err());
        }
        let heap = VmHeap::default();
        let iterator = crate::iteration::lazy(
            "map",
            &[bound_storage_get(), VmValue::List(vec![])],
            &[],
            &heap,
        )
        .unwrap();
        assert!(validate_contract_values(std::iter::once(&iterator)).is_err());
    }

    #[test]
    fn repeated_references_and_cycles_remain_shareable() {
        let heap = VmHeap::default();
        let value = heap.capture(VmValue::List(vec![])).unwrap();
        let VmValue::Reference(reference) = &value else {
            panic!()
        };
        reference.append_sequence(value.clone()).unwrap();
        validate_contract_values(std::iter::once(&value)).unwrap();
        let mut dag = VmValue::None;
        for _ in 0..40 {
            dag = heap
                .capture(VmValue::Tuple(vec![dag.clone(), dag]))
                .unwrap();
        }
        validate_contract_values(std::iter::once(&dag)).unwrap();
        assert!(reference.with_value(|value| matches!(value,VmValue::List(items) if items[0].identical(&VmValue::Reference(reference.clone())))));
    }

    #[test]
    fn shared_graph_limits_apply_across_all_call_arguments() {
        let boundary = VmValue::List(vec![VmValue::None; 131_071]);
        validate_contract_values(std::iter::once(&boundary)).unwrap();
        let too_many = VmValue::List(vec![VmValue::None; 131_072]);
        assert!(validate_contract_values(std::iter::once(&too_many)).is_err());
        let first = VmValue::List(vec![VmValue::None; 70_000]);
        let second = first.clone();
        assert!(validate_contract_values([&first, &second].into_iter()).is_err());
        let mut nested = VmValue::None;
        for _ in 0..128 {
            nested = VmValue::Tuple(vec![nested]);
        }
        validate_contract_values(std::iter::once(&nested)).unwrap();
        assert!(validate_contract_values(std::iter::once(&VmValue::Tuple(vec![nested]))).is_err());
    }
}
