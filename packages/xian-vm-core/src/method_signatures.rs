//! One public method catalog drives attribute admission and argument binding.
use super::*;

type Arguments = (Vec<VmValue>, Vec<(String, VmValue)>);
#[derive(Clone, Copy)]
enum Default {
    None,
    Int(i64),
    Bool(bool),
    Text(&'static str),
    Bytes,
    OmittedHex,
}
impl Default {
    fn value(self) -> VmValue {
        match self {
            Self::None => VmValue::None,
            Self::Int(value) => vm_int(value),
            Self::Bool(value) => VmValue::Bool(value),
            Self::Text(value) => VmValue::String(value.into()),
            Self::Bytes => VmValue::Bytes(vec![]),
            Self::OmittedHex => VmValue::Builtin("__binary_hex_default_sep".into()),
        }
    }
}
#[derive(Clone, Copy)]
enum Signature {
    Positional(usize, usize),
    Named {
        names: &'static [&'static str],
        defaults: &'static [Default],
        required: usize,
        positional: usize,
    },
    BinaryTranslate,
    Custom,
}
use self::Default::{Bool, Int, None as Null, Text};
use self::Signature::{BinaryTranslate, Custom, Named, Positional as Pos};

pub(super) fn supports(receiver: &VmValue, method: &str) -> bool {
    signature(receiver, method).is_some()
}

pub(super) fn bind(
    receiver: &VmValue,
    method: &str,
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<Arguments, VmExecutionError> {
    let sig = signature(receiver, method).ok_or_else(|| {
        VmExecutionError::new(format!(
            "{} has no public method '{method}'",
            receiver.type_name()
        ))
    })?;
    match sig {
        Custom => Ok((args, kwargs)),
        BinaryTranslate => bind_translate(method, args, kwargs),
        Pos(min, max) => bind_positional(method, args, kwargs, min, max),
        Named {
            names,
            defaults,
            required,
            positional,
        } => bind_named(method, args, kwargs, names, defaults, required, positional),
    }
}

fn bind_translate(
    method: &str,
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<Arguments, VmExecutionError> {
    if args.is_empty() || args.len() > 2 {
        return Err(VmExecutionError::new(
            "translate() requires a positional table and optional delete",
        ));
    }
    if kwargs.iter().any(|(name, _)| name != "delete") {
        return Err(VmExecutionError::new(
            "translate() got unexpected keyword; table is positional-only",
        ));
    }
    bind_named(
        method,
        args,
        kwargs,
        &["table", "delete"],
        &[Null, Default::Bytes],
        1,
        2,
    )
}
fn bind_positional(
    method: &str,
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
    min: usize,
    max: usize,
) -> Result<Arguments, VmExecutionError> {
    if !kwargs.is_empty() {
        return Err(VmExecutionError::new(format!(
            "{method}() accepts positional arguments only; unexpected keyword"
        )));
    }
    if args.len() < min || args.len() > max {
        return Err(VmExecutionError::new(format!(
            "invalid positional argument count for {method}()"
        )));
    }
    Ok((args, vec![]))
}

fn bind_named(
    method: &str,
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
    names: &[&str],
    defaults: &[Default],
    required: usize,
    positional: usize,
) -> Result<Arguments, VmExecutionError> {
    if args.len() > positional {
        return Err(VmExecutionError::new(format!(
            "too many positional arguments for {method}()"
        )));
    }
    let mut bound: Vec<Option<VmValue>> = vec![None; names.len()];
    let mut length = args.len();
    for (index, value) in args.into_iter().enumerate() {
        bound[index] = Some(value);
    }
    for (name, value) in kwargs {
        let index = names.iter().position(|item| *item == name).ok_or_else(|| {
            VmExecutionError::new(format!("{method}() got unexpected keyword '{name}'"))
        })?;
        if bound[index].is_some() {
            return Err(VmExecutionError::new(format!(
                "{method}() got multiple values for '{name}'"
            )));
        }
        bound[index] = Some(value);
        length = length.max(index + 1);
    }
    if bound[..required].iter().any(Option::is_none) {
        return Err(VmExecutionError::new(format!(
            "{method}() missing required argument"
        )));
    }
    let values = bound
        .into_iter()
        .take(length)
        .enumerate()
        .map(|(index, value)| value.unwrap_or_else(|| defaults[index].value()))
        .collect();
    Ok((values, vec![]))
}

fn signature(receiver: &VmValue, method: &str) -> Option<Signature> {
    if method.starts_with('_') {
        return None;
    }
    if let VmValue::Reference(reference) = receiver {
        return reference.with_value(|value| signature(value, method));
    }
    scalar_value_signature(receiver, method)
        .or_else(|| collection_signature(receiver, method))
        .or_else(|| capability_signature(receiver, method))
}
fn scalar_value_signature(receiver: &VmValue, method: &str) -> Option<Signature> {
    match receiver {
        VmValue::String(_) => text_signature(method, false),
        VmValue::Bytes(_) | VmValue::ByteArray(_) => {
            binary_signature(method, matches!(receiver, VmValue::ByteArray(_)))
        }
        VmValue::Int(_) | VmValue::Bool(_) | VmValue::Float(_) | VmValue::Range(_) => {
            scalar_signature(receiver, method)
        }
        VmValue::RawDecimal(_) => crate::decimal_methods::supports(method).then_some(Custom),
        VmValue::DateTime(_) if method == "strptime" => Some(strptime_signature()),
        _ => None,
    }
}
fn collection_signature(receiver: &VmValue, method: &str) -> Option<Signature> {
    match receiver {
        VmValue::List(_) => list_signature(method),
        VmValue::Tuple(_) | VmValue::DecimalTuple(_) => {
            positionals(method, &[(&["count"], 1, 1), (&["index"], 1, 3)])
        }
        VmValue::Dict(_) => dict_signature(method),
        VmValue::BuiltinSet(_) => builtin_set_signature(method),
        VmValue::Set(_) | VmValue::FrozenSet(_) => {
            set_signature(method, matches!(receiver, VmValue::Set(_)))
        }
        _ => None,
    }
}
fn capability_signature(receiver: &VmValue, method: &str) -> Option<Signature> {
    match receiver {
        VmValue::MappingProxy(_) => ["keys", "values", "items", "get", "copy"]
            .contains(&method)
            .then(|| dict_signature(method))
            .flatten(),
        VmValue::View(view) => (!matches!(view.mode, crate::iteration::ViewMode::Values)
            && method == "isdisjoint")
            .then_some(Pos(1, 1)),
        VmValue::Builtin(name) | VmValue::TypeMarker(name) => class_signature(name, method),
        VmValue::StorageRef(storage) => storage_signature(&storage.storage_type, method),
        VmValue::ForeignStorageRef(storage) => storage_signature(
            if storage.is_hash {
                "ForeignHash"
            } else {
                "ForeignVariable"
            },
            method,
        ),
        _ => None,
    }
}
fn positionals(method: &str, groups: &[(&[&str], usize, usize)]) -> Option<Signature> {
    groups
        .iter()
        .find(|(names, _, _)| names.contains(&method))
        .map(|(_, min, max)| Pos(*min, *max))
}

fn text_signature(method: &str, binary: bool) -> Option<Signature> {
    positionals(
        method,
        &[
            (
                &[
                    "capitalize",
                    "casefold",
                    "isalnum",
                    "isalpha",
                    "isascii",
                    "isdecimal",
                    "isdigit",
                    "isidentifier",
                    "islower",
                    "isnumeric",
                    "isprintable",
                    "isspace",
                    "istitle",
                    "isupper",
                    "lower",
                    "swapcase",
                    "title",
                    "upper",
                ],
                0,
                0,
            ),
            (&["center", "ljust", "rjust"], 1, 2),
            (
                &[
                    "count",
                    "find",
                    "index",
                    "rfind",
                    "rindex",
                    "startswith",
                    "endswith",
                ],
                1,
                3,
            ),
            (
                &[
                    "join",
                    "partition",
                    "rpartition",
                    "removeprefix",
                    "removesuffix",
                    "zfill",
                ],
                1,
                1,
            ),
            (&["strip", "lstrip", "rstrip"], 0, 1),
            (&["replace"], 2, 3),
        ],
    )
    .or_else(|| text_named_signature(method, binary))
}
fn text_named_signature(method: &str, binary: bool) -> Option<Signature> {
    Some(match method {
        "expandtabs" => Named {
            names: &["tabsize"],
            defaults: &[Int(8)],
            required: 0,
            positional: 1,
        },
        "split" | "rsplit" => Named {
            names: &["sep", "maxsplit"],
            defaults: &[Null, Int(-1)],
            required: 0,
            positional: 2,
        },
        "splitlines" => Named {
            names: &["keepends"],
            defaults: &[Bool(false)],
            required: 0,
            positional: 1,
        },
        _ => return string_only_signature(method, binary),
    })
}
fn string_only_signature(method: &str, binary: bool) -> Option<Signature> {
    if binary {
        return None;
    }
    Some(match method {
        "encode" => Named {
            names: &["encoding", "errors"],
            defaults: &[Text("utf-8"), Text("strict")],
            required: 0,
            positional: 2,
        },
        "format" | "format_map" => Custom,
        "translate" => Pos(1, 1),
        "maketrans" => Pos(1, 3),
        _ => return None,
    })
}
fn binary_signature(method: &str, mutable: bool) -> Option<Signature> {
    if [
        "casefold",
        "isdecimal",
        "isidentifier",
        "isnumeric",
        "isprintable",
    ]
    .contains(&method)
    {
        return None;
    }
    binary_only_signature(method)
        .or_else(|| mutable.then(|| binary_mutation_signature(method)).flatten())
        .or_else(|| text_signature(method, true))
}
fn binary_only_signature(method: &str) -> Option<Signature> {
    Some(match method {
        "decode" => Named {
            names: &["encoding", "errors"],
            defaults: &[Text("utf-8"), Text("strict")],
            required: 0,
            positional: 2,
        },
        "hex" => Named {
            names: &["sep", "bytes_per_sep"],
            defaults: &[Default::OmittedHex, Int(1)],
            required: 0,
            positional: 2,
        },
        "translate" => BinaryTranslate,
        "fromhex" => Pos(1, 1),
        "maketrans" => Pos(2, 2),
        _ => return None,
    })
}
fn binary_mutation_signature(method: &str) -> Option<Signature> {
    positionals(
        method,
        &[
            (&["append", "extend", "remove"], 1, 1),
            (&["insert"], 2, 2),
            (&["pop"], 0, 1),
            (&["clear", "copy", "reverse"], 0, 0),
        ],
    )
}

fn list_signature(method: &str) -> Option<Signature> {
    Some(match method {
        "append" | "extend" | "remove" | "count" => Pos(1, 1),
        "insert" => Pos(2, 2),
        "index" => Pos(1, 3),
        "pop" => Pos(0, 1),
        "clear" | "copy" | "reverse" => Pos(0, 0),
        "sort" => Custom,
        _ => return None,
    })
}
fn dict_signature(method: &str) -> Option<Signature> {
    Some(match method {
        "get" | "pop" | "setdefault" | "fromkeys" => Pos(1, 2),
        "keys" | "values" | "items" | "clear" | "copy" | "popitem" => Pos(0, 0),
        "update" => Custom,
        _ => return None,
    })
}
fn builtin_set_signature(method: &str) -> Option<Signature> {
    Some(match method {
        "add"
        | "remove"
        | "discard"
        | "issubset"
        | "issuperset"
        | "isdisjoint"
        | "symmetric_difference"
        | "symmetric_difference_update" => Pos(1, 1),
        "union"
        | "intersection"
        | "difference"
        | "update"
        | "intersection_update"
        | "difference_update" => Pos(0, usize::MAX),
        "clear" | "pop" | "copy" => Pos(0, 0),
        _ => return None,
    })
}
fn set_signature(method: &str, mutable: bool) -> Option<Signature> {
    Some(match method {
        "issubset" | "issuperset" | "isdisjoint" | "symmetric_difference" => Named {
            names: &["other"],
            defaults: &[Null],
            required: 1,
            positional: 1,
        },
        "union" | "intersection" | "difference" => Pos(0, usize::MAX),
        "copy" => Pos(0, 0),
        "clear" | "pop" if mutable => Pos(0, 0),
        "add" | "remove" | "discard" if mutable => Named {
            names: &["value"],
            defaults: &[Null],
            required: 1,
            positional: 1,
        },
        _ => return None,
    })
}
fn scalar_signature(receiver: &VmValue, method: &str) -> Option<Signature> {
    match receiver {
        VmValue::Range(_) => positionals(method, &[(&["count", "index"], 1, 1)]),
        VmValue::Float(_) => positionals(
            method,
            &[
                (
                    &["is_integer", "hex", "as_integer_ratio", "conjugate"],
                    0,
                    0,
                ),
                (&["fromhex"], 1, 1),
            ],
        ),
        _ => integer_signature(method),
    }
}
fn integer_signature(method: &str) -> Option<Signature> {
    Some(match method {
        "bit_count" | "bit_length" | "as_integer_ratio" | "conjugate" | "is_integer" => Pos(0, 0),
        "to_bytes" => Named {
            names: &["length", "byteorder", "signed"],
            defaults: &[Int(1), Text("big"), Bool(false)],
            required: 0,
            positional: 2,
        },
        "from_bytes" => Named {
            names: &["bytes", "byteorder", "signed"],
            defaults: &[Null, Text("big"), Bool(false)],
            required: 1,
            positional: 2,
        },
        _ => return None,
    })
}

fn class_signature(name: &str, method: &str) -> Option<Signature> {
    match (name, method) {
        ("str", "maketrans") => Some(Pos(1, 3)),
        ("bytes" | "bytearray", "fromhex") => Some(Pos(1, 1)),
        ("bytes" | "bytearray", "maketrans") => Some(Pos(2, 2)),
        ("dict", "fromkeys") => Some(Pos(1, 2)),
        ("int" | "bool", "from_bytes") => scalar_signature(&vm_int(0), method),
        ("float", "fromhex") => Some(Pos(1, 1)),
        ("datetime.datetime", "strptime") => Some(strptime_signature()),
        _ => representative(name)
            .filter(|value| signature(value, method).is_some())
            .map(|_| Custom),
    }
}
fn strptime_signature() -> Signature {
    Named {
        names: &["date_string", "format"],
        defaults: &[Null, Null],
        required: 2,
        positional: 2,
    }
}

fn storage_signature(kind: &str, method: &str) -> Option<Signature> {
    match (kind, method) {
        ("Hash" | "ForeignHash", "all" | "clear") => Some(Pos(0, usize::MAX)),
        ("Hash" | "ForeignHash", "clone_from") => Some(Named {
            names: &["source"],
            defaults: &[Null],
            required: 1,
            positional: 1,
        }),
        ("Variable" | "ForeignVariable", "get" | "clear") => Some(Pos(0, 0)),
        ("Variable" | "ForeignVariable", "set" | "append" | "remove") => Some(Named {
            names: &["value"],
            defaults: &[Null],
            required: 1,
            positional: 1,
        }),
        ("Variable" | "ForeignVariable", "extend") => Some(Named {
            names: &["values"],
            defaults: &[Null],
            required: 1,
            positional: 1,
        }),
        ("Variable" | "ForeignVariable", "update") => Some(Named {
            names: &["other"],
            defaults: &[Null],
            required: 1,
            positional: 1,
        }),
        ("Variable" | "ForeignVariable", "insert") => Some(Named {
            names: &["index", "value"],
            defaults: &[Null, Null],
            required: 2,
            positional: 2,
        }),
        ("Variable" | "ForeignVariable", "pop") => Some(Named {
            names: &["key", "default"],
            defaults: &[Null, Null],
            required: 0,
            positional: 2,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_arguments_fill_only_holes_and_reject_duplicates() {
        let text = VmValue::String("a b c".into());
        let (args, kwargs) =
            bind(&text, "split", vec![], vec![("maxsplit".into(), vm_int(1))]).unwrap();
        assert_eq!(args, vec![VmValue::None, vm_int(1)]);
        assert!(kwargs.is_empty());
        assert!(bind(
            &text,
            "split",
            vec![VmValue::None],
            vec![("sep".into(), VmValue::None)]
        )
        .is_err());
        assert!(bind(&text, "split", vec![], vec![("bad".into(), vm_int(1))]).is_err());
        assert!(bind(
            &text,
            "split",
            vec![VmValue::None, vm_int(1), vm_int(2)],
            vec![]
        )
        .is_err());
    }

    #[test]
    fn positional_and_keyword_only_parameters_remain_distinct() {
        assert!(bind(
            &VmValue::List(vec![]),
            "append",
            vec![],
            vec![("value".into(), vm_int(1))]
        )
        .is_err());
        assert!(bind(
            &vm_int(1),
            "to_bytes",
            vec![
                vm_int(1),
                VmValue::String("big".into()),
                VmValue::Bool(true)
            ],
            vec![]
        )
        .is_err());
        let (args, _) = bind(
            &vm_int(1),
            "to_bytes",
            vec![],
            vec![("signed".into(), VmValue::Bool(true))],
        )
        .unwrap();
        assert_eq!(
            args,
            vec![
                vm_int(1),
                VmValue::String("big".into()),
                VmValue::Bool(true)
            ]
        );
        assert!(bind(
            &VmValue::Bytes(vec![]),
            "translate",
            vec![],
            vec![("table".into(), VmValue::None)]
        )
        .is_err());
    }

    #[test]
    fn omitted_binary_separator_is_not_explicit_none() {
        let bytes = VmValue::Bytes(vec![1, 2]);
        let (omitted, _) = bind(
            &bytes,
            "hex",
            vec![],
            vec![("bytes_per_sep".into(), vm_int(2))],
        )
        .unwrap();
        assert_eq!(
            omitted,
            vec![
                VmValue::Builtin("__binary_hex_default_sep".into()),
                vm_int(2)
            ]
        );
        let (explicit, _) = bind(&bytes, "hex", vec![VmValue::None], vec![]).unwrap();
        assert_eq!(explicit, vec![VmValue::None]);
        assert!(!supports(&bytes, "__class__"));
        assert!(!supports(&bytes, "not_a_method"));
    }
    #[test]
    fn positional_limits_accept_both_edges_and_reject_outside() {
        let list = VmValue::List(vec![]);
        assert!(bind(&list, "append", vec![vm_int(1)], vec![]).is_ok());
        assert!(bind(&list, "append", vec![], vec![]).is_err());
        assert!(bind(&list, "append", vec![vm_int(1), vm_int(2)], vec![]).is_err());
        assert!(bind(&list, "pop", vec![], vec![]).is_ok());
        assert!(bind(&list, "pop", vec![vm_int(0)], vec![]).is_ok());
        let text = VmValue::String("a b".into());
        let (args, _) = bind(&text, "split", vec![VmValue::None, vm_int(1)], vec![]).unwrap();
        assert_eq!(args, vec![VmValue::None, vm_int(1)]);
        assert!(bind(&vm_int(1), "from_bytes", vec![], vec![]).is_err());
    }

    #[test]
    fn binary_translate_table_is_positional_and_delete_may_be_named() {
        let bytes = VmValue::Bytes(vec![1, 2]);
        let deletion = VmValue::Bytes(vec![1]);
        let (args, _) = bind(
            &bytes,
            "translate",
            vec![VmValue::None],
            vec![("delete".into(), deletion.clone())],
        )
        .unwrap();
        assert_eq!(args, vec![VmValue::None, deletion.clone()]);
        assert!(bind(
            &bytes,
            "translate",
            vec![VmValue::None, deletion.clone()],
            vec![]
        )
        .is_ok());
        assert!(bind(
            &bytes,
            "translate",
            vec![VmValue::None],
            vec![("table".into(), VmValue::None)]
        )
        .is_err());
        assert!(bind(
            &bytes,
            "translate",
            vec![VmValue::None, deletion.clone()],
            vec![("delete".into(), deletion)]
        )
        .is_err());
    }
}

/// Python wrapper methods bind self by name, unlike C method descriptors.
pub(super) fn wrapper_class(receiver: &VmValue, method: &str) -> Option<&'static str> {
    let class = match receiver {
        VmValue::Builtin(name) | VmValue::TypeMarker(name) => match name.as_str() {
            "set" => "set",
            "frozenset" => "frozenset",
            _ => return None,
        },
        _ => return None,
    };
    let sample = if class == "set" {
        VmValue::Set(vec![])
    } else {
        VmValue::FrozenSet(vec![])
    };
    signature(&sample, method).map(|_| {
        if method != "copy" && set_signature(method, false).is_some() {
            "set"
        } else {
            class
        }
    })
}

pub(super) fn bind_wrapper_receiver(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<(VmValue, Vec<VmValue>, Vec<(String, VmValue)>), VmExecutionError> {
    let mut args = args.into_iter();
    let mut receiver = args.next();
    let mut remaining = Vec::new();
    for (name, value) in kwargs {
        if name == "self" {
            if receiver.replace(value).is_some() {
                return Err(VmExecutionError::new("multiple values for self"));
            }
        } else {
            remaining.push((name, value));
        }
    }
    let receiver = receiver.ok_or_else(|| VmExecutionError::new("unbound method missing self"))?;
    Ok((receiver, args.collect(), remaining))
}

pub(super) fn wrapper_receiver_compatible(value: &VmValue, method: &str) -> bool {
    match value {
        VmValue::Reference(reference) => {
            reference.with_value(|value| wrapper_receiver_compatible(value, method))
        }
        VmValue::Set(_) => true,
        VmValue::FrozenSet(_) => set_signature(method, false).is_some(),
        _ => false,
    }
}

// Native descriptors on builtin classes bind the first positional argument at
// invocation, unlike class/static factories that retain the class receiver.
pub(super) fn unbound_class(receiver: &VmValue, method: &str) -> Option<&'static str> {
    let value = receiver.snapshot();
    let (VmValue::Builtin(name) | VmValue::TypeMarker(name)) = value else {
        return None;
    };
    if matches!(
        (name.as_str(), method),
        ("str", "maketrans")
            | ("dict", "fromkeys")
            | ("int" | "bool", "from_bytes")
            | ("float", "fromhex")
    ) {
        return None;
    }
    let kind = match name.as_str() {
        "str" => "str",
        "list" => "list",
        "tuple" => "tuple",
        "dict" => "dict",
        "int" | "bool" => "int",
        "float" => "float",
        _ => return None,
    };
    let sample = representative(kind)?;
    signature(&sample, method).map(|_| kind)
}
fn representative(name: &str) -> Option<VmValue> {
    Some(match name {
        "str" => VmValue::String(String::new()),
        "list" => VmValue::List(vec![]),
        "tuple" => VmValue::Tuple(vec![]),
        "dict" => VmValue::Dict(vec![]),
        "int" | "bool" => vm_int(0),
        "float" => VmValue::Float(0.0),
        _ => return None,
    })
}
pub(super) fn receiver_matches(kind: &str, value: &VmValue) -> bool {
    super::type_matches_name(value, kind)
}
