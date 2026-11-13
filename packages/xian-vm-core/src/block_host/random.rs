//! The contract random syscalls: `contracting.stdlib.bridge.random` as
//! `NativeVmHost.handle_syscall` serves them. A transaction has one random
//! state, shared by its nested calls and constructors; `seed()` starts a
//! stream from the transaction's context and an optional salt.
//!
//! The Python functions receive the VM's arguments converted to Python values
//! and return values the VM converts back (`vm_to_py`, `py_to_vm`). This port
//! serves the calls whose arguments that conversion keeps as they are (ints,
//! bools, text, bytes, `None`, the VM's index lists), bound as Python binds
//! them, with Python's results and exceptions. The VM's work bounds
//! (`interpreter::random_bounds`) come first, here as in the VM (this host
//! runs V2 only): no draw above 512 bits or the sequence limit, salts only
//! str, int, bool or `None`, populations only sequences the VM indexes. It
//! hands back to the Python path, unchanged: other argument types for the
//! numbers (their conversion is Python's) and call shapes Python refuses
//! with its own binding errors. Increment 7 of the single-engine plan gives
//! those explicit rules.
mod stream;
#[cfg(test)]
mod tests;

pub(crate) use stream::Stream;

use crate::interpreter::{numeric_v2, random_bounds};
use crate::{VmExecutionContext, VmExecutionError, VmValue};
use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive, Zero};

const UNSEEDED: &str = "Random state not seeded. Call seed().";
/// `_seed_material`'s context fields with the defaults of their `or`.
const SEED_FIELDS: [(&str, &str); 4] = [
    ("chain_id", ""),
    ("block_num", "0"),
    ("block_hash", "0"),
    ("input_hash", "0"),
];

/// Why a random syscall returned no value.
#[derive(Debug)]
pub(crate) enum Refusal {
    /// What the Python call raises, as the VM receives it (`host_error`), or
    /// the boundary's refusal of its result.
    Raised(VmExecutionError),
    /// A call this port leaves to the Python path.
    Handback(String),
}

pub(crate) type Served = Result<VmValue, Refusal>;

/// One transaction's random state.
pub(crate) struct TxRandom {
    /// `chain_id`, `block_num`, `block_hash` and `__input_hash`.
    context: [VmValue; 4],
    stream: Option<Stream>,
}

impl TxRandom {
    pub(crate) fn new(context: &VmExecutionContext) -> Self {
        Self {
            context: [
                context.chain_id.clone(),
                context.block_num.clone(),
                context.block_hash.clone(),
                context.input_hash.clone(),
            ],
            stream: None,
        }
    }

    /// `_current_random`.
    fn stream(&mut self) -> Result<&mut Stream, Refusal> {
        self.stream
            .as_mut()
            .ok_or_else(|| raised("AssertionError", UNSEEDED))
    }

    /// `_seed_material`: each context value, or its default when falsy,
    /// then the salt unless it is `None`.
    fn seed_material(&self, salt: &VmValue) -> Result<String, Refusal> {
        let mut parts = Vec::with_capacity(SEED_FIELDS.len() + 1);
        for ((name, default), value) in SEED_FIELDS.iter().zip(&self.context) {
            let text = match falsy(value) {
                Some(true) => Some((*default).to_owned()),
                Some(false) => python_text(value),
                None => None,
            };
            let text = text.ok_or_else(|| unknown(&format!("seed {name}"), value))?;
            parts.push(format!("{name}={text}"));
        }
        if !matches!(salt, VmValue::None) {
            let text = python_text(salt).expect("random_bounds admits only these salts");
            parts.push(format!("aux_salt={text}"));
        }
        Ok(parts.join("|"))
    }
}

/// The random syscall `syscall_id` (`None`: not one served here).
pub(crate) fn call(
    random: &mut TxRandom,
    syscall_id: &str,
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Option<Served> {
    let name = syscall_id.strip_prefix("random.")?;
    let operation = OPERATIONS.iter().find(|operation| operation.name == name)?;
    if let Err(refused) = random_bounds::check_v2(syscall_id, &args, &kwargs) {
        return Some(Err(Refusal::Raised(refused)));
    }
    Some(match bind(operation, args, kwargs) {
        Some(bound) => (operation.run)(random, &bound).and_then(boundary),
        None => Err(Refusal::Handback(format!("{syscall_id} call shape"))),
    })
}

/// A random function: its parameters, how many of them are required (the
/// rest default to `None`), whether it is called with keywords too, and
/// what it does with the bound arguments.
struct Operation {
    name: &'static str,
    params: &'static [&'static str],
    required: usize,
    keywords: bool,
    run: fn(&mut TxRandom, &[VmValue]) -> Served,
}

const fn operation(
    name: &'static str,
    params: &'static [&'static str],
    run: fn(&mut TxRandom, &[VmValue]) -> Served,
) -> Operation {
    Operation {
        name,
        params,
        required: params.len(),
        keywords: true,
        run,
    }
}

const OPERATIONS: [Operation; 8] = [
    Operation {
        required: 0,
        ..operation("seed", &["aux_salt"], seed)
    },
    operation("random", &[], random_float),
    // `handle_syscall` returns shuffle's first positional argument.
    Operation {
        keywords: false,
        ..operation("shuffle", &["items"], shuffle)
    },
    operation("getrandbits", &["k"], getrandbits),
    operation("randrange", &["k"], randrange),
    operation("randint", &["a", "b"], randint),
    operation("choice", &["items"], choice),
    operation("choices", &["items", "k"], choices),
];

/// The arguments bound to `operation`'s parameters as Python binds a call,
/// or `None` where Python would raise a binding error.
fn bind(
    operation: &Operation,
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Option<Vec<VmValue>> {
    if args.len() > operation.params.len() || (!operation.keywords && !kwargs.is_empty()) {
        return None;
    }
    let mut bound: Vec<Option<VmValue>> = args.into_iter().map(Some).collect();
    bound.resize(operation.params.len(), None);
    for (name, value) in kwargs {
        let index = operation.params.iter().position(|param| *param == name)?;
        if bound[index].replace(value).is_some() {
            return None;
        }
    }
    bound
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            value.or_else(|| (index >= operation.required).then_some(VmValue::None))
        })
        .collect()
}

fn seed(random: &mut TxRandom, args: &[VmValue]) -> Served {
    let material = random.seed_material(&args[0])?;
    random.stream = Some(Stream::new(&material));
    Ok(VmValue::None)
}

fn random_float(random: &mut TxRandom, _: &[VmValue]) -> Served {
    Ok(VmValue::Float(random.stream()?.random()))
}

fn shuffle(random: &mut TxRandom, args: &[VmValue]) -> Served {
    let Population::Items(items) = Population::of(&args[0])? else {
        return Err(unknown("shuffle population", &args[0]));
    };
    let stream = random.stream()?;
    let mut items = items.to_vec();
    for index in (1..items.len()).rev() {
        let other = stream.index_below(index + 1);
        items.swap(index, other);
    }
    Ok(VmValue::List(items))
}

fn getrandbits(random: &mut TxRandom, args: &[VmValue]) -> Served {
    let bits = number(&args[0])?;
    let stream = random.stream()?;
    match bits.to_u64() {
        Some(bits) => Ok(VmValue::Int(stream.getrandbits(bits).into())),
        None => Err(raised("ValueError", "number of bits must be non-negative")),
    }
}

fn randrange(random: &mut TxRandom, args: &[VmValue]) -> Served {
    let upper = number(&args[0])?;
    let stream = random.stream()?;
    match upper.to_biguint().filter(|upper| !upper.is_zero()) {
        Some(upper) => Ok(VmValue::Int(stream.randbelow(&upper).into())),
        None => Err(raised("ValueError", "upper bound must be positive")),
    }
}

fn randint(random: &mut TxRandom, args: &[VmValue]) -> Served {
    let (low, high) = (number(&args[0])?, number(&args[1])?);
    if low > high {
        return Err(raised("ValueError", "empty range for randint()"));
    }
    let span = (&high - &low + 1u32).to_biguint().expect("a positive span");
    Ok(VmValue::Int(
        low + BigInt::from(random.stream()?.randbelow(&span)),
    ))
}

fn choice(random: &mut TxRandom, args: &[VmValue]) -> Served {
    choose(random, &Population::of(&args[0])?)
}

fn choices(random: &mut TxRandom, args: &[VmValue]) -> Served {
    let population = Population::of(&args[0])?;
    let draws = number(&args[1])?;
    if draws.is_negative() {
        return Err(raised(
            "ValueError",
            "number of choices must be non-negative",
        ));
    }
    let draws = draws.to_u64().expect("random_bounds bounds the draws");
    (0..draws)
        .map(|_| choose(random, &population))
        .collect::<Result<_, _>>()
        .map(VmValue::List)
}

/// `choice`: the length check, then a draw below it.
fn choose(random: &mut TxRandom, population: &Population<'_>) -> Served {
    let len = population.len();
    if len == 0 {
        return Err(raised("IndexError", "Cannot choose from an empty sequence"));
    }
    let index = random.stream()?.index_below(len);
    Ok(population.get(index))
}

/// A sequence the Python functions index: the VM's index list (it replaces a
/// list or tuple population with the positions of its items), text by code
/// point, or bytes as ints.
enum Population<'a> {
    Items(&'a [VmValue]),
    Text(Vec<char>),
    Bytes(&'a [u8]),
}

impl<'a> Population<'a> {
    fn of(value: &'a VmValue) -> Result<Self, Refusal> {
        match value {
            VmValue::List(items) => {
                match items.iter().find(|item| !matches!(item, VmValue::Int(_))) {
                    None => Ok(Self::Items(items)),
                    Some(item) => Err(Refusal::Handback(format!(
                        "random population is a list of {}",
                        item.type_name()
                    ))),
                }
            }
            VmValue::String(text) => Ok(Self::Text(text.chars().collect())),
            VmValue::Bytes(bytes) | VmValue::ByteArray(bytes) => Ok(Self::Bytes(bytes)),
            other => Err(unknown("population", other)),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Items(items) => items.len(),
            Self::Text(text) => text.len(),
            Self::Bytes(bytes) => bytes.len(),
        }
    }

    fn get(&self, index: usize) -> VmValue {
        match self {
            Self::Items(items) => items[index].clone(),
            Self::Text(text) => VmValue::String(text[index].to_string()),
            Self::Bytes(bytes) => VmValue::Int(bytes[index].into()),
        }
    }
}

/// An int argument (a bool is one in Python).
fn number(value: &VmValue) -> Result<BigInt, Refusal> {
    match value {
        VmValue::Int(number) => Ok(number.clone()),
        VmValue::Bool(flag) => Ok(BigInt::from(u8::from(*flag))),
        other => Err(unknown("argument", other)),
    }
}

/// Python's truth value of the values whose `str()` is known here.
fn falsy(value: &VmValue) -> Option<bool> {
    match value {
        VmValue::None => Some(true),
        VmValue::Bool(flag) => Some(!flag),
        VmValue::Int(number) => Some(number.is_zero()),
        VmValue::String(text) => Some(text.is_empty()),
        _ => None,
    }
}

/// Python's `str()` of a str, int, bool or `None`.
fn python_text(value: &VmValue) -> Option<String> {
    match value {
        VmValue::String(text) => Some(text.clone()),
        VmValue::Int(number) => Some(number.to_string()),
        VmValue::Bool(true) => Some("True".to_owned()),
        VmValue::Bool(false) => Some("False".to_owned()),
        VmValue::None => Some("None".to_owned()),
        _ => None,
    }
}

/// The V2 boundary's refusal of a returned value (`py_to_vm`).
fn boundary(value: VmValue) -> Served {
    if numeric_v2::active() {
        numeric_v2::validate_leaf(&value).map_err(Refusal::Raised)?;
    }
    Ok(value)
}

/// A Python exception with one message, as `host_error` converts it.
fn raised(name: &str, message: &str) -> Refusal {
    Refusal::Raised(VmExecutionError::described(
        name,
        format!("{name}: {message}"),
        message,
    ))
}

fn unknown(what: &str, value: &VmValue) -> Refusal {
    Refusal::Handback(format!("random {what} is a {}", value.type_name()))
}
