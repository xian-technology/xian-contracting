//! The random syscalls against values `contracting.stdlib.bridge.random`
//! produces (generated with the Python bridge; the full differential fuzz is
//! `tests/unit/test_native_vm_random_parity.py` in xian-contracting).
use super::*;
use crate::interpreter::numeric_v2::Scope;
use crate::XIAN_VM_V2_PROFILE;
use num_bigint::BigUint;

fn int(value: i64) -> VmValue {
    VmValue::Int(value.into())
}

fn big(text: &str) -> VmValue {
    VmValue::Int(text.parse().unwrap())
}

fn text(value: &str) -> VmValue {
    VmValue::String(value.to_owned())
}

fn list(values: &[i64]) -> VmValue {
    VmValue::List(values.iter().map(|value| int(*value)).collect())
}

fn context(
    chain_id: VmValue,
    block_num: VmValue,
    block_hash: VmValue,
    input_hash: VmValue,
) -> TxRandom {
    TxRandom::new(&VmExecutionContext {
        chain_id,
        block_num,
        block_hash,
        input_hash,
        ..VmExecutionContext::default()
    })
}

fn node_context() -> TxRandom {
    context(text("xian-local"), int(17), text("abc"), text("f00d"))
}

fn run(random: &mut TxRandom, syscall: &str, args: &[VmValue]) -> Served {
    call(random, syscall, args.to_vec(), vec![]).expect("a random syscall")
}

fn ok(random: &mut TxRandom, syscall: &str, args: &[VmValue]) -> VmValue {
    match run(random, syscall, args) {
        Ok(value) => value,
        Err(refusal) => panic!("{syscall} refused: {refusal:?}"),
    }
}

/// The text and the structured exception of a raised call.
fn raised_by(
    random: &mut TxRandom,
    syscall: &str,
    args: &[VmValue],
) -> (String, String, Vec<VmValue>) {
    match run(random, syscall, args) {
        Err(error) => {
            let exception = error.exception().expect("a structured exception");
            (
                error.to_string(),
                exception.name.clone(),
                exception.args.clone(),
            )
        }
        other => panic!("{syscall} did not raise: {other:?}"),
    }
}

/// The message of a call that fails with a `TypeError`.
fn type_error(
    random: &mut TxRandom,
    syscall: &str,
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
) -> String {
    match call(random, syscall, args.to_vec(), kwargs.to_vec()).expect("a random syscall") {
        Err(error) => {
            let exception = error.exception().expect("a structured exception");
            assert_eq!(exception.name, "TypeError");
            let VmValue::String(message) = &exception.args[0] else {
                panic!("a message argument");
            };
            assert_eq!(error.to_string(), format!("TypeError: {message}"));
            message.clone()
        }
        other => panic!("{syscall} was served: {other:?}"),
    }
}

/// The text and exception type name of a call that raised or was refused.
fn raised_or_refused(
    random: &mut TxRandom,
    syscall: &str,
    args: &[VmValue],
) -> (String, Option<String>, ()) {
    match run(random, syscall, args) {
        Err(error) => (
            error.to_string(),
            error.exception().map(|e| e.name.clone()),
            (),
        ),
        other => panic!("{syscall} did not raise: {other:?}"),
    }
}

/// The next 32 bits of a stream seeded with `material`.
fn draw(material: &str) -> VmValue {
    VmValue::Int(Stream::new(material).getrandbits(32).into())
}

#[test]
fn the_stream_is_pythons_deterministic_random() {
    let mut stream = Stream::new("seed|x");
    let bits: Vec<String> = [0, 1, 7, 8, 9, 70, 256, 513]
        .into_iter()
        .map(|k| stream.getrandbits(k).to_string())
        .collect();
    assert_eq!(
        bits,
        [
            "0",
            "1",
            "6",
            "81",
            "446",
            "172575020636962294798",
            "77743408459678220980176535679901288282840520006569338772017585170930200148335",
            "14730684032877290092891753529201063728075777644644227797024266211937316800121662480591421473661911585828253511015220179513805041628480657179834394908531544",
        ]
    );
    let below: Vec<String> = [1u64, 10]
        .into_iter()
        .map(BigUint::from)
        .chain([BigUint::from(2u32).pow(80) + 1u32])
        .map(|upper| stream.randbelow(&upper).to_string())
        .collect();
    assert_eq!(below, ["0", "3", "190777804437847548588612"]);
    assert_eq!(stream.random(), 0.914674176037491);
    assert_eq!(Stream::new("x").random(), 0.18259175789971782);
}

#[test]
fn the_seed_material_formats_the_context_and_salt_like_python() {
    let node = "chain_id=xian-local|block_num=17|block_hash=abc|input_hash=f00d";
    for (salt, material) in [
        (VmValue::None, node.to_owned()),
        (VmValue::Bool(true), format!("{node}|aux_salt=True")),
        (int(-7), format!("{node}|aux_salt=-7")),
    ] {
        let mut random = node_context();
        ok(&mut random, "random.seed", &[salt]);
        assert_eq!(
            ok(&mut random, "random.getrandbits", &[int(32)]),
            draw(&material)
        );
    }
    // Python's `or` defaults replace falsy context values; a salt only when None.
    let mut empty = context(VmValue::None, int(0), text(""), VmValue::None);
    for (salt, material) in [
        (
            VmValue::Bool(false),
            "chain_id=|block_num=0|block_hash=0|input_hash=0|aux_salt=False",
        ),
        (
            text(""),
            "chain_id=|block_num=0|block_hash=0|input_hash=0|aux_salt=",
        ),
    ] {
        call(
            &mut empty,
            "random.seed",
            vec![],
            vec![("aux_salt".to_owned(), salt)],
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            ok(&mut empty, "random.getrandbits", &[int(32)]),
            draw(material)
        );
    }
    let mut odd = context(text(""), VmValue::Bool(true), VmValue::Bool(false), int(0));
    ok(&mut odd, "random.seed", &[]);
    assert_eq!(
        ok(&mut odd, "random.getrandbits", &[int(32)]),
        draw("chain_id=|block_num=True|block_hash=0|input_hash=0")
    );
}

#[test]
fn the_draws_follow_the_python_functions() {
    let mut random = node_context();
    ok(&mut random, "random.seed", &[]);
    assert_eq!(
        ok(
            &mut random,
            "random.shuffle",
            &[list(&[0, 1, 2, 3, 4, 5, 6, 7])]
        ),
        list(&[2, 4, 3, 0, 1, 6, 7, 5])
    );
    assert_eq!(
        ok(&mut random, "random.choice", &[text("héllo")]),
        text("o")
    );
    assert_eq!(
        ok(
            &mut random,
            "random.choice",
            &[VmValue::Bytes(vec![1, 2, 255])]
        ),
        int(255)
    );
    assert_eq!(
        ok(&mut random, "random.choice", &[list(&[5, 6, 7])]),
        int(5)
    );
    assert_eq!(
        ok(&mut random, "random.choices", &[text("ab"), int(5)]),
        VmValue::List(vec![text("b"); 5])
    );
    assert_eq!(
        ok(
            &mut random,
            "random.choices",
            &[list(&[0, 1, 2]), VmValue::Bool(true)]
        ),
        list(&[0])
    );
    let bound = BigInt::from(2).pow(511);
    assert_eq!(
        ok(&mut random, "random.randint", &[VmValue::Int(-bound.clone()), VmValue::Int(bound)]),
        big("-2437974436227297337061274857159745248456715607240753729077715378914372755109803099637837764889133063186150855290889674057921951167075910836386869878861889")
    );
    assert_eq!(ok(&mut random, "random.randint", &[int(3), int(3)]), int(3));
    assert_eq!(
        ok(
            &mut random,
            "random.randint",
            &[VmValue::Bool(false), VmValue::Bool(true)]
        ),
        int(0)
    );
    assert_eq!(
        ok(&mut random, "random.randrange", &[VmValue::Bool(true)]),
        int(0)
    );
    assert_eq!(
        ok(
            &mut random,
            "random.randrange",
            &[big("1000000000000000000000000000000")]
        ),
        big("636690585820578705229346133968")
    );
    assert_eq!(
        ok(&mut random, "random.getrandbits", &[VmValue::Bool(true)]),
        int(1)
    );
    assert_eq!(
        ok(&mut random, "random.getrandbits", &[VmValue::Bool(false)]),
        int(0)
    );
}

#[test]
fn errors_are_pythons_in_pythons_order() {
    let mut random = node_context();
    let unseeded = |name: &str| {
        (
            "AssertionError: Random state not seeded. Call seed().".to_owned(),
            "AssertionError".to_owned(),
            vec![text(name)],
        )
    };
    let message = "Random state not seeded. Call seed().";
    assert_eq!(
        raised_by(&mut random, "random.getrandbits", &[int(-1)]),
        unseeded(message)
    );
    assert_eq!(
        raised_by(&mut random, "random.shuffle", &[list(&[])]),
        unseeded(message)
    );
    assert_eq!(
        raised_by(&mut random, "random.random", &[]),
        unseeded(message)
    );
    assert_eq!(
        raised_by(&mut random, "random.randint", &[int(1), int(5)]),
        unseeded(message)
    );
    assert_eq!(
        raised_by(&mut random, "random.choice", &[list(&[1])]),
        unseeded(message)
    );
    // Checks that come before the state's.
    let value_error = |text_: &str| {
        (
            format!("ValueError: {text_}"),
            "ValueError".to_owned(),
            vec![text(text_)],
        )
    };
    assert_eq!(
        raised_by(&mut random, "random.randint", &[int(5), int(1)]),
        value_error("empty range for randint()")
    );
    assert_eq!(
        raised_by(&mut random, "random.choices", &[list(&[1]), int(-1)]),
        value_error("number of choices must be non-negative")
    );
    assert_eq!(
        raised_by(&mut random, "random.choice", &[text("")]),
        (
            "IndexError: Cannot choose from an empty sequence".to_owned(),
            "IndexError".to_owned(),
            vec![text("Cannot choose from an empty sequence")]
        )
    );
    assert_eq!(
        ok(&mut random, "random.choices", &[list(&[]), int(0)]),
        VmValue::List(vec![])
    );
    // Checks after it.
    ok(&mut random, "random.seed", &[]);
    assert_eq!(
        raised_by(&mut random, "random.getrandbits", &[int(-1)]),
        value_error("number of bits must be non-negative")
    );
    assert_eq!(
        raised_by(&mut random, "random.randrange", &[int(0)]),
        value_error("upper bound must be positive")
    );
    assert_eq!(
        raised_by(
            &mut random,
            "random.choices",
            &[VmValue::Bytes(vec![]), int(2)]
        )
        .1,
        "IndexError"
    );
}

#[test]
fn random_floats_fail_after_their_draw_and_large_draws_before_any() {
    let _scope = Scope::enter(XIAN_VM_V2_PROFILE);
    let mut random = node_context();
    ok(&mut random, "random.seed", &[]);
    let refused = |served: Served| match served {
        Err(error) if error.exception().is_none() => error.to_string(),
        other => panic!("not refused: {other:?}"),
    };
    assert_eq!(
        refused(run(&mut random, "random.random", &[])),
        "binary float and raw Decimal are unavailable in xian_vm_v2"
    );
    assert_eq!(
        refused(run(&mut random, "random.getrandbits", &[int(600)])),
        "integer exceeds the 512-bit magnitude limit"
    );
    assert_eq!(
        refused(run(
            &mut random,
            "random.choices",
            &[list(&[1]), int(1 << 40)]
        )),
        "random.choices() exceeds the maximum allowed allocation size"
    );
    // random() drew 7 bytes; the refused calls drew nothing.
    let mut stream = Stream::new("chain_id=xian-local|block_num=17|block_hash=abc|input_hash=f00d");
    stream.getrandbits(53 + 3);
    assert_eq!(
        ok(&mut random, "random.getrandbits", &[int(64)]),
        VmValue::Int(stream.getrandbits(64).into())
    );
}

#[test]
fn calls_python_binds_differently_fail_with_a_type_error() {
    let mut random = node_context();
    let decimal = VmValue::Decimal(crate::VmDecimal::from_str_literal("1.5").unwrap());
    // Salts other than str, int, bool or None are refused (random_bounds).
    for salt in [decimal.clone(), list(&[1])] {
        let (text_, name, _) = raised_or_refused(&mut random, "random.seed", &[salt]);
        assert_eq!(
            (text_.as_str(), name),
            ("random.seed() salt must be a str, int or None", None)
        );
    }
    let mut odd = context(decimal.clone(), int(1), text("h"), text("x"));
    assert_eq!(
        type_error(&mut odd, "random.seed", &[], &[]),
        "random seed chain_id cannot be a decimal"
    );
    ok(&mut random, "random.seed", &[]);
    for (syscall, args, kwargs) in [
        ("random.seed", vec![int(1), int(2)], vec![]),
        (
            "random.seed",
            vec![int(1)],
            vec![("aux_salt".to_owned(), int(2))],
        ),
        (
            "random.getrandbits",
            vec![],
            vec![("bits".to_owned(), int(2))],
        ),
        ("random.randint", vec![int(1)], vec![]),
        (
            "random.shuffle",
            vec![],
            vec![("items".to_owned(), list(&[1]))],
        ),
    ] {
        assert!(
            type_error(&mut random, syscall, &args, &kwargs)
                .starts_with(&format!("{syscall}() takes the parameters (")),
            "{syscall}"
        );
    }
    assert_eq!(
        type_error(&mut random, "random.getrandbits", &[decimal], &[]),
        "random argument cannot be a decimal"
    );
    assert_eq!(
        raised_or_refused(&mut random, "random.choice", &[VmValue::Dict(vec![])]).0,
        "random.choice() population must be a list, tuple, str, bytes or bytearray"
    );
    assert_eq!(
        type_error(
            &mut random,
            "random.choice",
            &[VmValue::List(vec![text("a")])],
            &[]
        ),
        "random population item cannot be a str"
    );
    // Served by name, bound like Python binds them.
    let kwargs = [("b".to_owned(), int(2)), ("a".to_owned(), int(2))];
    assert_eq!(
        call(&mut random, "random.randint", vec![], kwargs.to_vec())
            .unwrap()
            .unwrap(),
        int(2)
    );
    assert!(call(&mut random, "random.missing", vec![], vec![]).is_none());
    assert!(call(&mut random, "zk.is_available", vec![], vec![]).is_none());
}

#[test]
fn word_sized_index_draws_are_randbelow() {
    for len in [
        1usize,
        2,
        3,
        7,
        8,
        9,
        255,
        256,
        257,
        1000,
        (1 << 32) + 5,
        usize::MAX,
    ] {
        let (mut words, mut big) = (Stream::new("idx"), Stream::new("idx"));
        for _ in 0..50 {
            let expected = big.randbelow(&BigUint::from(len));
            assert_eq!(BigUint::from(words.index_below(len)), expected, "len {len}");
        }
    }
}
