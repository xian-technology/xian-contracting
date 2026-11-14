//! The block host's zk syscalls against the texts and results of the Python
//! zk bridge (the contracting fuzz test compares the two call by call).
use super::super::{BlockHost, HostCharges, Modules, TxInputs};
use super::call;
use crate::state_view::tests::Fixture;
use crate::stored_value_encoder::encode_stored_value;
use crate::{VmBudget, VmContractHandle, VmValue};
use xian_zk::build_demo_vector;

fn text(value: &str) -> VmValue {
    VmValue::String(value.to_owned())
}

fn texts(values: &[String]) -> VmValue {
    VmValue::List(values.iter().map(|value| text(value)).collect())
}

fn field(byte: u8) -> String {
    format!("0x{}", format!("{byte:02x}").repeat(32))
}

/// A view whose LMDB holds `stored`.
fn fixture(name: &str, stored: &[(String, VmValue)]) -> Fixture {
    let encoded: Vec<(String, Vec<u8>)> = stored
        .iter()
        .map(|(key, value)| (key.clone(), encode_stored_value(value).unwrap()))
        .collect();
    let borrowed: Vec<(&str, &[u8])> = encoded
        .iter()
        .map(|(key, value)| (key.as_str(), &value[..]))
        .collect();
    Fixture::new(&format!("zk-{name}"), &borrowed, &[])
}

/// The registry entry of an active Groth16 BN254 key `vk_id`.
fn registered(vk_id: &str, vk_hex: &str, vk_hash: &str) -> Vec<(String, VmValue)> {
    [
        ("vk_hex", text(vk_hex)),
        ("scheme", text("groth16")),
        ("curve", text("bn254")),
        ("vk_hash", text(vk_hash)),
        ("active", VmValue::Bool(true)),
        ("circuit_name", text("demo")),
        ("tree_depth", VmValue::Int(20.into())),
    ]
    .into_iter()
    .map(|(field, value)| (format!("zk_registry.verifying_keys:{vk_id}:{field}"), value))
    .collect()
}

fn host<'a>(fixture: &Fixture, modules: &'a Modules) -> BlockHost<'a> {
    BlockHost::new(
        fixture.view.clone(),
        modules,
        HostCharges::new(
            VmBudget::new(10_000_000, crate::XIAN_VM_V2_PROFILE),
            true,
            "con_zk",
        ),
        TxInputs {
            context: Default::default(),
            zk_enabled_without_state: true,
        },
    )
}

fn zk(host: &mut BlockHost<'_>, name: &str, args: &[VmValue]) -> Result<VmValue, String> {
    call(host, &format!("zk.{name}"), args, &[])
        .expect("a zk syscall")
        .map_err(|error| error.to_string())
}

#[test]
fn registered_keys_verify_from_chain_state_not_the_transactions_writes() {
    let demo = build_demo_vector().unwrap();
    let fixture = fixture("registered", &registered("demo", &demo.vk_hex, "h1"));
    let modules = Modules::default();
    let mut host = host(&fixture, &modules);
    let inputs = texts(&demo.public_inputs);
    let args = [text("demo"), text(&demo.proof_hex), inputs.clone()];
    assert_eq!(
        zk(&mut host, "verify_groth16", &args),
        Ok(VmValue::Bool(true))
    );
    let wrong = [text("demo"), text(&demo.proof_hex), texts(&[field(5)])];
    assert_eq!(
        zk(&mut host, "verify_groth16", &wrong),
        Ok(VmValue::Bool(false))
    );
    assert_eq!(
        zk(&mut host, "has_verifying_key", &[text("demo")]),
        Ok(VmValue::Bool(true))
    );
    // A key the transaction's own host writes register is not registered.
    let key = "zk_registry.verifying_keys:fresh:vk_hex";
    host.writes.stage(key, text(&demo.vk_hex));
    assert_eq!(
        zk(
            &mut host,
            "verify_groth16",
            &[text("fresh"), text(&demo.proof_hex), inputs]
        ),
        Err("AssertionError: Unknown verifying key id 'fresh'!".to_owned())
    );
    assert_eq!(
        zk(&mut host, "has_verifying_key", &[text("fresh")]),
        Ok(VmValue::Bool(false))
    );
    assert!(host.stop.is_none());
}

#[test]
fn registry_entries_are_checked_in_the_python_order() {
    let mut stored = registered("demo", "0x12", "h");
    stored.extend(registered("nohash", "0x12", ""));
    stored.extend(registered("badhex", "0x1", "h"));
    stored.push((
        "zk_registry.verifying_keys:off:vk_hex".to_owned(),
        text("0x12"),
    ));
    stored.extend(
        registered("old", "0x12", "h")
            .into_iter()
            .map(|(key, value)| match key.ends_with(":active") {
                true => (key, VmValue::Int(1.into())),
                false => (key, value),
            }),
    );
    let fixture = fixture("checks", &stored);
    let modules = Modules::default();
    let mut host = host(&fixture, &modules);
    let proof = [text("0xab"), VmValue::List(vec![])];
    for (vk_id, expected) in [
        (
            "off",
            "AssertionError: Verifying key 'off' must use Groth16!",
        ),
        ("old", "AssertionError: Verifying key 'old' is inactive!"),
        (
            "nohash",
            "AssertionError: Verifying key 'nohash' is missing vk_hash!",
        ),
        (
            "badhex",
            "AssertionError: registered vk_hex must contain whole bytes of hex!",
        ),
        ("demo", "AssertionError: invalid verifying key bytes: "),
    ] {
        let args = [text(vk_id), proof[0].clone(), proof[1].clone()];
        let refused = zk(&mut host, "verify_groth16", &args).unwrap_err();
        assert!(refused.starts_with(expected), "{vk_id}: {refused}");
        let known = zk(&mut host, "has_verifying_key", &[text(vk_id)]);
        assert_eq!(known, Ok(VmValue::Bool(vk_id == "demo")), "{vk_id}");
    }
    let info = zk(&mut host, "get_vk_info", &[text("demo")]).unwrap();
    let VmValue::Dict(entries) = info else {
        panic!("{info:?}")
    };
    assert_eq!(entries.len(), 25);
    assert_eq!(entries[0], (text("vk_id"), text("demo")));
    assert_eq!(entries[12], (text("tree_depth"), VmValue::Int(20.into())));
    assert_eq!(entries[21], (text("deprecated"), VmValue::Bool(false)));
    assert_eq!(
        zk(&mut host, "get_vk_info", &[text("nope")]),
        Ok(VmValue::None)
    );
}

#[test]
fn arguments_are_checked_with_the_python_texts() {
    let fixture = fixture("arguments", &[]);
    let modules = Modules::default();
    let mut host = host(&fixture, &modules);
    let handle = VmValue::ContractHandle(VmContractHandle {
        module: "0xzz".to_owned(),
        origin: "static_import".to_owned(),
    });
    let inputs = texts(&[field(1)]);
    for (args, expected) in [
        (
            vec![VmValue::Int(1.into()), text("0x00"), inputs.clone()],
            "vk_hex must be a string!",
        ),
        (
            vec![text("12"), text("0x00"), inputs.clone()],
            "vk_hex must be 0x-prefixed hex!",
        ),
        (
            vec![text("0x"), text("0x00"), inputs.clone()],
            "vk_hex must not be empty!",
        ),
        (
            vec![text("0x0é"), text("0x00"), inputs.clone()],
            "vk_hex must be valid hex!",
        ),
        (
            vec![text("0x0"), text("0x00"), inputs.clone()],
            "vk_hex must contain whole bytes of hex!",
        ),
        (
            vec![handle, text("0x00"), inputs.clone()],
            "vk_hex must be valid hex!",
        ),
        (
            vec![
                text("0x00"),
                text(&format!("0x{}", "0".repeat(4096))),
                inputs.clone(),
            ],
            "proof_hex exceeds the maximum size!",
        ),
        (
            vec![text("0x00"), text("0x00"), VmValue::Tuple(vec![])],
            "public_inputs must be a list!",
        ),
        (
            vec![text("0x00"), text("0x00"), texts(&vec![field(1); 33])],
            "Too many public inputs for zk verification!",
        ),
        (
            vec![text("0x00"), text("0x00"), texts(&["0x00".to_owned()])],
            "public_inputs[0] must be exactly 32 bytes!",
        ),
    ] {
        assert_eq!(
            zk(&mut host, "verify_groth16_bn254", &args),
            Err(format!("AssertionError: {expected}"))
        );
    }
    for (vk_id, expected) in [
        (VmValue::None, "vk_id must be a string!"),
        (text(""), "vk_id must not be empty!"),
        (text(&"é".repeat(129)), "vk_id exceeds the maximum size!"),
    ] {
        assert_eq!(
            zk(&mut host, "get_vk_info", &[vk_id]),
            Err(format!("AssertionError: {expected}"))
        );
    }
    // 128 characters of four bytes each: a key LMDB cannot hold reads as missing.
    assert_eq!(
        zk(&mut host, "get_vk_info", &[text(&"😀".repeat(128))]),
        Ok(VmValue::None)
    );
    assert!(host.stop.is_none());
}

#[test]
fn arguments_the_zk_functions_do_not_take_fail_with_a_type_error() {
    let fixture = fixture("handback", &[]);
    let modules = Modules::default();
    let mut host = host(&fixture, &modules);
    let refused = call(
        &mut host,
        "zk.has_verifying_key",
        &[VmValue::BuiltinSet(vec![])],
        &[],
    );
    assert_eq!(
        refused.unwrap().unwrap_err().to_string(),
        "TypeError: zk.has_verifying_key() cannot take a set argument"
    );
    let shape = call(&mut host, "zk.has_verifying_key", &[], &[]);
    assert_eq!(
        shape.unwrap().unwrap_err().to_string(),
        "TypeError: zk.has_verifying_key() takes exactly 1 positional arguments"
    );
    assert!(host.stop.is_none());
    assert!(call(&mut host, "zk.unknown", &[], &[]).is_none());
}

#[test]
fn shielded_helpers_check_their_arguments_then_refuse_like_the_binding() {
    let fixture = fixture("shielded", &[]);
    let modules = Modules::default();
    let mut host = host(&fixture, &modules);
    let zero = text(&field(0));
    let one = text(&field(1));
    let mut binding = vec![one.clone(); 8];
    binding.extend([VmValue::Int((1u128 << 64).into()), VmValue::Int(0.into())]);
    assert_eq!(
        zk(&mut host, "shielded_command_binding", &binding),
        Err("OverflowError: int too big to convert".to_owned())
    );
    binding[8] = VmValue::Int((-1).into());
    assert_eq!(
        zk(&mut host, "shielded_command_binding", &binding),
        Err("AssertionError: fee must be a non-negative integer!".to_owned())
    );
    binding[8] = VmValue::Bool(true);
    assert!(zk(&mut host, "shielded_command_binding", &binding).is_ok());
    let append = [
        VmValue::Int(0.into()),
        texts(&[field(0), field(0)]),
        VmValue::List(vec![one.clone()]),
    ];
    assert_eq!(
        zk(&mut host, "shielded_note_append_commitments", &append),
        Err("ValueError: filled_subtrees length does not match tree depth".to_owned())
    );
    assert_eq!(
        zk(&mut host, "shielded_output_payload_hash", &[text("")]),
        Ok(zero.clone())
    );
    assert_eq!(
        zk(
            &mut host,
            "shielded_output_payload_hashes",
            &[VmValue::List(vec![VmValue::None, text("")])]
        ),
        Ok(VmValue::List(vec![zero.clone(), zero.clone()]))
    );
    let deposit = [
        text("con_x"),
        text("0x00"),
        VmValue::Int(5.into()),
        VmValue::List(vec![one.clone()]),
        VmValue::List(vec![]),
    ];
    assert_eq!(
        zk(&mut host, "shielded_deposit_public_inputs", &deposit),
        Err("AssertionError: payload_hashes has invalid length!".to_owned())
    );
    let mut deposit = [
        text("con_x"),
        text("0x00"),
        VmValue::Int(5.into()),
        VmValue::List(vec![one.clone()]),
        VmValue::List(vec![zero.clone()]),
    ];
    assert_eq!(
        zk(&mut host, "shielded_deposit_public_inputs", &deposit),
        Err("ValueError: field values must be 32 bytes".to_owned())
    );
    deposit[1] = zero;
    let VmValue::List(inputs) = zk(&mut host, "shielded_deposit_public_inputs", &deposit).unwrap()
    else {
        panic!("public inputs")
    };
    assert!(!inputs.is_empty());
}

#[test]
fn warming_verifies_what_is_not_cached_and_feeds_verification() {
    let demo = build_demo_vector().unwrap();
    let fixture = fixture("warm", &registered("warm", &demo.vk_hex, "hash-warm"));
    let modules = Modules::default();
    let mut host = host(&fixture, &modules);
    let request = |proof: &str| {
        VmValue::Dict(vec![
            (text("vk_id"), text("warm")),
            (text("proof_hex"), text(proof)),
            (text("public_inputs"), texts(&demo.public_inputs)),
        ])
    };
    let requests = VmValue::List(vec![request(&demo.proof_hex)]);
    assert_eq!(
        zk(&mut host, "warm_verified_proofs", &[requests]),
        Ok(VmValue::List(vec![VmValue::Bool(true)]))
    );
    let malformed = VmValue::List(vec![request("0x00")]);
    let refused = zk(&mut host, "warm_verified_proofs", &[malformed]).unwrap_err();
    assert!(
        refused.starts_with("AssertionError: invalid proof bytes"),
        "{refused}"
    );
    assert_eq!(
        zk(
            &mut host,
            "warm_verified_proofs",
            &[VmValue::List(vec![text("x")])]
        ),
        Err("AssertionError: requests[0] must be a dict!".to_owned())
    );
}
