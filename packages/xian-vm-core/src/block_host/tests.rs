//! A block host's reads see what its transaction's host syscalls staged.
use super::*;
use crate::state_view::tests::{encoded, Fixture};
use crate::VmBudget;

fn int(value: i64) -> VmValue {
    VmValue::Int(value.into())
}

/// A view holding `stored` in LMDB and `pending` in the overlay.
fn fixture(name: &str, stored: &[(&str, &str)], pending: &[(&str, Option<&str>)]) -> Fixture {
    let stored: Vec<(&str, Vec<u8>)> = stored
        .iter()
        .map(|(key, value)| (*key, encoded(value).to_vec()))
        .collect();
    let stored: Vec<(&str, &[u8])> = stored
        .iter()
        .map(|(key, value)| (*key, &value[..]))
        .collect();
    Fixture::new(&format!("block-host-{name}"), &stored, pending)
}

/// A host over `fixture` for a metered transaction to `submission`.
fn host<'a>(fixture: &Fixture, modules: &'a Modules) -> BlockHost<'a> {
    BlockHost::new(
        fixture.view.clone(),
        modules,
        HostCharges::new(budget(10_000_000), true, "submission"),
        inputs(),
    )
}

/// A transaction context with a block time and the zk feature on.
fn inputs() -> TxInputs {
    TxInputs {
        context: crate::VmExecutionContext {
            caller: Some("alice".to_owned()),
            signer: Some("alice".to_owned()),
            now: VmValue::Int(7.into()),
            ..Default::default()
        },
        zk_enabled_without_state: true,
    }
}

fn budget(raw: u64) -> VmBudget {
    VmBudget::new(raw, crate::XIAN_VM_V2_PROFILE)
}

fn scan(host: &mut BlockHost<'_>, prefix: &str) -> Vec<(String, VmValue)> {
    let mut seen = Vec::new();
    host.visit_prefix(prefix, &mut |key, value| {
        seen.push((key, value));
        true
    })
    .unwrap();
    seen
}

#[test]
fn reads_see_staged_writes_before_the_overlay_and_lmdb() {
    let fixture = fixture(
        "get",
        &[("c.stored", "lmdb"), ("c.both", "lmdb")],
        &[("c.both", Some("overlay")), ("c.gone", Some("overlay"))],
    );
    let modules = Modules::default();
    let mut host = host(&fixture, &modules);
    host.writes.stage("c.both", int(1));
    host.writes.stage("c.gone", VmValue::None);
    host.writes.stage("c.new", int(2));
    assert_eq!(host.get("c.stored").unwrap(), Some(text("lmdb")));
    assert_eq!(host.get("c.both").unwrap(), Some(int(1)));
    assert_eq!(host.get("c.gone").unwrap(), None);
    assert_eq!(host.get("c.new").unwrap(), Some(int(2)));
    assert!(host.stop.is_none());
}

#[test]
fn scans_merge_staged_entries_into_the_overlay_and_lmdb() {
    let fixture = fixture(
        "scan",
        &[("c.h:a", "lmdb"), ("c.h:c", "lmdb"), ("c.h:e", "lmdb")],
        &[("c.h:b", Some("overlay")), ("c.h:c", None)],
    );
    let modules = Modules::default();
    let mut host = host(&fixture, &modules);
    host.writes.stage("c.h:a", int(1));
    host.writes.stage("c.h:d", int(4));
    host.writes.stage("c.h:e", VmValue::None);
    assert_eq!(
        scan(&mut host, "c.h:"),
        vec![
            ("c.h:a".to_owned(), int(1)),
            ("c.h:b".to_owned(), text("overlay")),
            ("c.h:d".to_owned(), int(4)),
        ]
    );
}

#[test]
fn a_staged_ir_text_is_the_contracts_module_and_nothing_else_is() {
    let fixture = fixture("ir", &[("con_a.__xian_ir_v1__", "stored ir")], &[]);
    let modules = Modules::default();
    let mut host = host(&fixture, &modules);
    let module_text = |host: &mut BlockHost<'_>, name: &str| match host.ir(name).unwrap() {
        Ir::Text(module) => Some(module.text.clone()),
        _ => None,
    };
    host.writes.stage("con_b.__xian_ir_v1__", text("staged ir"));
    assert_eq!(
        module_text(&mut host, "con_b"),
        Some("staged ir".to_owned())
    );
    // Like `load_module_ir_json`, a staged value that is not IR text leaves
    // the stored IR in place.
    host.writes.stage("con_a.__xian_ir_v1__", text(""));
    assert_eq!(
        module_text(&mut host, "con_a"),
        Some("stored ir".to_owned())
    );
    // The staged module never enters the run's shared cache.
    let mut fresh = self::host(&fixture, &modules);
    assert_eq!(module_text(&mut fresh, "con_b"), None);
}

#[test]
fn the_staged_writes_leave_with_the_transaction() {
    let fixture = fixture("take", &[], &[]);
    let modules = Modules::default();
    let mut host = host(&fixture, &modules);
    host.writes.stage("c.k", int(1));
    let mut writes = std::collections::BTreeMap::new();
    let (staged, _) = host.finish().unwrap();
    staged.settle(0, &mut writes, &mut Vec::new());
    assert_eq!(writes.get("c.k"), Some(&int(1)));
    let mut next = self::host(&fixture, &modules);
    assert_eq!(next.get("c.k").unwrap(), None);
}

/// `NativeVmHost.handle_syscall` for a contract metadata change.
fn change(host: &mut BlockHost<'_>, syscall: &str, args: &[VmValue]) -> Option<VmValue> {
    metadata::change(host, syscall, args, &[]).map(|result| result.unwrap())
}

#[test]
fn metadata_changes_stage_the_value_and_charge_its_encoded_bytes_to_the_entry() {
    let fixture = fixture("set-owner", &[("con_x.__owner__", "alice")], &[]);
    let modules = Modules::default();
    let mut host = host(&fixture, &modules);
    let owner = change(
        &mut host,
        "contract.set_owner",
        &[text("con_x"), text("bob")],
    );
    let developer = change(
        &mut host,
        "contract.set_developer",
        &[text("con_x"), text("dev2")],
    );
    assert_eq!(
        (owner, developer),
        (Some(VmValue::None), Some(VmValue::None))
    );
    assert_eq!(host.get("con_x.__owner__").unwrap(), Some(text("bob")));
    assert_eq!(host.get("con_x.__developer__").unwrap(), Some(text("dev2")));
    // (encoded key + encoded value) * 25: ("con_x.__owner__" + "\"bob\"")
    // and ("con_x.__developer__" + "\"dev2\""), no write cap.
    let charged = (15 + 5) * 25 + (19 + 6) * 25;
    let (_, charges) = host.finish().unwrap();
    assert_eq!(charges.raw_cost(), charged);
    let mut costs = std::collections::HashMap::from([("submission".to_owned(), 7)]);
    charges.add_contract_costs(&mut costs);
    assert_eq!(costs["submission"], 7 + charged);
}

#[test]
fn a_metadata_change_past_the_budget_fails_as_the_python_host_reports_it() {
    let fixture = fixture("set-owner-budget", &[], &[]);
    let modules = Modules::default();
    let shared = budget(400);
    let mut host = BlockHost::new(
        fixture.view.clone(),
        &modules,
        HostCharges::new(shared.clone(), true, "con_entry"),
        inputs(),
    );
    let refused = metadata::change(
        &mut host,
        "contract.set_owner",
        &[text("con_x"), text("bob")],
        &[],
    )
    .unwrap()
    .unwrap_err();
    assert_eq!(refused.to_string(), "VmRuntimeExecutionError: Out of chi.");
    // Staged before the charge; the failed transaction drops it.
    assert_eq!(host.get("con_x.__owner__").unwrap(), Some(text("bob")));
    assert_eq!(host.finish().unwrap().1.raw_cost(), 500);
    // The shared budget took the charge.
    assert!(shared.charge(0).is_err());
}

#[test]
fn unmetered_metadata_changes_are_free() {
    let fixture = fixture("set-owner-free", &[], &[]);
    let modules = Modules::default();
    let mut host = BlockHost::new(
        fixture.view.clone(),
        &modules,
        HostCharges::new(budget(1), false, "submission"),
        inputs(),
    );
    change(&mut host, "contract.set_owner", &[text("con_x"), int(5)]);
    assert_eq!(host.get("con_x.__owner__").unwrap(), Some(int(5)));
    assert_eq!(host.finish().unwrap().1.raw_cost(), 0);
}

#[test]
fn metadata_changes_the_python_host_serves_otherwise_are_handed_back() {
    let fixture = fixture("set-owner-back", &[], &[]);
    let modules = Modules::default();
    let mut host = host(&fixture, &modules);
    // Not a contract name string: `make_key` would raise.
    let handle = VmValue::ContractHandle(crate::VmContractHandle {
        module: "con_x".to_owned(),
        origin: "dynamic_import".to_owned(),
    });
    assert!(
        metadata::change(&mut host, "contract.set_owner", &[handle, text("bob")], &[])
            .unwrap()
            .is_err()
    );
    assert!(matches!(host.stop.take(), Some(Stop::Handback(_))));
    // Any other shape is not served here.
    assert!(change(&mut host, "contract.set_owner", &[text("con_x")]).is_none());
    assert!(metadata::change(
        &mut host,
        "contract.set_owner",
        &[text("con_x"), text("bob")],
        &[("extra".to_owned(), int(1))]
    )
    .is_none());
    assert!(change(&mut host, "contract.owner_of", &[text("con_x")]).is_none());
    assert_eq!(host.get("con_x.__owner__").unwrap(), None);
}

const EVENTS: &str = "v = Variable()
Built = LogEvent(\"Built\", {\"by\": indexed(str), \"start\": int})

@construct
def seed(start: int):
    assert start > 0, \"bad start\"
    v.set(start)
    Built({\"by\": ctx.caller, \"start\": start})

@export
def get():
    return v.get()
";

/// `contract.deploy` as `submission.submit_contract` calls it.
fn deployment(name: &str, code: &str, start: Option<i64>) -> Vec<(String, VmValue)> {
    let arguments = start.map_or(VmValue::None, |start| {
        VmValue::Dict(vec![(text("start"), int(start))])
    });
    vec![
        ("name".to_owned(), text(name)),
        ("code".to_owned(), text(code)),
        ("owner".to_owned(), VmValue::None),
        ("constructor_args".to_owned(), arguments),
        ("developer".to_owned(), text("dev")),
        ("deployer".to_owned(), VmValue::None),
        ("initiator".to_owned(), VmValue::None),
    ]
}

fn deploy(host: &mut BlockHost<'_>, kwargs: &[(String, VmValue)]) -> Result<VmValue, String> {
    deploy::deploy(host, "contract.deploy", &[], kwargs)
        .expect("contract.deploy is served here")
        .map_err(|error| error.to_string())
}

#[test]
fn a_deployment_runs_the_constructor_and_stages_its_effects_and_metadata() {
    let fixture = fixture("deploy", &[], &[]);
    let modules = Modules::default();
    let mut host = host(&fixture, &modules);
    assert_eq!(
        deploy(&mut host, &deployment("con_new", EVENTS, Some(5))),
        Ok(VmValue::None)
    );
    assert_eq!(host.get("con_new.v").unwrap(), Some(int(5)));
    assert_eq!(host.get("con_new.__owner__").unwrap(), None);
    assert_eq!(
        host.get("con_new.__developer__").unwrap(),
        Some(text("dev"))
    );
    assert_eq!(
        host.get("con_new.__deployer__").unwrap(),
        Some(text("alice"))
    );
    assert_eq!(
        host.get("con_new.__initiator__").unwrap(),
        Some(text("alice"))
    );
    assert_eq!(host.get("con_new.__submitted__").unwrap(), Some(int(7)));
    let Some(VmValue::String(source)) = host.get("con_new.__source__").unwrap() else {
        panic!("the normalized source is staged");
    };
    assert!(matches!(host.ir("con_new").unwrap(), Ir::Text(_)));
    assert!(host.constructing.is_empty());
    // A second deployment of the name finds the staged one.
    assert_eq!(
        deploy(&mut host, &deployment("con_new", EVENTS, Some(5))),
        Err("VmRuntimeExecutionError: Contract already exists.".to_owned())
    );
    let (staged, charges) = host.finish().unwrap();
    let mut events = Vec::new();
    staged.settle(0, &mut std::collections::BTreeMap::new(), &mut events);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "Built");
    assert_eq!(events[0].caller, text("alice"));
    // The constructor's work, the metadata writes and the deployment itself.
    assert!(charges.raw_cost() > 5_000 + source.len() as u64);
}

#[test]
fn a_failed_constructor_fails_the_deployment_with_its_exception() {
    let fixture = fixture("deploy-fails", &[], &[]);
    let modules = Modules::default();
    let mut host = host(&fixture, &modules);
    let refused = deploy::deploy(
        &mut host,
        "contract.deploy",
        &[],
        &deployment("con_new", EVENTS, Some(0)),
    )
    .unwrap()
    .unwrap_err();
    assert!(
        refused
            .to_string()
            .starts_with("VmRuntimeExecutionError: contract constructor failed: "),
        "{refused}"
    );
    let exception = refused.exception().expect("the constructor's exception");
    assert_eq!(
        (exception.name.as_str(), &exception.args[..]),
        ("AssertionError", &[text("bad start")][..])
    );
    assert!(host.constructing.is_empty());
    assert_eq!(host.get("con_new.__xian_ir_v1__").unwrap(), None);
    assert_eq!(host.get("con_new.v").unwrap(), None);
    // The constructor's work still counts.
    assert!(host.finish().unwrap().1.raw_cost() > 0);
}

#[test]
fn deployments_refuse_bad_names_existing_contracts_and_bad_source_like_python() {
    let fixture = fixture("deploy-refused", &[("con_old.__source__", "x = 1")], &[]);
    let modules = Modules::default();
    let mut host = host(&fixture, &modules);
    let refused = |host: &mut BlockHost<'_>, name: &str, code: &str| {
        deploy(host, &deployment(name, code, None)).unwrap_err()
    };
    let unsafe_name = "AssertionError: Contract name must start with a lowercase ASCII letter \
                       and contain only lowercase ASCII letters, digits, and underscores.";
    assert_eq!(refused(&mut host, "Bad", EVENTS), unsafe_name);
    assert_eq!(refused(&mut host, "con_é", EVENTS), unsafe_name);
    assert_eq!(
        refused(&mut host, "", EVENTS),
        "AssertionError: Contract name must be a non-empty string."
    );
    assert_eq!(
        refused(&mut host, &"c".repeat(65), EVENTS),
        "AssertionError: Contract name length exceeds 64 characters!"
    );
    assert_eq!(
        refused(&mut host, "con_old", EVENTS),
        "VmRuntimeExecutionError: Contract already exists."
    );
    assert_eq!(
        refused(&mut host, "con_new", ""),
        "VmRuntimeExecutionError: native contract deployment requires non-empty source code"
    );
    let syntax = refused(&mut host, "con_new", "def broken(:\n");
    assert!(syntax.starts_with("CompilerError: "), "{syntax}");
    assert!(syntax.contains("\n[{\"severity\":\"error\""), "{syntax}");
    assert!(host.stop.is_none());
}

#[test]
fn a_zk_contract_deploys_only_with_the_zk_feature_on() {
    let source = "@export\ndef get():\n    return zk.is_available()\n";
    let fixture = fixture("deploy-zk", &[], &[]);
    let modules = Modules::default();
    let mut host = host(&fixture, &modules);
    assert_eq!(
        deploy(&mut host, &deployment("con_zk", source, None)),
        Ok(VmValue::None)
    );
    let mut off = self::host(&fixture, &modules);
    off.tx.zk_enabled_without_state = false;
    assert_eq!(
        deploy(&mut off, &deployment("con_zk", source, None)),
        Err(
            "VmRuntimeExecutionError: contract 'con_zk' uses zk host syscalls, \
             but the chain zk runtime feature is disabled"
                .to_owned()
        )
    );
}

#[test]
fn constructor_arguments_the_wire_round_trip_would_change_are_handed_back() {
    let fixture = fixture("deploy-args", &[], &[]);
    let modules = Modules::default();
    for arguments in [
        VmValue::Dict(vec![(text("start"), VmValue::Tuple(vec![int(1)]))]),
        VmValue::Dict(vec![(
            text("start"),
            VmValue::Dict(vec![(text("__fixed__"), text("1"))]),
        )]),
        VmValue::Dict(vec![(int(1), int(1))]),
        VmValue::List(vec![]),
    ] {
        let mut host = host(&fixture, &modules);
        let mut kwargs = deployment("con_new", EVENTS, None);
        kwargs[3].1 = arguments;
        assert!(deploy(&mut host, &kwargs).is_err());
        assert!(matches!(host.stop, Some(Stop::Handback(_))));
    }
}

#[test]
fn the_zk_feature_reads_as_python_coerces_it() {
    use deploy::runtime_feature_value as value;
    for (input, expected) in [
        (VmValue::Bool(true), Some(Ok(true))),
        (text(" On\x1c"), Some(Ok(true))),
        (text("no"), Some(Ok(false))),
        (int(0), Some(Ok(false))),
        (int(1), Some(Ok(true))),
        (int(2), Some(Err(()))),
        (text("maybe"), Some(Err(()))),
        (text("\u{a0}true"), None),
    ] {
        assert_eq!(value(&input), expected, "{input:?}");
    }
}

#[test]
fn a_code_hash_charges_the_bytes_it_hashes_first() {
    let source = "x = 1\n".repeat(100);
    let fixture = fixture("code-hash", &[("con_x.__source__", &source)], &[]);
    let modules = Modules::default();
    let mut host = host(&fixture, &modules);
    let args = [text("con_x"), text("source")];
    let digest = metadata::read(&mut host, "contract.code_hash", &args, &[]).unwrap();
    assert!(matches!(digest.unwrap(), VmValue::String(hex) if hex.len() == 64));
    let missing = [text("con_none"), text("source")];
    assert_eq!(
        metadata::read(&mut host, "contract.code_hash", &missing, &[])
            .unwrap()
            .unwrap(),
        VmValue::None
    );
    assert_eq!(host.finish().unwrap().1.raw_cost(), source.len() as u64 * 4);
    // Out of budget: refused before hashing.
    let mut poor = BlockHost::new(
        fixture.view.clone(),
        &modules,
        HostCharges::new(budget(10), true, "con_entry"),
        inputs(),
    );
    let refused = metadata::read(&mut poor, "contract.code_hash", &args, &[]).unwrap();
    assert_eq!(
        refused.unwrap_err().to_string(),
        "VmRuntimeExecutionError: Out of chi."
    );
}
