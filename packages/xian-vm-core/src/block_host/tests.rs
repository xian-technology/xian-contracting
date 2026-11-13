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
        &VmExecutionContext::default(),
    )
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
        &VmExecutionContext::default(),
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
        &VmExecutionContext::default(),
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
