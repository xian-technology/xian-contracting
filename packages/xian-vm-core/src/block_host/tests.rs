//! A block host's reads see what its transaction's host syscalls staged.
use super::*;
use crate::state_view::tests::{encoded, Fixture};

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
    let mut host = BlockHost::new(fixture.view.clone(), &modules);
    host.writes.stage("c.both", int(1));
    host.writes.stage("c.gone", VmValue::None);
    host.writes.stage("c.new", int(2));
    assert_eq!(host.get("c.stored").unwrap(), Some(text("lmdb")));
    assert_eq!(host.get("c.both").unwrap(), Some(int(1)));
    assert_eq!(host.get("c.gone").unwrap(), None);
    assert_eq!(host.get("c.new").unwrap(), Some(int(2)));
    assert!(host.take_stop().is_none());
}

#[test]
fn scans_merge_staged_entries_into_the_overlay_and_lmdb() {
    let fixture = fixture(
        "scan",
        &[("c.h:a", "lmdb"), ("c.h:c", "lmdb"), ("c.h:e", "lmdb")],
        &[("c.h:b", Some("overlay")), ("c.h:c", None)],
    );
    let modules = Modules::default();
    let mut host = BlockHost::new(fixture.view.clone(), &modules);
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
    let mut host = BlockHost::new(fixture.view.clone(), &modules);
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
    let mut fresh = BlockHost::new(fixture.view.clone(), &modules);
    assert_eq!(module_text(&mut fresh, "con_b"), None);
}

#[test]
fn the_staged_writes_leave_with_the_transaction() {
    let fixture = fixture("take", &[], &[]);
    let modules = Modules::default();
    let mut host = BlockHost::new(fixture.view.clone(), &modules);
    host.writes.stage("c.k", int(1));
    let mut writes = std::collections::BTreeMap::new();
    host.take_writes().settle(0, &mut writes, &mut Vec::new());
    assert_eq!(writes.get("c.k"), Some(&int(1)));
    assert_eq!(host.get("c.k").unwrap(), None);
}
