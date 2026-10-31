use xian_vm_core::{VmDateTime, VmTimeDelta};

#[test]
fn historical_duration_product_uses_normalized_components() {
    for (left, right, seconds) in [
        (172800, 259200, 518400),
        (86402, 172803, 172806),
        (-1, -1, 7464873601),
        (-172800, 259200, -518400),
        (0, 86399, 0),
    ] {
        let left = VmTimeDelta::from_raw_seconds(left).unwrap();
        let right = VmTimeDelta::from_raw_seconds(right).unwrap();
        assert_eq!(left.mul_timedelta(&right).unwrap().seconds(), seconds);
    }
    let largest = VmTimeDelta::from_raw_seconds(86_399_999_999_999).unwrap();
    assert!(largest.mul_timedelta(&largest).is_err());
    let smallest = VmTimeDelta::from_raw_seconds(-86_399_999_913_600).unwrap();
    let two_days = VmTimeDelta::new(0, 2, 0, 0, 0).unwrap();
    assert!(smallest.mul_timedelta(&two_days).is_err());
    assert!(smallest.mul_timedelta(&smallest).is_err());
}

#[test]
fn numeric_format_policy_and_adjacent_fields() {
    for (text, format, expected) in [
        ("246", "%H%M", "1900-01-01 02:46:00"),
        ("02\u{1c}03", "%m %d", "1900-02-03 00:00:00"),
        ("202601", "%Y%f", "2026-01-01 00:00:00.010000"),
        ("2024-W01-1", "%G-W%V-%u", "2024-01-01 00:00:00"),
        ("2026年02月03日 %", "%Y年%m月%d日 %%", "2026-02-03 00:00:00"),
    ] {
        assert_eq!(
            VmDateTime::parse(text, format).unwrap().to_string(),
            expected
        );
    }
    for (text, format) in [
        ("2026-02-03", "%F"),
        ("PM", "%p"),
        ("Feb", "%b"),
        ("UTC", "%Z"),
        ("+0000", "%z"),
        ("2026 2026", "%Y %Y"),
        ("2026 26", "%Y %y"),
        ("12 12", "%H %I"),
        ("03 03", "%U %W"),
        ("1 1", "%w %u"),
        ("2024-W01-1 2024", "%G-W%V-%u %Y"),
    ] {
        assert_eq!(
            VmDateTime::parse(text, format).unwrap_err().to_string(),
            "unsupported datetime format",
            "{format}"
        );
    }
    assert!(VmDateTime::parse("２０２６", "%Y").is_err());
}

#[test]
fn parser_work_is_bounded_before_execution() {
    assert_eq!(
        VmDateTime::parse_work_cost(&"x".repeat(31045), "%Y%m%d%H%M%S").unwrap(),
        1_000_000
    );
    assert!(VmDateTime::parse_work_cost(&"x".repeat(31046), "%Y%m%d%H%M%S").is_err());
    let format = "%Y%m%d%H%M%S%f%j%U%w";
    assert_eq!(
        VmDateTime::parse_work_cost(&"1".repeat(527), format).unwrap(),
        999936
    );
    assert!(VmDateTime::parse_work_cost(&"1".repeat(528), format).is_err());
    let literal = "x".repeat(5000);
    let text = format!("111111111111111111{literal}");
    let format = format!("{format}{literal}");
    assert_eq!(
        VmDateTime::parse(&text, &format).unwrap_err().to_string(),
        "datetime parse work limit exceeded"
    );
}
