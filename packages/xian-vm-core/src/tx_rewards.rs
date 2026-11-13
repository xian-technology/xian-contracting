//! A transaction's fee rewards, as `xian.rewards.RewardsHandler.
//! build_tx_reward_outputs` computes them: shares in `decimal.Decimal` at the
//! default 28-digit context, each converted to `ContractingDecimal` and
//! divided by the chain chi rate. Inputs the port does not cover, and every
//! case where Python raises, stop with `Stop::Handback`.
use crate::python_decimal::PyDecimal;
use crate::settlement::{checked_add, fixed_int, handback, Settled};
use crate::{VmDecimal, VmValue};
use num_bigint::BigInt;
use num_traits::{Signed, Zero};
use std::cmp::Ordering;

/// Reads state as the node's client does (`get_var`, unmarked).
pub(crate) trait RewardState {
    fn get(&mut self, key: &str) -> Settled<Option<VmValue>>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RewardKind {
    Validator,
    Delegator,
    Foundation,
    Developer,
}

impl RewardKind {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Validator => "validator_reward",
            Self::Delegator => "delegator_reward",
            Self::Foundation => "foundation_reward",
            Self::Developer => "developer_reward",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RewardRecord {
    pub(crate) kind: RewardKind,
    pub(crate) recipient_key: String,
    pub(crate) source_contract: Option<String>,
    pub(crate) validator_key: Option<String>,
    pub(crate) delegator_key: Option<String>,
    pub(crate) value: VmDecimal,
}

/// Amounts by recipient, in first-credit order (a Python dict).
pub(crate) type Credits = Vec<(String, VmDecimal)>;

/// `rewards` of a receipt: one credit map per kind, in `RewardKind` order.
pub(crate) type RewardBuckets = [(RewardKind, Credits); 4];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TxRewards {
    /// `None` when no reward was paid.
    pub(crate) rewards: Option<RewardBuckets>,
    /// Balance deltas by storage key.
    pub(crate) deltas: Credits,
    pub(crate) records: Vec<RewardRecord>,
}

impl TxRewards {
    fn none(records: Vec<RewardRecord>) -> Self {
        Self {
            rewards: None,
            deltas: Vec::new(),
            records,
        }
    }
}

fn merge(credits: &mut Credits, other: &Credits) -> Settled<()> {
    for (key, amount) in other {
        credit(credits, key, amount)?;
    }
    Ok(())
}

fn credit(credits: &mut Credits, key: &str, amount: &VmDecimal) -> Settled<()> {
    match credits.iter_mut().find(|(existing, _)| existing == key) {
        Some((_, total)) => *total = checked_add(total, amount)?,
        None => credits.push((key.to_owned(), amount.clone())),
    }
    Ok(())
}

/// `RewardsHandler._as_decimal` for the value types the port covers.
fn as_decimal(value: &VmValue) -> Settled<PyDecimal> {
    match value {
        VmValue::Int(value) => Ok(PyDecimal::int(value.clone())),
        VmValue::Decimal(value) => Ok(PyDecimal::fixed(value)),
        other => handback(format!("{} reward input", other.type_name())),
    }
}

fn present(value: Option<VmValue>) -> Option<VmValue> {
    value.filter(|value| !matches!(value, VmValue::None))
}

/// Python truthiness of a state value the port covers.
fn truthy(value: &VmValue) -> Settled<bool> {
    Ok(match value {
        VmValue::None => false,
        VmValue::Bool(value) => *value,
        VmValue::Int(value) => !value.is_zero(),
        VmValue::Decimal(value) => !value.is_zero(),
        VmValue::String(value) => !value.is_empty(),
        VmValue::List(items) => !items.is_empty(),
        other => return handback(format!("truthiness of {}", other.type_name())),
    })
}

fn string(value: VmValue, what: &str) -> Settled<String> {
    match value {
        VmValue::String(value) => Ok(value),
        other => handback(format!("{what} is a {}", other.type_name())),
    }
}

/// A list of strings; a falsy value is the empty list.
fn names(value: Option<VmValue>, what: &str) -> Settled<Vec<String>> {
    match present(value) {
        None => Ok(Vec::new()),
        Some(VmValue::List(items)) => items.into_iter().map(|item| string(item, what)).collect(),
        Some(other) if !truthy(&other)? => Ok(Vec::new()),
        Some(other) => handback(format!("{what} list is a {}", other.type_name())),
    }
}

/// A key value: the default when missing or empty, else a string.
fn key_or(value: Option<VmValue>, default: &str, what: &str) -> Settled<String> {
    match present(value) {
        None => Ok(default.to_owned()),
        Some(VmValue::String(value)) if value.is_empty() => Ok(default.to_owned()),
        Some(value) => string(value, what),
    }
}

/// A non-negative amount: missing is 0, negative is 0.
fn non_negative(value: Option<VmValue>) -> Settled<PyDecimal> {
    let Some(value) = present(value) else {
        return Ok(PyDecimal::int(0));
    };
    let value = as_decimal(&value)?;
    Ok(if value.sign()? == Ordering::Less {
        PyDecimal::int(0)
    } else {
        value
    })
}

/// `0 + w1 + w2 + ...`, as Python's `sum` adds.
fn sum<T>(weights: &[(T, PyDecimal)]) -> Settled<PyDecimal> {
    let mut total = PyDecimal::int(0);
    for (_, weight) in weights {
        total = total.add(weight)?;
    }
    Ok(total)
}

/// `share`s of `total` by weight; the last takes what is left.
fn split<T>(
    total: &PyDecimal,
    weights: &[(T, PyDecimal)],
    scale: &PyDecimal,
    base: &PyDecimal,
    mut allocated: PyDecimal,
) -> Settled<Vec<PyDecimal>> {
    let mut shares = Vec::with_capacity(weights.len());
    for (index, (_, weight)) in weights.iter().enumerate() {
        if index + 1 == weights.len() {
            shares.push(total.sub(&allocated)?);
        } else {
            let share = scale.mul(weight)?.div(base)?;
            allocated = allocated.add(&share)?;
            shares.push(share);
        }
    }
    Ok(shares)
}

struct Rewards<'a> {
    state: &'a mut dyn RewardState,
}

impl Rewards<'_> {
    fn var(&mut self, contract: &str, variable: &str, args: &[&str]) -> Settled<Option<VmValue>> {
        let mut key = format!("{contract}.{variable}");
        for arg in args {
            key.push(':');
            key.push_str(arg);
        }
        self.state.get(&key)
    }

    /// The operator's reward key, commission (basis points, capped at
    /// 10000) and self bond of `validator`.
    fn operator_terms(&mut self, validator: &str) -> Settled<(String, PyDecimal, PyDecimal)> {
        let operator_key = key_or(
            self.var("validators", "reward_keys", &[validator])?,
            validator,
            "reward key",
        )?;
        let commission_bps =
            non_negative(self.var("validators", "commission_bps", &[validator])?)?;
        let cap = PyDecimal::int(10_000);
        let commission_bps = if commission_bps.compare(&cap)? == Ordering::Greater {
            cap
        } else {
            commission_bps
        };
        let self_bond = non_negative(self.var("validators", "self_bond", &[validator])?)?;
        Ok((operator_key, commission_bps, self_bond))
    }

    /// The positive delegations to `validator` as `((delegator, reward key),
    /// amount)`, and their total.
    fn delegations(
        &mut self,
        validator: &str,
    ) -> Settled<(Vec<((String, String), PyDecimal)>, PyDecimal)> {
        let mut weights = Vec::new();
        let mut total = PyDecimal::int(0);
        for delegator in names(
            self.var("validators", "delegator_lists", &[validator])?,
            "delegator",
        )? {
            let delegation =
                non_negative(self.var("validators", "delegations", &[&delegator, validator])?)?;
            if delegation.sign()? != Ordering::Greater {
                continue;
            }
            total = total.add(&delegation)?;
            let reward_key = key_or(
                self.var(
                    "validators",
                    "delegator_reward_keys",
                    &[&delegator, validator],
                )?,
                &delegator,
                "reward key",
            )?;
            weights.push(((delegator, reward_key), delegation));
        }
        Ok((weights, total))
    }

    /// `build_single_validator_reward_outputs`: credits `mapping` and
    /// appends the records.
    fn single_validator(
        &mut self,
        validator: &str,
        total_reward: &PyDecimal,
        mapping: &mut Credits,
        records: &mut Vec<RewardRecord>,
    ) -> Settled<()> {
        let (operator_key, commission_bps, self_bond) = self.operator_terms(validator)?;
        let (weights, total_delegated) = self.delegations(validator)?;
        let record =
            |kind, recipient: &str, delegator: Option<&str>, value: &VmDecimal| RewardRecord {
                kind,
                recipient_key: recipient.to_owned(),
                source_contract: None,
                validator_key: Some(validator.to_owned()),
                delegator_key: delegator.map(str::to_owned),
                value: value.clone(),
            };
        let stake_base = self_bond.add(&total_delegated)?;
        let mut own = Credits::new();
        if stake_base.sign()? != Ordering::Greater {
            let amount = total_reward.to_fixed()?;
            records.push(record(RewardKind::Validator, &operator_key, None, &amount));
            own.push((operator_key, amount));
            return merge(mapping, &own);
        }
        let commission = total_reward
            .mul(&commission_bps)?
            .div(&PyDecimal::int(10_000))?;
        let remainder = total_reward.sub(&commission)?;
        let mut operator_total = commission;
        if self_bond.sign()? == Ordering::Greater {
            operator_total = operator_total.add(&remainder.mul(&self_bond)?.div(&stake_base)?)?;
        }
        if operator_total.sign()? == Ordering::Greater {
            let amount = operator_total.to_fixed()?;
            credit(&mut own, &operator_key, &amount)?;
            records.push(record(RewardKind::Validator, &operator_key, None, &amount));
        }
        let shares = split(
            total_reward,
            &weights,
            &remainder,
            &stake_base,
            operator_total,
        )?;
        for (((delegator, reward_key), _), share) in weights.iter().zip(shares) {
            let amount = share.to_fixed()?;
            credit(&mut own, reward_key, &amount)?;
            records.push(record(
                RewardKind::Delegator,
                reward_key,
                Some(delegator),
                &amount,
            ));
        }
        merge(mapping, &own)
    }

    /// `build_validator_set_reward_outputs`: records only (the mapping is
    /// built for its overflow checks, as Python builds it).
    fn validator_set(
        &mut self,
        total: &PyDecimal,
        ratio: &PyDecimal,
        redirected: &PyDecimal,
    ) -> Settled<Vec<RewardRecord>> {
        let validator_total = total.mul(ratio)?.add(redirected)?;
        let weighted = self.weighted_validators()?;
        let mut records = Vec::new();
        if weighted.is_empty() {
            return Ok(records);
        }
        let total_weight = sum(&weighted)?;
        let shares = split(
            &validator_total,
            &weighted,
            &validator_total,
            &total_weight,
            PyDecimal::int(0),
        )?;
        let mut mapping = Credits::new();
        for ((validator, _), share) in weighted.iter().zip(shares) {
            self.single_validator(validator, &share, &mut mapping, &mut records)?;
        }
        Ok(records)
    }

    /// The active validators with their power (a missing or non-positive
    /// power counts as 1).
    fn weighted_validators(&mut self) -> Settled<Vec<(String, PyDecimal)>> {
        let validators = names(
            self.var("validators", "active_validators", &[])?,
            "validator",
        )?;
        let mut weighted = Vec::with_capacity(validators.len());
        for validator in validators {
            let power = match present(self.var("validators", "powers", &[&validator])?) {
                None => PyDecimal::int(1),
                Some(value) => {
                    let power = as_decimal(&value)?;
                    if power.sign()? == Ordering::Greater {
                        power
                    } else {
                        PyDecimal::int(1)
                    }
                }
            };
            weighted.push((validator, power));
        }
        Ok(weighted)
    }

    /// The developer of `source`; "" when it has none.
    fn developer(&mut self, source: &str) -> Settled<String> {
        match present(self.var(source, "__developer__", &[])?) {
            Some(value) if truthy(&value)? => string(value, "developer"),
            _ => Ok(String::new()),
        }
    }

    /// `find_developer_and_reward`: developer credits, records and the share
    /// redirected to validators.
    fn developers(
        &mut self,
        total: &PyDecimal,
        contract: &str,
        ratio: &PyDecimal,
        contract_costs: &[(String, BigInt)],
    ) -> Settled<(Credits, Vec<RewardRecord>, PyDecimal)> {
        let developer_total = total.mul(ratio)?;
        let mut weights = Vec::new();
        for (source, weight) in contract_costs {
            if weight.is_positive() {
                weights.push((source.clone(), PyDecimal::int(weight.clone())));
            }
        }
        if weights.is_empty() {
            weights.push((contract.to_owned(), PyDecimal::int(1)));
        }
        let total_weight = sum(&weights)?;
        let shares = split(
            &developer_total,
            &weights,
            &developer_total,
            &total_weight,
            PyDecimal::int(0),
        )?;
        let mut credits = Credits::new();
        let mut records = Vec::new();
        let mut redirected = PyDecimal::int(0);
        for ((source, _), share) in weights.iter().zip(shares) {
            let recipient = self.developer(source)?;
            if recipient.is_empty() || recipient == "sys" {
                redirected = redirected.add(&share)?;
                continue;
            }
            let amount = share.to_fixed()?;
            credit(&mut credits, &recipient, &amount)?;
            records.push(RewardRecord {
                kind: RewardKind::Developer,
                recipient_key: recipient,
                source_contract: Some(source.clone()),
                validator_key: None,
                delegator_key: None,
                value: amount,
            });
        }
        Ok((credits, records, redirected))
    }
}

/// The chain chi rate as `chain_chi_rate` reads it; anything but a positive
/// integer is refused there, so it is left to Python.
pub(crate) fn chain_chi_rate(value: Option<VmValue>) -> Settled<BigInt> {
    match value {
        Some(VmValue::Int(rate)) if rate.is_positive() => Ok(rate),
        _ => handback("chain state has no valid chi rate"),
    }
}

/// The reward split (validator, burn, foundation, developer ratios), or
/// `None` when rewards are not set up.
fn reward_split(value: Option<VmValue>) -> Settled<Option<Vec<VmValue>>> {
    match present(value) {
        None => Ok(None),
        Some(value) if !truthy(&value)? => Ok(None),
        Some(VmValue::List(parts)) if parts.len() == 4 => Ok(Some(parts)),
        Some(other) => handback(format!("reward split is a {}", other.type_name())),
    }
}

/// The receipt's rewards, the balance deltas and the records, as
/// `build_tx_reward_outputs` assembles them from per-chi amounts.
struct Payout {
    rate: BigInt,
    buckets: RewardBuckets,
    deltas: Credits,
    records: Vec<RewardRecord>,
}

impl Payout {
    fn new(rate: BigInt) -> Self {
        let kinds = [
            RewardKind::Validator,
            RewardKind::Delegator,
            RewardKind::Foundation,
            RewardKind::Developer,
        ];
        Self {
            rate,
            buckets: kinds.map(|kind| (kind, Credits::new())),
            deltas: Credits::new(),
            records: Vec::new(),
        }
    }

    /// `value` in chi, priced in tokens at the chain rate.
    fn tokens(&self, value: &VmDecimal) -> Settled<VmDecimal> {
        crate::settlement::checked(value.div(&fixed_int(&self.rate)?))
    }

    fn pay(&mut self, kind: RewardKind, recipient: &str, amount: &VmDecimal) -> Settled<()> {
        let bucket = self
            .buckets
            .iter_mut()
            .find(|(candidate, _)| *candidate == kind)
            .expect("every kind has a bucket");
        credit(&mut bucket.1, recipient, amount)?;
        credit(
            &mut self.deltas,
            &format!("currency.balances:{recipient}"),
            amount,
        )
    }

    /// Pays `record` and keeps it, with its amount in tokens.
    fn pay_record(&mut self, record: RewardRecord) -> Settled<()> {
        let amount = self.tokens(&record.value)?;
        self.pay(record.kind, &record.recipient_key, &amount)?;
        self.records.push(RewardRecord {
            value: amount,
            ..record
        });
        Ok(())
    }

    fn finish(self) -> TxRewards {
        if self.buckets.iter().all(|(_, credits)| credits.is_empty()) {
            return TxRewards::none(self.records);
        }
        TxRewards {
            rewards: Some(self.buckets),
            deltas: self.deltas,
            records: self.records,
        }
    }
}

/// `build_tx_reward_outputs` for `total_chi` chi used by a transaction to
/// `contract`; `contract_costs` in name order.
pub(crate) fn tx_reward_outputs(
    state: &mut dyn RewardState,
    total_chi: &BigInt,
    contract: &str,
    contract_costs: &[(String, BigInt)],
) -> Settled<TxRewards> {
    let mut rewards = Rewards { state };
    let Some(split) = reward_split(rewards.var("rewards", "S", &["value"])?)? else {
        return Ok(TxRewards::none(Vec::new()));
    };
    if !total_chi.is_positive() {
        return Ok(TxRewards::none(Vec::new()));
    }
    let rate = chain_chi_rate(rewards.var("chi_cost", "S", &["value"])?)?;
    // Python logs an incomplete configuration; it keeps that report.
    let Some(foundation_owner) = present(rewards.var("foundation", "owner", &[])?) else {
        return handback("reward configuration is incomplete");
    };
    let foundation_owner = string(foundation_owner, "foundation owner")?;
    let [validator_ratio, _burn, foundation_ratio, developer_ratio] =
        [0, 1, 2, 3].map(|index| as_decimal(&split[index]));
    let total = PyDecimal::int(total_chi.clone());

    // calculate_participant_reward(foundation_ratio, 1, total): Python turns a
    // failure into a zero reward; the port leaves that to Python.
    let foundation_reward = foundation_ratio?
        .div(&PyDecimal::int(1))?
        .mul(&total)?
        .round(8)?
        .to_fixed()?;
    let (developer_credits, developer_records, redirected) =
        rewards.developers(&total, contract, &developer_ratio?, contract_costs)?;
    let validator_records = rewards.validator_set(&total, &validator_ratio?, &redirected)?;

    let mut payout = Payout::new(rate);
    if !foundation_reward.is_zero() {
        payout.pay_record(RewardRecord {
            kind: RewardKind::Foundation,
            recipient_key: foundation_owner,
            source_contract: None,
            validator_key: None,
            delegator_key: None,
            value: foundation_reward,
        })?;
    }
    for record in validator_records {
        payout.pay_record(record)?;
    }
    for (developer, reward) in &developer_credits {
        let amount = payout.tokens(reward)?;
        payout.pay(RewardKind::Developer, developer, &amount)?;
    }
    // Developer records are priced one by one, after the per-developer sums.
    for record in developer_records {
        let value = payout.tokens(&record.value)?;
        payout.records.push(RewardRecord { value, ..record });
    }
    Ok(payout.finish())
}

#[cfg(test)]
mod tests {
    //! The pinned corpus of xian-abci (tests/unit/test_reward_output_corpus.py
    //! and test_fee_settlement_corpus.py, seed 20261113), with the outputs of
    //! its Python reference, as wire JSON. xian-abci checks the same cases
    //! through the Python bindings; this runs them in Rust.
    use super::*;
    use crate::settlement::{self, Balance, Stop};
    use crate::stored_value::decode_stored_value;
    use crate::stored_value_encoder::encode_stored_value;
    use serde_json::Value;
    use std::collections::HashMap;

    fn corpus() -> Value {
        serde_json::from_str(include_str!("../tests/settlement_corpus.json")).unwrap()
    }

    fn decode(text: &str) -> VmValue {
        decode_stored_value(text.as_bytes()).unwrap()
    }

    fn wire(value: &VmValue) -> String {
        String::from_utf8(encode_stored_value(value).unwrap()).unwrap()
    }

    fn text(value: &str) -> VmValue {
        VmValue::String(value.to_owned())
    }

    fn dict(entries: Vec<(&str, VmValue)>) -> VmValue {
        VmValue::Dict(
            entries
                .into_iter()
                .map(|(key, value)| (text(key), value))
                .collect(),
        )
    }

    fn credits(credits: &Credits) -> VmValue {
        VmValue::Dict(
            credits
                .iter()
                .map(|(key, value)| (text(key), VmValue::Decimal(value.clone())))
                .collect(),
        )
    }

    fn optional(value: &Option<String>) -> VmValue {
        value.as_deref().map_or(VmValue::None, text)
    }

    fn record(record: &RewardRecord) -> VmValue {
        let mut entries = vec![
            ("type", text(record.kind.name())),
            ("recipient_key", text(&record.recipient_key)),
            ("source_contract", optional(&record.source_contract)),
            ("value", VmValue::Decimal(record.value.clone())),
        ];
        if record.validator_key.is_some() {
            entries.push(("validator_key", optional(&record.validator_key)));
        }
        if record.delegator_key.is_some() {
            entries.push(("delegator_key", optional(&record.delegator_key)));
        }
        dict(entries)
    }

    fn outputs(rewards: &TxRewards) -> VmValue {
        let buckets = rewards.rewards.as_ref().map_or(VmValue::None, |buckets| {
            VmValue::Dict(
                buckets
                    .iter()
                    .map(|(kind, entries)| (text(kind.name()), credits(entries)))
                    .collect(),
            )
        });
        VmValue::List(vec![
            buckets,
            credits(&rewards.deltas),
            VmValue::List(rewards.records.iter().map(record).collect()),
        ])
    }

    impl RewardState for HashMap<String, VmValue> {
        fn get(&mut self, key: &str) -> Settled<Option<VmValue>> {
            Ok(HashMap::get(self, key).cloned())
        }
    }

    fn int(value: &Value) -> BigInt {
        BigInt::from(value.as_i64().unwrap())
    }

    #[test]
    fn rewards_match_the_python_corpus() {
        let corpus = corpus();
        let cases = corpus["rewards"].as_array().unwrap();
        assert_eq!(cases.len(), 160);
        for (index, case) in cases.iter().enumerate() {
            let mut state: HashMap<String, VmValue> = case["state"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(key, value)| (key.clone(), decode(value.as_str().unwrap())))
                .collect();
            let costs: Vec<(String, BigInt)> = case["contract_costs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|pair| (pair[0].as_str().unwrap().to_owned(), int(&pair[1])))
                .collect();
            let rewards = tx_reward_outputs(
                &mut state,
                &int(&case["total_chi"]),
                case["contract"].as_str().unwrap(),
                &costs,
            )
            .unwrap();
            assert_eq!(
                wire(&outputs(&rewards)),
                case["expected"].as_str().unwrap(),
                "case {index}"
            );
        }
    }

    fn fee_outcome(case: &Value) -> Result<VmValue, Stop> {
        let rate = int(&case["rate"]);
        let chi_used = int(&case["chi_used"]);
        let start = Balance::of(Some(&decode(case["balance"].as_str().unwrap())))?;
        let (reserved, refunded) = match settlement::reserve(&start, &int(&case["budget"]), &rate)?
        {
            None => (VmValue::None, VmValue::None),
            Some(reservation) => {
                let after = match case["written"].as_str() {
                    Some(written) => Balance::of(Some(&decode(written)))?,
                    None => Balance::Fixed(reservation.spendable.clone()),
                };
                let refunded = settlement::refund(&reservation, &after, &chi_used, &rate)?;
                (
                    VmValue::List(vec![
                        VmValue::Decimal(reservation.amount),
                        VmValue::Decimal(reservation.spendable),
                    ]),
                    VmValue::Decimal(refunded),
                )
            }
        };
        let metered = settlement::metered_balance(&start, &chi_used, &rate)?
            .unwrap_or_else(|| text("unchanged"));
        Ok(dict(vec![
            ("reserved", reserved),
            ("refunded", refunded),
            ("metered", metered),
        ]))
    }

    #[test]
    fn fee_settlement_matches_the_python_corpus() {
        let corpus = corpus();
        let cases = corpus["fees"].as_array().unwrap();
        assert_eq!(cases.len(), 400);
        for (index, case) in cases.iter().enumerate() {
            assert_eq!(
                wire(&fee_outcome(case).unwrap()),
                case["expected"].as_str().unwrap(),
                "case {index}"
            );
        }
    }
}
