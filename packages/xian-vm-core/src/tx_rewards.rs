//! A transaction's fee rewards, as `xian.rewards.RewardsHandler.
//! build_tx_reward_outputs` computes them: shares in `decimal.Decimal` at the
//! default 28-digit context, each converted to `ContractingDecimal` and
//! divided by the chain chi rate.
//!
//! Revision 14: a transaction's rewards are paid in full or not at all. A
//! reward input of a type it may not hold (the split, the foundation owner,
//! the validators and their terms, a developer), a computation the decimal
//! context cannot represent, or a recipient whose balance key LMDB cannot
//! store means no rewards for that transaction: its fee is burned, as the
//! burn share is. The transaction itself is unaffected, so the governance
//! transaction that repairs the configuration still runs.
use crate::lmdb_env::storage_key_error;
use crate::python_decimal::{DecimalSignal, PyDecimal};
use crate::settlement::{checked_add, fixed_int, InvalidBalance, Settled, Stop};
use crate::{VmDecimal, VmValue};
use num_bigint::BigInt;
use num_traits::{Signed, Zero};
use std::cmp::Ordering;

/// Reads state as the node's client does (`get_var`, unmarked).
pub(crate) trait RewardState {
    fn get(&mut self, key: &str) -> Settled<Option<VmValue>>;
}

/// Why a transaction pays no rewards.
#[derive(Debug)]
pub(crate) enum Unpaid {
    /// An invalid reward input or an unrepresentable amount.
    Invalid,
    Fault(Stop),
}

impl From<Stop> for Unpaid {
    fn from(stop: Stop) -> Self {
        Self::Fault(stop)
    }
}

impl From<DecimalSignal> for Unpaid {
    fn from(_: DecimalSignal) -> Self {
        Self::Invalid
    }
}

impl From<InvalidBalance> for Unpaid {
    fn from(_: InvalidBalance) -> Self {
        Self::Invalid
    }
}

type Reward<T> = Result<T, Unpaid>;

fn invalid<T>() -> Reward<T> {
    Err(Unpaid::Invalid)
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

fn merge(credits: &mut Credits, other: &Credits) -> Reward<()> {
    for (key, amount) in other {
        credit(credits, key, amount)?;
    }
    Ok(())
}

fn credit(credits: &mut Credits, key: &str, amount: &VmDecimal) -> Reward<()> {
    match credits.iter_mut().find(|(existing, _)| existing == key) {
        Some((_, total)) => *total = checked_add(total, amount)?,
        None => credits.push((key.to_owned(), amount.clone())),
    }
    Ok(())
}

/// `RewardsHandler._as_decimal` for the value types the port covers.
fn as_decimal(value: &VmValue) -> Reward<PyDecimal> {
    match value {
        VmValue::Int(value) => Ok(PyDecimal::int(value.clone())),
        VmValue::Decimal(value) => Ok(PyDecimal::fixed(value)),
        _ => invalid(),
    }
}

fn present(value: Option<VmValue>) -> Option<VmValue> {
    value.filter(|value| !matches!(value, VmValue::None))
}

/// Python truthiness of a state value the port covers.
fn truthy(value: &VmValue) -> Reward<bool> {
    Ok(match value {
        VmValue::None => false,
        VmValue::Bool(value) => *value,
        VmValue::Int(value) => !value.is_zero(),
        VmValue::Decimal(value) => !value.is_zero(),
        VmValue::String(value) => !value.is_empty(),
        VmValue::List(items) => !items.is_empty(),
        _ => return invalid(),
    })
}

fn string(value: VmValue) -> Reward<String> {
    match value {
        VmValue::String(value) => Ok(value),
        _ => invalid(),
    }
}

/// A list of strings; a falsy value is the empty list.
fn names(value: Option<VmValue>) -> Reward<Vec<String>> {
    match present(value) {
        None => Ok(Vec::new()),
        Some(VmValue::List(items)) => items.into_iter().map(string).collect(),
        Some(other) if !truthy(&other)? => Ok(Vec::new()),
        Some(_) => invalid(),
    }
}

/// A key value: the default when missing or empty, else a string.
fn key_or(value: Option<VmValue>, default: &str) -> Reward<String> {
    match present(value) {
        None => Ok(default.to_owned()),
        Some(VmValue::String(value)) if value.is_empty() => Ok(default.to_owned()),
        Some(value) => string(value),
    }
}

/// A non-negative amount: missing is 0, negative is 0.
fn non_negative(value: Option<VmValue>) -> Reward<PyDecimal> {
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
fn sum<T>(weights: &[(T, PyDecimal)]) -> Reward<PyDecimal> {
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
) -> Reward<Vec<PyDecimal>> {
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
    fn var(&mut self, contract: &str, variable: &str, args: &[&str]) -> Reward<Option<VmValue>> {
        let mut key = format!("{contract}.{variable}");
        for arg in args {
            key.push(':');
            key.push_str(arg);
        }
        Ok(self.state.get(&key)?)
    }

    /// The operator's reward key, commission (basis points, capped at
    /// 10000) and self bond of `validator`.
    fn operator_terms(&mut self, validator: &str) -> Reward<(String, PyDecimal, PyDecimal)> {
        let operator_key = key_or(
            self.var("validators", "reward_keys", &[validator])?,
            validator,
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
    ) -> Reward<(Vec<((String, String), PyDecimal)>, PyDecimal)> {
        let mut weights = Vec::new();
        let mut total = PyDecimal::int(0);
        for delegator in names(self.var("validators", "delegator_lists", &[validator])?)? {
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
    ) -> Reward<()> {
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
    ) -> Reward<Vec<RewardRecord>> {
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
    fn weighted_validators(&mut self) -> Reward<Vec<(String, PyDecimal)>> {
        let validators = names(self.var("validators", "active_validators", &[])?)?;
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
    fn developer(&mut self, source: &str) -> Reward<String> {
        match present(self.var(source, "__developer__", &[])?) {
            Some(value) if truthy(&value)? => string(value),
            _ => Ok(String::new()),
        }
    }

    /// `find_developer_and_reward`: developer credits, records and the share
    /// redirected to validators (all of it without `pay_developers`).
    fn developers(
        &mut self,
        total: &PyDecimal,
        contract: &str,
        ratio: &PyDecimal,
        contract_costs: &[(String, BigInt)],
        pay_developers: bool,
    ) -> Reward<(Credits, Vec<RewardRecord>, PyDecimal)> {
        let developer_total = total.mul(ratio)?;
        if !pay_developers {
            return Ok((Credits::new(), Vec::new(), developer_total));
        }
        let weights = developer_weights(contract, contract_costs);
        let total_weight = sum(&weights)?;
        let shares = split(
            &developer_total,
            &weights,
            &developer_total,
            &total_weight,
            PyDecimal::int(0),
        )?;
        self.developer_shares(&weights, shares)
    }

    /// Each contract's developer share credited to its developer, or
    /// redirected to validators when it has none (or the system one).
    fn developer_shares(
        &mut self,
        weights: &[(String, PyDecimal)],
        shares: Vec<PyDecimal>,
    ) -> Reward<(Credits, Vec<RewardRecord>, PyDecimal)> {
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

/// `_developer_weights`: the contracts with a positive execution cost, in
/// name order, else the entry contract.
fn developer_weights(
    contract: &str,
    contract_costs: &[(String, BigInt)],
) -> Vec<(String, PyDecimal)> {
    let weights: Vec<_> = contract_costs
        .iter()
        .filter(|(_, weight)| weight.is_positive())
        .map(|(source, weight)| (source.clone(), PyDecimal::int(weight.clone())))
        .collect();
    if weights.is_empty() {
        return vec![(contract.to_owned(), PyDecimal::int(1))];
    }
    weights
}

/// The state key of the chain's chi rate (chi per native token).
pub(crate) const CHI_RATE_KEY: &str = "chi_cost.S:value";

/// The chain chi rate: a positive integer (whose `ContractingDecimal` is
/// representable). The node refuses to run on any other rate, as admission
/// does (`validated_chi_rate`): a broken chain, not a price to guess.
pub(crate) fn chain_chi_rate(value: Option<VmValue>) -> Settled<BigInt> {
    let shown = value
        .as_ref()
        .map_or_else(|| "None".to_owned(), VmValue::python_repr);
    value.and_then(valid_chi_rate).ok_or_else(|| {
        Stop::Fault(format!(
            "chain state has no valid chi rate ({CHI_RATE_KEY} = {shown})"
        ))
    })
}

/// `value` as a chi rate, if it is one.
pub(crate) fn valid_chi_rate(value: VmValue) -> Option<BigInt> {
    match value {
        VmValue::Int(rate) if rate.is_positive() && fixed_int(&rate).is_ok() => Some(rate),
        _ => None,
    }
}

/// The reward split (validator, burn, foundation, developer ratios), or
/// `None` when rewards are not set up.
fn reward_split(value: Option<VmValue>) -> Reward<Option<Vec<VmValue>>> {
    match present(value) {
        None => Ok(None),
        Some(value) if !truthy(&value)? => Ok(None),
        Some(VmValue::List(parts)) if parts.len() == 4 => Ok(Some(parts)),
        Some(_) => invalid(),
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
    fn tokens(&self, value: &VmDecimal) -> Reward<VmDecimal> {
        Ok(crate::settlement::checked(
            value.div(&fixed_int(&self.rate)?),
        )?)
    }

    fn pay(&mut self, kind: RewardKind, recipient: &str, amount: &VmDecimal) -> Reward<()> {
        let key = format!("currency.balances:{recipient}");
        if storage_key_error(&key).is_some() {
            return invalid();
        }
        let bucket = self
            .buckets
            .iter_mut()
            .find(|(candidate, _)| *candidate == kind)
            .expect("every kind has a bucket");
        credit(&mut bucket.1, recipient, amount)?;
        credit(&mut self.deltas, &key, amount)
    }

    /// Pays `record` and keeps it, with its amount in tokens.
    fn pay_record(&mut self, record: RewardRecord) -> Reward<()> {
        let amount = self.tokens(&record.value)?;
        self.pay(record.kind, &record.recipient_key, &amount)?;
        self.records.push(RewardRecord {
            value: amount,
            ..record
        });
        Ok(())
    }

    fn pay_records(&mut self, records: Vec<RewardRecord>) -> Reward<()> {
        for record in records {
            self.pay_record(record)?;
        }
        Ok(())
    }

    /// The foundation's share, when it has one.
    fn pay_foundation(&mut self, owner: String, reward: VmDecimal) -> Reward<()> {
        if reward.is_zero() {
            return Ok(());
        }
        self.pay_record(RewardRecord {
            kind: RewardKind::Foundation,
            recipient_key: owner,
            source_contract: None,
            validator_key: None,
            delegator_key: None,
            value: reward,
        })
    }

    /// The developer credits by developer; their records are priced one by
    /// one, after the per-developer sums.
    fn pay_developers(&mut self, credits: &Credits, records: Vec<RewardRecord>) -> Reward<()> {
        for (developer, reward) in credits {
            let amount = self.tokens(reward)?;
            self.pay(RewardKind::Developer, developer, &amount)?;
        }
        for record in records {
            let value = self.tokens(&record.value)?;
            self.records.push(RewardRecord { value, ..record });
        }
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

/// `build_tx_reward_outputs` for the fee of `total` chi paid by a
/// transaction to `contract`; `contract_costs` in name order. Without
/// `pay_developers` (a failed call) the developer share goes to validators.
/// An invalid reward input pays nothing (the fee is burned).
pub(crate) fn tx_reward_outputs(
    state: &mut dyn RewardState,
    total: &PyDecimal,
    contract: &str,
    contract_costs: &[(String, BigInt)],
    pay_developers: bool,
) -> Settled<TxRewards> {
    match paid_rewards(state, total, contract, contract_costs, pay_developers) {
        Ok(rewards) => Ok(rewards),
        Err(Unpaid::Invalid) => Ok(TxRewards::none(Vec::new())),
        Err(Unpaid::Fault(stop)) => Err(stop),
    }
}

fn paid_rewards(
    state: &mut dyn RewardState,
    total: &PyDecimal,
    contract: &str,
    contract_costs: &[(String, BigInt)],
    pay_developers: bool,
) -> Reward<TxRewards> {
    let mut rewards = Rewards { state };
    let Some((split, rate, foundation_owner)) = reward_terms(&mut rewards, total)? else {
        return Ok(TxRewards::none(Vec::new()));
    };
    let [validator_ratio, foundation_ratio, developer_ratio] = paid_ratios(&split)?;
    let foundation_reward = foundation_share(&foundation_ratio, total)?;
    let (developer_credits, developer_records, redirected) = rewards.developers(
        total,
        contract,
        &developer_ratio,
        contract_costs,
        pay_developers,
    )?;
    let validator_records = rewards.validator_set(total, &validator_ratio, &redirected)?;

    let mut payout = Payout::new(rate);
    payout.pay_foundation(foundation_owner, foundation_reward)?;
    payout.pay_records(validator_records)?;
    payout.pay_developers(&developer_credits, developer_records)?;
    Ok(payout.finish())
}

/// The validator, foundation and developer ratios of the split. The burn
/// share is never paid: it is the part no one is credited.
fn paid_ratios(split: &[VmValue]) -> Reward<[PyDecimal; 3]> {
    Ok([
        as_decimal(&split[0])?,
        as_decimal(&split[2])?,
        as_decimal(&split[3])?,
    ])
}

/// `calculate_participant_reward(foundation_ratio, 1, total)`.
fn foundation_share(ratio: &PyDecimal, total: &PyDecimal) -> Reward<VmDecimal> {
    Ok(ratio
        .div(&PyDecimal::int(1))?
        .mul(total)?
        .round(8)?
        .to_fixed()?)
}

/// The reward split, the chain chi rate and the foundation owner, as
/// `_build_tx_reward_outputs` reads them; `None` when no reward is paid.
fn reward_terms(
    rewards: &mut Rewards<'_>,
    total: &PyDecimal,
) -> Reward<Option<(Vec<VmValue>, BigInt, String)>> {
    let Some(split) = reward_split(rewards.var("rewards", "S", &["value"])?)? else {
        return Ok(None);
    };
    if total.sign()? != Ordering::Greater {
        return Ok(None);
    }
    let Some(rate) = rewards
        .var("chi_cost", "S", &["value"])?
        .and_then(valid_chi_rate)
    else {
        return invalid();
    };
    // A configuration without a foundation owner is incomplete.
    let Some(foundation_owner) = present(rewards.var("foundation", "owner", &[])?) else {
        return invalid();
    };
    Ok(Some((split, rate, string(foundation_owner)?)))
}

#[cfg(test)]
mod tests {
    //! The pinned corpus of xian-abci (tests/unit/test_reward_output_corpus.py
    //! and test_fee_settlement_corpus.py, seed 20261113), with the outputs of
    //! its Python reference, as wire JSON. xian-abci checks the same cases
    //! through the Python bindings; this runs them in Rust.
    use super::*;
    use crate::settlement::{self, Balance, InvalidBalance};
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

    /// The reward cases under `key`: a success pays developers and its
    /// chi used is an integer; a failure pays no developer, and its paid
    /// chi is wire-encoded (a decimal when it paid its whole balance).
    fn assert_reward_corpus(key: &str, pay_developers: bool) {
        let corpus = corpus();
        let cases = corpus[key].as_array().unwrap();
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
            let total = match &case["total_chi"] {
                Value::String(text) => as_decimal(&decode(text)).unwrap(),
                number => PyDecimal::int(int(number)),
            };
            let rewards = tx_reward_outputs(
                &mut state,
                &total,
                case["contract"].as_str().unwrap(),
                &costs,
                pay_developers,
            )
            .unwrap();
            assert_eq!(
                wire(&outputs(&rewards)),
                case["expected"].as_str().unwrap(),
                "{key} case {index}"
            );
        }
    }

    #[test]
    fn rewards_match_the_python_corpus() {
        assert_reward_corpus("rewards", true);
    }

    #[test]
    fn failed_transaction_rewards_match_the_python_corpus() {
        assert_reward_corpus("failed_rewards", false);
    }

    fn fee_outcome(case: &Value) -> Result<VmValue, InvalidBalance> {
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
        let (metered, paid) = match settlement::failure_charge(&start, &chi_used, &rate)? {
            None => (text("unchanged"), text("0")),
            Some(charge) => (charge.balance, text(&charge.paid_chi.to_string())),
        };
        Ok(dict(vec![
            ("reserved", reserved),
            ("refunded", refunded),
            ("metered", metered),
            ("paid", paid),
        ]))
    }

    /// The Python reference's outcome, with revision 14's rule: a failure
    /// charge leaves a negative balance as it is and pays nothing.
    fn expected_fee_outcome(case: &Value) -> Value {
        let expected: Value = serde_json::from_str(case["expected"].as_str().unwrap()).unwrap();
        let start = decode(case["balance"].as_str().unwrap());
        let negative = match Balance::of(Some(&start)) {
            Ok(Balance::Int(value)) => value.is_negative(),
            Ok(Balance::Fixed(value)) => value.scaled.is_negative(),
            Err(_) => false,
        };
        let mut outcome = expected;
        if negative {
            outcome["metered"] = Value::from("unchanged");
            outcome["paid"] = Value::from("0");
        }
        outcome
    }

    #[test]
    fn fee_settlement_matches_the_python_corpus() {
        let corpus = corpus();
        let cases = corpus["fees"].as_array().unwrap();
        assert_eq!(cases.len(), 400);
        for (index, case) in cases.iter().enumerate() {
            assert_eq!(
                serde_json::from_str::<Value>(&wire(&fee_outcome(case).unwrap())).unwrap(),
                expected_fee_outcome(case),
                "case {index}"
            );
        }
    }
}
