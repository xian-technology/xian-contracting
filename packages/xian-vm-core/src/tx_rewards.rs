//! A transaction's fee rewards, in `ContractingDecimal` arithmetic (30
//! fractional digits; every product and quotient truncated toward zero):
//! shares of the paid chi, each divided by the chain chi rate.
//!
//! Conservation (revision 14): the shares never sum to more than the paid
//! chi, and none is negative, so the tokens paid out never exceed the fee
//! the sender was charged (`chi / rate`). What is not paid out (the burn
//! share and the truncation dust) is burned. A proportional share is
//! `amount * weight / total weight` with one truncation; the last
//! participant of a split takes what is left; the foundation share is
//! rounded down to 8 places. A split whose paid ratios (validators,
//! foundation, developers) are negative or sum to more than 1 pays no
//! rewards.
//!
//! Revision 14: a transaction's rewards are paid in full or not at all. A
//! reward input of a type it may not hold (the split, the foundation owner,
//! the validators and their terms, a developer), an amount outside the
//! decimal range, or a recipient whose balance key LMDB cannot
//! store means no rewards for that transaction: its fee is burned, as the
//! burn share is. The transaction itself is unaffected, so the governance
//! transaction that repairs the configuration still runs.
// The browser build runs single transactions: block-only parts are unused there.
#![cfg_attr(not(feature = "python-extension"), allow(dead_code))]
use crate::committed_store::storage_key_error;
use crate::settlement::{checked, checked_add, fixed_int, InvalidBalance, Settled, Stop};
use crate::{VmDecimal, VmValue};
use num_bigint::BigInt;
use num_traits::{Signed, Zero};

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

/// A reward input as a decimal, for the value types a reward input can hold.
fn as_decimal(value: &VmValue) -> Reward<VmDecimal> {
    match value {
        VmValue::Int(value) => Ok(fixed_int(value)?),
        VmValue::Decimal(value) => Ok(value.clone()),
        _ => invalid(),
    }
}

/// `ContractingDecimal(n)` of a small constant.
fn whole(value: u32) -> VmDecimal {
    fixed_int(&BigInt::from(value)).expect("a small integer is a decimal")
}

fn sub(left: &VmDecimal, right: &VmDecimal) -> Reward<VmDecimal> {
    Ok(checked(left.sub(right))?)
}

/// `amount * weight / base`, truncated once (the product is exact). Every
/// operand is non-negative and `base` positive, so the share is at most
/// `amount` whenever `weight <= base`.
fn proportional(amount: &VmDecimal, weight: &VmDecimal, base: &VmDecimal) -> Reward<VmDecimal> {
    Ok(checked(VmDecimal::from_scaled(
        &amount.scaled * &weight.scaled / &base.scaled,
    ))?)
}

fn present(value: Option<VmValue>) -> Option<VmValue> {
    value.filter(|value| !matches!(value, VmValue::None))
}

/// Python truthiness of a present state value the port covers (callers
/// filter `None` with `present`).
fn truthy(value: &VmValue) -> Reward<bool> {
    Ok(match value {
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
fn non_negative(value: Option<VmValue>) -> Reward<VmDecimal> {
    let Some(value) = present(value) else {
        return Ok(VmDecimal::zero());
    };
    let value = as_decimal(&value)?;
    Ok(if value.scaled.is_negative() {
        VmDecimal::zero()
    } else {
        value
    })
}

/// A validator's staking terms (with a positive stake).
struct Stake {
    commission_bps: VmDecimal,
    self_bond: VmDecimal,
    stake_base: VmDecimal,
    weights: Vec<((String, String), VmDecimal)>,
}

/// Credits `validator`'s reward to its operator (commission and self bond)
/// and its delegators (the last takes what is left), and records them.
fn credit_stake(
    (own, records): (&mut Credits, &mut Vec<RewardRecord>),
    validator: &str,
    operator_key: &str,
    total_reward: &VmDecimal,
    stake: &Stake,
) -> Reward<()> {
    let (operator_total, remainder) = operator_share(
        total_reward,
        &stake.commission_bps,
        &stake.self_bond,
        &stake.stake_base,
    )?;
    if operator_total.scaled.is_positive() {
        credit_operator((own, records), validator, operator_key, &operator_total)?;
    }
    let shares = split(
        total_reward,
        &stake.weights,
        &remainder,
        &stake.stake_base,
        operator_total,
    )?;
    credit_delegators(validator, &stake.weights, shares, own, records)
}

/// Credits the operator's share of `validator`'s reward and records it.
fn credit_operator(
    (own, records): (&mut Credits, &mut Vec<RewardRecord>),
    validator: &str,
    operator_key: &str,
    amount: &VmDecimal,
) -> Reward<()> {
    credit(own, operator_key, amount)?;
    records.push(validator_record(
        RewardKind::Validator,
        validator,
        operator_key,
        None,
        amount,
    ));
    Ok(())
}

/// Credits each delegator's share of `validator`'s reward and records it.
fn credit_delegators(
    validator: &str,
    weights: &[((String, String), VmDecimal)],
    shares: Vec<VmDecimal>,
    own: &mut Credits,
    records: &mut Vec<RewardRecord>,
) -> Reward<()> {
    for (((delegator, reward_key), _), amount) in weights.iter().zip(shares) {
        credit(own, reward_key, &amount)?;
        records.push(validator_record(
            RewardKind::Delegator,
            validator,
            reward_key,
            Some(delegator),
            &amount,
        ));
    }
    Ok(())
}

/// A reward record of `validator`'s share.
fn validator_record(
    kind: RewardKind,
    validator: &str,
    recipient: &str,
    delegator: Option<&str>,
    value: &VmDecimal,
) -> RewardRecord {
    RewardRecord {
        kind,
        recipient_key: recipient.to_owned(),
        source_contract: None,
        validator_key: Some(validator.to_owned()),
        delegator_key: delegator.map(str::to_owned),
        value: value.clone(),
    }
}

/// The operator's share of a validator's `total_reward` (its commission and
/// its self bond's part of the rest) and the rest, which the stake shares.
fn operator_share(
    total_reward: &VmDecimal,
    commission_bps: &VmDecimal,
    self_bond: &VmDecimal,
    stake_base: &VmDecimal,
) -> Reward<(VmDecimal, VmDecimal)> {
    let commission = proportional(total_reward, commission_bps, &whole(10_000))?;
    let remainder = sub(total_reward, &commission)?;
    if !self_bond.scaled.is_positive() {
        return Ok((commission, remainder));
    }
    let bonded = proportional(&remainder, self_bond, stake_base)?;
    Ok((checked_add(&commission, &bonded)?, remainder))
}

/// `w1 + w2 + ...`.
fn sum<T>(weights: &[(T, VmDecimal)]) -> Reward<VmDecimal> {
    let mut total = VmDecimal::zero();
    for (_, weight) in weights {
        total = checked_add(&total, weight)?;
    }
    Ok(total)
}

/// `share`s of `total` by weight (`scale * weight / base`); the last takes
/// what is left of `total` after `allocated` and the others.
fn split<T>(
    total: &VmDecimal,
    weights: &[(T, VmDecimal)],
    scale: &VmDecimal,
    base: &VmDecimal,
    mut allocated: VmDecimal,
) -> Reward<Vec<VmDecimal>> {
    let mut shares = Vec::with_capacity(weights.len());
    for (index, (_, weight)) in weights.iter().enumerate() {
        if index + 1 == weights.len() {
            shares.push(sub(total, &allocated)?);
        } else {
            let share = proportional(scale, weight, base)?;
            allocated = checked_add(&allocated, &share)?;
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
    fn operator_terms(&mut self, validator: &str) -> Reward<(String, VmDecimal, VmDecimal)> {
        let operator_key = key_or(
            self.var("validators", "reward_keys", &[validator])?,
            validator,
        )?;
        let commission_bps =
            non_negative(self.var("validators", "commission_bps", &[validator])?)?;
        let commission_bps = commission_bps.min(whole(10_000));
        let self_bond = non_negative(self.var("validators", "self_bond", &[validator])?)?;
        Ok((operator_key, commission_bps, self_bond))
    }

    /// The positive delegations to `validator` as `((delegator, reward key),
    /// amount)`, and their total.
    fn delegations(
        &mut self,
        validator: &str,
    ) -> Reward<(Vec<((String, String), VmDecimal)>, VmDecimal)> {
        let mut weights = Vec::new();
        for delegator in names(self.var("validators", "delegator_lists", &[validator])?)? {
            if let Some(weight) = self.delegation(delegator, validator)? {
                weights.push(weight);
            }
        }
        let total = sum(&weights)?;
        Ok((weights, total))
    }

    /// A positive delegation to `validator` as `((delegator, reward key),
    /// amount)`.
    fn delegation(
        &mut self,
        delegator: String,
        validator: &str,
    ) -> Reward<Option<((String, String), VmDecimal)>> {
        let delegation =
            non_negative(self.var("validators", "delegations", &[&delegator, validator])?)?;
        if !delegation.scaled.is_positive() {
            return Ok(None);
        }
        let reward_key = key_or(
            self.var(
                "validators",
                "delegator_reward_keys",
                &[&delegator, validator],
            )?,
            &delegator,
        )?;
        Ok(Some(((delegator, reward_key), delegation)))
    }

    /// `build_single_validator_reward_outputs`: credits `mapping` and
    /// appends the records.
    fn single_validator(
        &mut self,
        validator: &str,
        total_reward: &VmDecimal,
        mapping: &mut Credits,
        records: &mut Vec<RewardRecord>,
    ) -> Reward<()> {
        let (operator_key, commission_bps, self_bond) = self.operator_terms(validator)?;
        let (weights, total_delegated) = self.delegations(validator)?;
        let stake_base = checked_add(&self_bond, &total_delegated)?;
        let mut own = Credits::new();
        let paid = (&mut own, &mut *records);
        if stake_base.scaled.is_positive() {
            let stake = Stake {
                commission_bps,
                self_bond,
                stake_base,
                weights,
            };
            credit_stake(paid, validator, &operator_key, total_reward, &stake)?;
        } else {
            credit_operator(paid, validator, &operator_key, total_reward)?;
        }
        merge(mapping, &own)
    }

    /// `build_validator_set_reward_outputs`: records only (the mapping is
    /// built for its overflow checks, as Python builds it).
    fn validator_set(
        &mut self,
        total: &VmDecimal,
        ratio: &VmDecimal,
        redirected: &VmDecimal,
    ) -> Reward<Vec<RewardRecord>> {
        let validator_total = checked_add(&checked(total.mul(ratio))?, redirected)?;
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
            VmDecimal::zero(),
        )?;
        let mut mapping = Credits::new();
        for ((validator, _), share) in weighted.iter().zip(shares) {
            self.single_validator(validator, &share, &mut mapping, &mut records)?;
        }
        Ok(records)
    }

    /// The active validators with their power (a missing or non-positive
    /// power counts as 1).
    fn weighted_validators(&mut self) -> Reward<Vec<(String, VmDecimal)>> {
        let validators = names(self.var("validators", "active_validators", &[])?)?;
        let mut weighted = Vec::with_capacity(validators.len());
        for validator in validators {
            let power = match present(self.var("validators", "powers", &[&validator])?) {
                None => whole(1),
                Some(value) => {
                    let power = as_decimal(&value)?;
                    if power.scaled.is_positive() {
                        power
                    } else {
                        whole(1)
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
        total: &VmDecimal,
        contract: &str,
        ratio: &VmDecimal,
        contract_costs: &[(String, BigInt)],
        pay_developers: bool,
    ) -> Reward<(Credits, Vec<RewardRecord>, VmDecimal)> {
        let developer_total = checked(total.mul(ratio))?;
        if !pay_developers {
            return Ok((Credits::new(), Vec::new(), developer_total));
        }
        let weights = developer_weights(contract, contract_costs)?;
        let total_weight = sum(&weights)?;
        let shares = split(
            &developer_total,
            &weights,
            &developer_total,
            &total_weight,
            VmDecimal::zero(),
        )?;
        self.developer_shares(&weights, shares)
    }

    /// Each contract's developer share credited to its developer, or
    /// redirected to validators when it has none (or the system one).
    fn developer_shares(
        &mut self,
        weights: &[(String, VmDecimal)],
        shares: Vec<VmDecimal>,
    ) -> Reward<(Credits, Vec<RewardRecord>, VmDecimal)> {
        let mut credits = Credits::new();
        let mut records = Vec::new();
        let mut redirected = VmDecimal::zero();
        for ((source, _), amount) in weights.iter().zip(shares) {
            let recipient = self.developer(source)?;
            if recipient.is_empty() || recipient == "sys" {
                redirected = checked_add(&redirected, &amount)?;
                continue;
            }
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
) -> Reward<Vec<(String, VmDecimal)>> {
    let mut weights = Vec::new();
    for (source, weight) in contract_costs
        .iter()
        .filter(|(_, weight)| weight.is_positive())
    {
        weights.push((source.clone(), fixed_int(weight)?));
    }
    if weights.is_empty() {
        return Ok(vec![(contract.to_owned(), whole(1))]);
    }
    Ok(weights)
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
    total: &VmDecimal,
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
    total: &VmDecimal,
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

/// The validator, foundation and developer ratios of the split: each
/// non-negative, together at most 1 (else no rewards: they could pay out
/// more than the fee). The burn share is never paid: it is the part no one
/// is credited, with the truncation dust.
fn paid_ratios(split: &[VmValue]) -> Reward<[VmDecimal; 3]> {
    let ratios = [
        as_decimal(&split[0])?,
        as_decimal(&split[2])?,
        as_decimal(&split[3])?,
    ];
    let paid = sum(&ratios.clone().map(|ratio| ((), ratio)))?;
    if ratios.iter().any(|ratio| ratio.scaled.is_negative()) || paid > whole(1) {
        return invalid();
    }
    Ok(ratios)
}

/// Places the foundation share keeps (rounded down, never up).
const FOUNDATION_PLACES: u32 = 8;

/// `total * ratio`, rounded down to 8 places.
fn foundation_share(ratio: &VmDecimal, total: &VmDecimal) -> Reward<VmDecimal> {
    let share = checked(total.mul(ratio))?;
    let unit = BigInt::from(10u8).pow(30 - FOUNDATION_PLACES);
    Ok(checked(VmDecimal::from_scaled(
        &share.scaled - &share.scaled % unit,
    ))?)
}

/// The reward split, the chain chi rate and the foundation owner, as
/// `_build_tx_reward_outputs` reads them; `None` when no reward is paid.
fn reward_terms(
    rewards: &mut Rewards<'_>,
    total: &VmDecimal,
) -> Reward<Option<(Vec<VmValue>, BigInt, String)>> {
    let Some(split) = reward_split(rewards.var("rewards", "S", &["value"])?)? else {
        return Ok(None);
    };
    if !total.scaled.is_positive() {
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
    //! and test_fee_settlement_corpus.py, seed 20261113), with its outputs as
    //! wire JSON (frozen from the retired Python reference, the rewards
    //! restated for revision 14's ContractingDecimal arithmetic). xian-abci
    //! checks the same cases through the Python bindings; this runs them in
    //! Rust.
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
                number => fixed_int(&int(number)).unwrap(),
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

    /// xorshift64*: a fixed generator, so a failing case reproduces.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
        fn below(&mut self, upper: u64) -> u64 {
            self.next() % upper
        }
        fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
            &items[self.below(items.len() as u64) as usize]
        }
        /// A number a reward input may hold: an int or a decimal of up to 30
        /// places, small to wide, now and then zero or negative.
        fn number(&mut self) -> VmValue {
            let width = *self.pick(&[3u64, 12, 40, 60]);
            let digits = 1 + self.below(width);
            let mut scaled = BigInt::zero();
            for _ in 0..digits {
                scaled = scaled * 10u8 + self.below(10);
            }
            let scaled = if self.below(12) == 0 { -scaled } else { scaled };
            if self.below(2) == 0 {
                VmValue::Int(scaled / BigInt::from(10u8).pow(30))
            } else {
                VmValue::Decimal(VmDecimal::from_scaled(scaled).unwrap())
            }
        }
        /// Four split ratios: mostly in [0, 1] with a sum of at most 1
        /// (sometimes exactly 1 with no burn), now and then out of range.
        fn split(&mut self) -> VmValue {
            let parts: Vec<BigInt> = (0..4)
                .map(|_| BigInt::from(self.below(1_000_000)))
                .collect();
            let sum: BigInt = parts.iter().sum::<BigInt>() + 1u8;
            let scale = BigInt::from(10u8).pow(30);
            let mut ratios: Vec<BigInt> = parts.iter().map(|part| part * &scale / &sum).collect();
            match self.below(6) {
                0 => {
                    let rest = &scale - &ratios[0] - &ratios[2];
                    ratios[1] = BigInt::zero();
                    ratios[3] = rest;
                }
                1 => {
                    let index = self.below(4) as usize;
                    ratios[index] *= 3u8;
                }
                2 => {
                    let index = self.below(4) as usize;
                    ratios[index] *= -1;
                }
                _ => {}
            }
            VmValue::List(
                ratios
                    .into_iter()
                    .map(|ratio| VmValue::Decimal(VmDecimal::from_scaled(ratio).unwrap()))
                    .collect(),
            )
        }
    }

    fn random_state(rng: &mut Rng, index: u64) -> HashMap<String, VmValue> {
        let mut state = HashMap::new();
        let rate = *rng.pick(&[1u64, 3, 7, 20, 2000, 999_983]);
        state.insert("rewards.S:value".to_owned(), rng.split());
        state.insert("chi_cost.S:value".to_owned(), VmValue::Int(rate.into()));
        state.insert("foundation.owner".to_owned(), text("foundation"));
        let validators: Vec<String> = (0..rng.below(5)).map(|n| format!("v{index}_{n}")).collect();
        for validator in &validators {
            state.insert(format!("validators.powers:{validator}"), rng.number());
            let bps = *rng.pick(&[0i64, 1, 500, 3333, 10_000, 12_000, -5]);
            state.insert(
                format!("validators.commission_bps:{validator}"),
                VmValue::Int(bps.into()),
            );
            state.insert(format!("validators.self_bond:{validator}"), rng.number());
            let delegators: Vec<String> = (0..rng.below(4)).map(|n| format!("d{n}")).collect();
            for delegator in &delegators {
                state.insert(
                    format!("validators.delegations:{delegator}:{validator}"),
                    rng.number(),
                );
            }
            state.insert(
                format!("validators.delegator_lists:{validator}"),
                VmValue::List(delegators.iter().map(|name| text(name)).collect()),
            );
        }
        state.insert(
            "validators.active_validators".to_owned(),
            VmValue::List(validators.iter().map(|name| text(name)).collect()),
        );
        for contract in ["con_a", "con_b"] {
            let developer = rng.pick(&["", "sys", "dev_a", "dev_b"]).to_owned();
            state.insert(format!("{contract}.__developer__"), text(&developer));
        }
        state
    }

    #[test]
    fn falsy_validator_lists_are_empty_and_other_values_invalid() {
        let zero = VmValue::Decimal(VmDecimal::zero());
        for falsy in [VmValue::Bool(false), VmValue::Int(0.into()), zero, text("")] {
            assert_eq!(names(Some(falsy)).unwrap(), Vec::<String>::new());
        }
        let one = VmValue::Decimal(fixed_int(&BigInt::from(1)).unwrap());
        for truthy in [VmValue::Bool(true), VmValue::Int(1.into()), one, text("v")] {
            assert!(matches!(names(Some(truthy)), Err(Unpaid::Invalid)));
        }
        assert!(matches!(
            truthy(&VmValue::Bytes(vec![])),
            Err(Unpaid::Invalid)
        ));
    }

    /// Every paid transaction pays out at most its fee: the shares, priced
    /// at the chi rate, never sum to more than `chi / rate` (what the sender
    /// was charged), and no share is negative. What is not paid is burned.
    #[test]
    fn rewards_never_pay_out_more_than_the_charged_fee() {
        let mut rng = Rng(0x5eed_2026_1114);
        let mut paid_cases = 0;
        for index in 0..4000 {
            let mut state = random_state(&mut rng, index);
            let rate = match state["chi_cost.S:value"] {
                VmValue::Int(ref rate) => rate.clone(),
                _ => unreachable!(),
            };
            let total_scaled = BigInt::from(1 + rng.below(10_000_000_000))
                * BigInt::from(10u8).pow(rng.below(31) as u32);
            let total = VmDecimal::from_scaled(total_scaled).unwrap();
            let costs = vec![
                ("con_a".to_owned(), BigInt::from(rng.below(5000))),
                ("con_b".to_owned(), BigInt::from(rng.below(5000))),
            ];
            let rewards =
                tx_reward_outputs(&mut state, &total, "con_a", &costs, rng.below(2) == 0).unwrap();
            if rewards.rewards.is_none() {
                continue;
            }
            paid_cases += 1;
            let fee = total.div(&fixed_int(&rate).unwrap()).unwrap();
            let mut paid = VmDecimal::zero();
            for (key, amount) in &rewards.deltas {
                assert!(!amount.scaled.is_negative(), "case {index}: {key} {amount}");
                paid = paid.add(amount).unwrap();
            }
            assert!(paid <= fee, "case {index}: paid {paid} > fee {fee}");
        }
        assert!(paid_cases > 2000, "{paid_cases}");
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
