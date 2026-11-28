//! Read-only CheckTx admission against one committed LMDB transaction.
use crate::lmdb_env::{LmdbEnv, LmdbError, Txn};
use crate::settlement::{fixed_int, Balance};
use crate::stored_value::decode_stored_value;
use crate::tx_rewards::{valid_chi_rate, CHI_RATE_KEY};
use crate::values::{decimal_scale_factor, VmDecimal, VmValue};
use num_bigint::BigInt;
use serde_json::Value;

type Decision = Result<(), String>;

/// An ambiguous stored value or amount is left to the application, which
/// defines how to report irregular state and non-numeric inputs.
pub(crate) fn check(
    document: &Value,
    environment: &LmdbEnv,
    max_chi: Option<u64>,
    require_balance: bool,
) -> Option<Decision> {
    let payload = &document["payload"];
    let sender = payload["sender"].as_str()?;
    let nonce = payload["nonce"].as_u64()?;
    let supplied = payload["chi_supplied"].as_u64()?;
    environment
        .read(|state| {
            // A native cache hit proves only the legacy static signature. The
            // decision to accept it must come from the same current snapshot.
            let policy = state.get(crate::account_policy::POLICY_KEY.as_bytes())?;
            let legacy_allowed = policy.is_none_or(|bytes| {
                decode_stored_value(bytes)
                    .is_ok_and(|v| crate::account_policy::allows_classical(Some(&v)))
            });
            if !legacy_allowed
                || state
                    .get(crate::account_policy::record_key(sender).as_bytes())?
                    .is_some()
            {
                return Ok(Some(Err(
                    "Account authorization requires hybrid signatures".into(),
                )));
            }
            let Some(nonce_check) = check_nonce(state, sender, nonce)? else {
                return Ok(None);
            };
            let eligibility = nonce_check.and_then(|()| check_chi(supplied, max_chi));
            if eligibility.is_err() || !require_balance {
                return Ok(Some(eligibility));
            }
            let balance = read_value(state, &format!("currency.balances:{sender}"))?;
            let rate = read_value(state, CHI_RATE_KEY)?;
            Ok(check_affordability(payload, balance, rate, supplied))
        })
        .ok()
        .flatten()
}

fn read_value(state: &Txn<'_>, key: &str) -> Result<Option<VmValue>, LmdbError> {
    Ok(match state.get(key.as_bytes())? {
        Some(raw) => decode_stored_value(raw).ok(),
        None => Some(VmValue::None),
    })
}

fn check_nonce(state: &Txn<'_>, sender: &str, nonce: u64) -> Result<Option<Decision>, LmdbError> {
    // This is the committed key written by ABCI NonceStorage.key.
    Ok(match read_value(state, &format!("__n.{sender}:"))? {
        Some(VmValue::None) => Some(Ok(())),
        Some(VmValue::Int(latest)) => {
            if BigInt::from(nonce) > latest {
                Some(Ok(()))
            } else {
                Some(Err(format!(
                    "Transaction nonce is invalid. Must be greater than {latest}, got {nonce}"
                )))
            }
        }
        _ => None,
    })
}

fn check_chi(supplied: u64, max_chi: Option<u64>) -> Decision {
    let Some(limit) = max_chi else {
        return Ok(());
    };
    if supplied == 0 {
        return Err("Transaction chi_supplied must be greater than zero".into());
    }
    if supplied > limit {
        return Err(format!(
            "Transaction chi_supplied {supplied} exceeds the chain's per-transaction limit of {limit} chi"
        ));
    }
    Ok(())
}

fn check_affordability(
    payload: &Value,
    balance: Option<VmValue>,
    rate: Option<VmValue>,
    supplied: u64,
) -> Option<Decision> {
    let balance = Balance::of(Some(&balance?)).ok()?;
    let rate = valid_chi_rate(rate?)?;
    let transfer = amount_to_check(payload)?;
    check_payment(balance, &rate, &BigInt::from(supplied), transfer)
}

fn amount_to_check(payload: &Value) -> Option<Option<Balance>> {
    let is_transfer = payload["contract"] == "currency" && payload["function"] == "transfer";
    let amount = &payload["kwargs"]["amount"];
    if is_transfer {
        transfer_amount(amount).map(Some)
    } else if amount.is_object() {
        // The reference path decodes wrapped amount values for other calls too.
        None
    } else {
        Some(None)
    }
}

fn check_payment(
    balance: Balance,
    rate: &BigInt,
    supplied: &BigInt,
    transfer: Option<Balance>,
) -> Option<Decision> {
    if !can_pay(&balance, rate, supplied)? {
        return Some(Err(
            "Transaction sender's balance cannot cover the chi_supplied fee reservation".into(),
        ));
    }
    if let Some(amount) = transfer {
        let remaining = subtract(balance, amount)?;
        if !can_pay(&remaining, rate, supplied)? {
            return Some(Err(
                "currency.transfer amount plus the chi_supplied fee reservation exceeds the sender's balance"
                    .into(),
            ));
        }
    }
    Some(Ok(()))
}

fn transfer_amount(value: &Value) -> Option<Balance> {
    if value.is_null() {
        return Some(Balance::Int(BigInt::ZERO));
    }
    if let Some(integer) = value.as_i64() {
        return Some(Balance::Int(BigInt::from(integer)));
    }
    let wire = serde_json::to_vec(value).ok()?;
    let decoded = decode_stored_value(&wire).ok()?;
    Balance::of(Some(&decoded)).ok()
}

fn can_pay(balance: &Balance, rate: &BigInt, supplied: &BigInt) -> Option<bool> {
    match balance {
        Balance::Int(balance) => Some(balance * rate >= *supplied),
        Balance::Fixed(balance) => {
            let priced = VmDecimal::from_scaled(&balance.scaled * rate).ok()?;
            Some(priced.scaled >= supplied * decimal_scale_factor())
        }
    }
}

fn subtract(balance: Balance, amount: Balance) -> Option<Balance> {
    let remaining = match (balance, amount) {
        (Balance::Int(balance), Balance::Int(amount)) => {
            return Some(Balance::Int(balance - amount));
        }
        (balance, Balance::Int(amount)) => balance.minus(&fixed_int(&amount).ok()?),
        (balance, Balance::Fixed(amount)) => balance.minus(&amount),
    };
    remaining.ok().map(Balance::Fixed)
}
