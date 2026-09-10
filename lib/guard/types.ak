use aiken/crypto.{VerificationKeyHash}
use cardano/assets.{PolicyId}

/// A metered outflow record. `policy == "" && name == ""` denotes ADA (lovelace);
/// otherwise it is the (policy, name) of a declared token. `amount` is the net
/// quantity that left the guard, stamped `at` the tx's window clock.
pub type SpendRecord {
  policy: ByteArray,
  name: ByteArray,
  at: Int,
  amount: Int,
}

/// Owner-declared per-token cap (QUANTITY, not value — no oracle). The agent may
/// move at most `per_tx` of this token out in one tx and `daily` over the sliding
/// `window_len`. Immutable to the agent (datum-invariance).
pub type AssetCap {
  policy: ByteArray,
  name: ByteArray,
  per_tx: Int,
  daily: Int,
}

/// Mutable guard state (inline datum on the singleton guard UTxO). v2 pinnable +
/// per-asset caps: `owner` and `stt_policy` in the datum for hash-only client
/// attestation; `token_caps` declares the tradeable-token set + quantity limits.
/// Only `spends` changes on the agent branch — every other field is an
/// owner-controlled invariant.
pub type GuardDatum {
  owner: VerificationKeyHash,
  stt_policy: PolicyId,
  agent: VerificationKeyHash,
  /// ADA (lovelace) caps + the shared sliding window (ms).
  per_tx_cap: Int,
  daily_cap: Int,
  window_len: Int,
  /// Declared tradeable tokens the agent may SELL, each quantity-capped. Tokens
  /// NOT listed here can be acquired but never leave the guard on the agent branch.
  token_caps: List<AssetCap>,
  /// Unified sliding-window records: ADA (policy/name = "") + one per declared
  /// token, newest first.
  spends: List<SpendRecord>,
  min_principal: Int,
  max_spends: Int,
  expiry: Int,
  kill: Bool,
}

pub type GuardRedeemer {
  OwnerSpend
  AgentSpend
}
