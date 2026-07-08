use aiken/crypto.{VerificationKeyHash}
use cardano/assets.{PolicyId}

pub type SpendRecord {
  at: Int,
  amount: Int,
}

/// Mutable guard state (inline datum on the singleton guard UTxO).
///
/// v2: `owner` and `stt_policy` moved INTO the datum so a client can attest the
/// guard hash-only — pin the (unparameterized) guard address + STT policy id,
/// then verify `owner == my key` and the caps by reading the datum, with no
/// apply_params. All fields except `spends` are OWNER-controlled invariants the
/// agent branch must forward unchanged.
pub type GuardDatum {
  /// Owner (phone) key — unconditional root authority; verified by the client.
  owner: VerificationKeyHash,
  /// The universal STT policy id authenticating this guard's singleton UTxO.
  stt_policy: PolicyId,
  /// Server session key hash — the bounded (agent) authority.
  agent: VerificationKeyHash,
  per_tx_cap: Int,
  daily_cap: Int,
  window_len: Int,
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
