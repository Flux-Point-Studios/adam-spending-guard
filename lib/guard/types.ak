use aiken/crypto.{VerificationKeyHash}

/// One recorded net-ADA outflow on the agent branch, stamped with the tx's
/// window clock (`now`). The rolling daily cap is enforced over the set of
/// records still inside the trailing `window_len`.
pub type SpendRecord {
  at: Int,
  amount: Int,
}

/// Mutable guard state, carried as the inline datum on the singleton guard UTxO.
///
/// Config fields (agent, caps, window_len, min_principal, max_spends, expiry,
/// kill) are OWNER-controlled invariants: the agent branch must forward them
/// unchanged. Only `spends` may change on the agent branch, and only by pruning
/// aged-out records and prepending the current one per the sliding-window rule.
pub type GuardDatum {
  /// Server session key hash — the bounded (agent) authority.
  agent: VerificationKeyHash,
  /// Max net ADA (lovelace) outflow the guard may lose in a single agent tx.
  per_tx_cap: Int,
  /// Max cumulative net ADA outflow over ANY trailing `window_len` interval.
  daily_cap: Int,
  /// Sliding window length in POSIX ms (e.g. 86_400_000 = 24h).
  window_len: Int,
  /// Active outflow records within the current window (state). Newest first.
  spends: List<SpendRecord>,
  /// The guard's continuing output must keep at least this much ADA; below it
  /// the agent branch is disabled (a defined, owner-sweepable state).
  min_principal: Int,
  /// Upper bound on the active record list — caps datum growth and rate-limits
  /// by count as well as value.
  max_spends: Int,
  /// POSIX ms hard session expiry; after this only the owner branch spends.
  expiry: Int,
  /// Owner-flipped kill switch; True disables the agent branch entirely.
  kill: Bool,
}

pub type GuardRedeemer {
  /// Unrestricted root branch (owner/phone signature). Retune / revoke / sweep.
  OwnerSpend
  /// Bounded branch (agent session key). Allowed only within the on-chain caps.
  AgentSpend
}
