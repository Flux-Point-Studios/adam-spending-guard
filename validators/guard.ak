//// ADAM spending-guard v2 (Plutus V3) — pinnable bounded-autonomy vault.
////
//// UNPARAMETERIZED: the script hash (and thus the address) is fixed, so a client
//// can PIN it by hashing the compiled code — no apply_params applicator needed.
//// The owner key lives in the datum, so the client verifies `datum.owner == my
//// key` + caps by reading the datum. The OWNER key has unrestricted control of
//// the funds; the AGENT session key may spend only within on-chain caps (net ADA
//// outflow per tx and per rolling window, principal floor, expiry, kill switch,
//// datum-invariance, STT singleton). Logic in lib/guard/logic.ak.
////
//// The same script is the one-shot state-token (STT) policy, so the policy id is
//// the guard's script hash: name = blake2b_256(cbor.serialise(genesis ref)) of a
//// UTxO consumed in the mint tx, exactly one token per mint, burn is -1.

use cardano/assets.{PolicyId}
use cardano/transaction.{OutputReference, Transaction}
use guard/logic
use guard/types.{GuardDatum, GuardRedeemer}

validator guard {
  spend(
    datum_opt: Option<GuardDatum>,
    redeemer: GuardRedeemer,
    own_ref: OutputReference,
    tx: Transaction,
  ) {
    logic.guard_spend_ok(datum_opt, redeemer, own_ref, tx)
  }

  mint(_redeemer: Data, policy_id: PolicyId, tx: Transaction) {
    logic.mint_ok(policy_id, tx)
  }

  else(_) {
    fail
  }
}
