//// ADAM spending-guard v2 (Plutus V3) — pinnable bounded-autonomy vault.
////
//// UNPARAMETERIZED: the script hash (and thus the address) is fixed, so a client
//// can PIN it by hashing the compiled code — no apply_params applicator needed.
//// The owner key and the STT policy id live in the datum, so the client verifies
//// `datum.owner == my key` + caps by reading the datum. The OWNER key has
//// unrestricted control; the AGENT session key may spend only within on-chain
//// caps (net ADA outflow per tx and per rolling window, principal floor, expiry,
//// kill switch, datum-invariance, STT singleton). Logic in lib/guard/logic.ak.

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
    expect Some(datum) = datum_opt
    logic.spend_ok(datum, redeemer, own_ref, tx)
  }

  else(_) {
    fail
  }
}
