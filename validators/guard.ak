//// ADAM spending-guard (Plutus V3) — an opt-in bounded-autonomy vault.
////
//// Funds live at this script address. The OWNER key (phone) has unrestricted
//// control; a delegated AGENT session key may spend ONLY within on-chain
//// limits. The ledger — not the off-chain policy — is the boundary.
////
//// The property is bounded via ECONOMIC CONSERVATION, not a destination
//// allow-list: the agent branch caps the NET ADA that may LEAVE the guarded
//// position per tx and per rolling window, and forces the continuing output
//// back to the guard. Whatever the agent does (any DEX, any counterparty), the
//// guard can only lose <= per_tx_cap / <= daily_cap of ADA, and trade proceeds
//// land back in the guard — a compromised agent cannot launder to its own
//// address, because that would drop the continuing value below the cap.
////
//// Logic lives in lib/guard/logic.ak so the adversarial test suite exercises
//// the exact same code.

use aiken/crypto.{VerificationKeyHash}
use cardano/assets.{AssetName, PolicyId}
use cardano/transaction.{OutputReference, Transaction}
use guard/logic
use guard/types.{GuardDatum, GuardRedeemer}

validator guard(
  owner: VerificationKeyHash,
  stt_policy: PolicyId,
  stt_name: AssetName,
) {
  spend(
    datum_opt: Option<GuardDatum>,
    redeemer: GuardRedeemer,
    own_ref: OutputReference,
    tx: Transaction,
  ) {
    expect Some(datum) = datum_opt
    logic.spend_ok(owner, stt_policy, stt_name, datum, redeemer, own_ref, tx)
  }

  else(_) {
    fail
  }
}
