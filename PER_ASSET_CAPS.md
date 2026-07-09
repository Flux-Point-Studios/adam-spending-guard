# Guard v2 — per-asset quantity caps (autonomous sell)

> **STATUS: on-chain core done, red-team GREEN — not yet productionized.** Extends
> the pinnable v2. Deployed guard is still v1 on main.

## Goal

Let ADAM autonomously **sell** (not just buy) tokens on mainnet while a fully-
compromised agent key can still only lose a bounded amount. Since a compromised
agent controls the *whole* transaction (including any counterparty), fair-price /
DEX-order enforcement is worthless. Bounds must be **owner-set quantities** (no
oracle).

## Model

- **ADA** — metered vs `per_tx_cap` / `daily_cap` over a sliding window (as v1).
- **Declared tokens** (`token_caps` in the datum) — each metered the SAME way vs
  its own `per_tx` / `daily` **quantity** caps. The agent can buy AND sell them
  (incl. cutting losses — quantity-bounded, not price-bounded).
- **Undeclared tokens** — may be acquired but **never leave** the guard on the
  agent branch (`conserve_undeclared`).

A compromised key moves at most `daily` of each declared token per window and
**nothing** undeclared.

## Datum

```
GuardDatum {
  owner, stt_policy, agent,
  per_tx_cap, daily_cap, window_len,           // ADA + shared window
  token_caps: [ {policy, name, per_tx, daily} ],   // owner-declared tradeable tokens
  spends:     [ {policy, name, at, amount} ],       // unified: ADA (policy=name="") + per-token
  min_principal, max_spends, expiry, kill,
}
```

## Canonical `spends` reconstruction (tx-builder MUST match, for `datum_ok`)

```
active       = [ r in datum.spends | r.at + window_len >= hi - max_skew ]   // prune, order preserved
ada_records  = [ {"", "", hi, ada_outflow} ]  if ada_outflow > 0  else []
token_records= for cap in token_caps, in order: [ {cap.policy, cap.name, hi, outflow} ] if outflow > 0
new_spends   = ada_records ++ token_records ++ active
```

## Red-team

`aiken-validator-redteam` on the per-asset validator (token_exfil, value, mint,
continuation, composed, double_sat + novel): **GREEN — 0 confirmed.** Probed:
selling above a cap via record mislabeling, recording a token move as ADA,
splitting a token across cont + a steal output, cross-token cap confusion,
duplicate/overlapping caps, undeclared exfiltration, the combined-spends
reconstruction. All defended. (The only claims were the known fast-forward-hi
window artifact — correctly refuted under ledger-consistency.) Baseline: 10/10.

## Productionization (remaining)

1. Port the full v1 48-suite onto the per-asset datum; one more red-team on the final.
2. Gateway/provisioning sets `token_caps`; owner flow to add/adjust tradeable tokens (OwnerSpend).
3. AdamKit / attestation: pin+verify `token_caps` in the datum (still hash-only).
4. tx-builder: compute the canonical `spends` reconstruction above; never add a 2nd guard-address input.
5. Ship the productionized `plutus.json` (pinned guard hash + STT policy).
