# ADAM Spending-Guard

Plutus V3 (Aiken) validator for **opt-in bounded-autonomy trading**. Funds live
at a per-user script address; the **owner** (phone key) has unrestricted control,
while a delegated **agent** session key may spend only within on-chain limits —
capped net ADA outflow per transaction and per rolling window, a principal floor,
a hard expiry, and an owner kill switch. The ledger, not any off-chain policy, is
the boundary.

> This repository is packaged for **independent security audit**. Start with
> [`THREAT_MODEL.md`](./THREAT_MODEL.md) — it states the guarantees, trust
> boundaries, every on-chain invariant with its enforcing clause, the attack
> classes considered, and what is explicitly out of scope.

## Layout

| Path | Contents |
|------|----------|
| `validators/guard.ak` | Spending validator (entry point) |
| `lib/guard/logic.ak` | All spend-decision logic (owner branch + 12-check agent branch) |
| `lib/guard/types.ak` | `GuardDatum`, `SpendRecord`, `GuardRedeemer` |
| `validators/state_token.ak` | One-shot state-thread-token minting policy (singleton authentication) |
| `validators/guard_test.ak` | Adversarial test suite (assumes a fully compromised agent) |
| `plutus.json` | Committed compiled blueprint (the artifact deployments fund) |

The decision logic is factored into `lib/guard/logic.ak` so the test suite
exercises the **exact** deployed code.

## Build & test

```sh
aiken check      # type-check + run the full adversarial test suite
aiken build      # compile to plutus.json (should match the committed blueprint)
```

Pinned toolchain: **Aiken v1.1.23**, Plutus **V3** (`aiken.toml`); dependencies
pinned in `aiken.lock` (aiken-lang/stdlib v3.1.0). CI runs `aiken check` on every
push (`.github/workflows/`).

## Trust model in one line

A fully compromised agent key can lose at most `daily_cap` ADA per rolling
`window_len`, never the principal below `min_principal`, never faster than the
cap — and the owner can sweep everything back at any time with only their own
signature, even if the operator is offline. See `THREAT_MODEL.md`.

## License

Apache-2.0.
