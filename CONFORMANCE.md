# STT-name conformance vectors

The ADAM guard v2 uses a **universal, unparameterized** state-thread token
(`validators/state_token.ak`). Its *policy id* is fixed (so a client can pin it by
hashing the compiled code — no `apply_params`), and per-guard uniqueness comes from
the token **name**:

```
name = blake2b_256( cbor.serialise(genesis_out_ref) )
```

where `genesis_out_ref` is the `OutputReference` of a UTxO consumed in the mint tx.
That UTxO can be spent only once, so each name can be minted only once (one-shot).

An off-chain host (the Gero iOS wallet) attests a guard **hash-only**: it pins the
guard script hash + STT policy id, reads the datum, and checks `datum.owner == myKey`.
To also verify the STT is *this guard's* singleton it must recompute the name — which
means reproducing `cbor.serialise(OutputReference)` **byte-for-byte**. This file is
that interop contract.

## Encoding

`OutputReference { transaction_id: Hash<Blake2b_256, Transaction>, output_index: Int }`
serialises as Plutus `Data` — constructor 0 with an **indefinite-length** field array:

```
D8 79              tag 121            (constructor index 0)
9F                 array(*)           INDEFINITE-length   <-- NOT 0x82 definite
  58 20 <32 bytes> bytestring(32)     transaction_id
  <uint>           unsigned int       output_index (canonical CBOR uint)
FF                 break
```

### ⚠️ The two traps

1. **Indefinite array.** Aiken's `cbor.serialise` emits `9F … FF`, *not* a definite
   `82 …` array. Hashing the definite form yields the wrong name.
2. **It is Plutus `Data`, not a CSL `TransactionInput`.**
   `cardano-serialization-lib` serialises a `TransactionInput` as a bare 2-array
   `[bytes, index]` with **no** constructor tag. You must instead build a
   `PlutusData::ConstrPlutusData(alt=0, [Bytes(txid), Int(index)])` and ensure it
   encodes the field list as an **indefinite** array. Verify against the vectors
   below before trusting any name check.

The `output_index` is a canonical CBOR unsigned integer, so its width changes with
magnitude (`0x00`, `0x18 18` for 24, `0x19 01 00` for 256, …). The vectors cover
these transitions.

## Vectors

Each row is asserted (bytes **and** name) by `validators/stt_name_conformance_test.ak`,
which runs under `aiken check` — so these values are ground truth from the toolchain,
not hand-derived.

| tx id (32 bytes) | index | `cbor.serialise(out_ref)` | `blake2b_256` name |
|---|---|---|---|
| `1111111111111111111111111111111111111111111111111111111111111111` | 0 | `d8799f5820111111111111111111111111111111111111111111111111111111111111111100ff` | `56664296ffc0310952b2bc81548beb7512c002c4ffac4dea24041ad10ac40fdd` |
| `1111111111111111111111111111111111111111111111111111111111111111` | 1 | `d8799f5820111111111111111111111111111111111111111111111111111111111111111101ff` | `e6b82f9f17464ed2994ea77bb177f40868f65b48bf290ff060e001cd3000a616` |
| `de1dc0ffee0badf00dcafe0000feed00badc0ffee0dea1beefdeadbeef123456` | 7 | `d8799f5820de1dc0ffee0badf00dcafe0000feed00badc0ffee0dea1beefdeadbeef12345607ff` | `cdbee5715b253d5c1cae1454545c401c7aa349fb389f0c4ec281d3182b1eb1bd` |
| `0000000000000000000000000000000000000000000000000000000000000000` | 24 | `d8799f582000000000000000000000000000000000000000000000000000000000000000001818ff` | `d85cc298557426f945643e89a5efa048b7bed47870001b782a3a9e839cd1980c` |
| `ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` | 256 | `d8799f5820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff190100ff` | `342691bdfe783a0be69087fedb4a2a0c4aa906f37273eb91866f5e01b3fa509d` |

## Reproduce / regenerate

```
aiken check -m stt_name        # runs the conformance tests
```

To (re)derive independently — e.g. to cross-check a host implementation — the
reference bytes above were produced by `blake2b_256` over the CBOR shown; any Plutus
`Data` encoder that matches the "Encoding" section will reproduce them.

When the guard is productionized, add one row per real genesis outref if desired; the
encoding itself is stable across stdlib v3.x.

---

# GuardDatum CBOR

The guard's inline datum is a `GuardDatum` (`lib/guard/types.ak`). The client
(Gero iOS wallet / AdamKit) must **decode** it byte-for-byte to attest owner + caps,
and the tx-builder must **reproduce** the continuation datum exactly — the validator's
`datum_ok` check in `lib/guard/logic.ak` is a *full structural equality*
(`cont_datum == GuardDatum { ..datum, spends: new_spends }`), so any mis-encoded field
fails the spend. This section is that encoding contract; it is pinned by
`validators/datum_cbor_conformance_test.ak`.

## Constructor / field encoding

`GuardDatum` is a Constr-0 record. `cbor.serialise` emits it as:

```
D8 79              tag 121            (constructor index 0)
9F  …  FF          array(*)           INDEFINITE-length field array (NOT definite 8C)
```

The **12 fields appear in exactly the `types.ak` declaration order** — the client MUST
emit them in this order:

| # | field | type | CBOR shape |
|---|---|---|---|
| 1 | `owner` | `VerificationKeyHash` (28-byte VKH) | `58 1C <28 bytes>` |
| 2 | `stt_policy` | `PolicyId` (28-byte hash) | `58 1C <28 bytes>` |
| 3 | `agent` | `VerificationKeyHash` (28-byte VKH) | `58 1C <28 bytes>` |
| 4 | `per_tx_cap` | `Int` (ADA/lovelace per-tx cap) | canonical uint |
| 5 | `daily_cap` | `Int` (ADA/lovelace daily cap) | canonical uint |
| 6 | `window_len` | `Int` (ms) | canonical uint |
| 7 | `token_caps` | `List<AssetCap>` | `9F <AssetCap…> FF` (see below) |
| 8 | `spends` | `List<SpendRecord>` | `9F <SpendRecord…> FF` (see below) |
| 9 | `min_principal` | `Int` (ADA floor, lovelace) | canonical uint |
| 10 | `max_spends` | `Int` | canonical uint |
| 11 | `expiry` | `Int` (POSIX ms) | canonical uint |
| 12 | `kill` | `Bool` | `D8 79 80` (False) / `D8 7A 80` (True) |

### Nested records

Each **`AssetCap`** ( `{ policy, name, per_tx, daily }` ) and each **`SpendRecord`**
( `{ policy, name, at, amount }` ) is *itself* a Constr-0 record — `D8 79 9F … FF` —
with its fields in declaration order.

### ADA sentinel: empty bytestring `0x40`

ADA (lovelace) records and caps use the **empty bytestring** for policy **and** name.
The empty bytestring is CBOR `0x40` (major type 2, length 0) — **not** `0x00`, **not**
`0xF6`/null. So an ADA `SpendRecord` begins `D8 79 9F 40 40 …`.

### ⚠️ The trap: empty constructors are DEFINITE

An empty-argument constructor does **not** serialise as `9F FF`. Aiken emits it in the
**definite empty form** — tag + `0x80` (definite array, length 0):

```
kill = False   ->   D8 79 80     (Constr 0, [])     NOT  D8 79 9F FF
kill = True    ->   D8 7A 80     (Constr 1, [])
```

`D8 79 80` reuses tag `121` for constructor index 0; `D8 7A 80` is tag `122` for
index 1. A client that emits `9F FF` for an empty constructor (or for an empty
`token_caps`/`spends` — but note those are *lists*, which DO use `9F FF`, so only true
`[]` **constructors** like `Bool` hit this) will produce a datum that fails the
on-chain equality. Empty **lists** (`token_caps: []`, `spends: []`) serialise as the
definite empty *array* `80` as well — an empty indefinite `9F FF` is not what Aiken
emits for an empty list either. Match the pinned vectors before trusting an encoder.

## Worked byte-map (pinned vector)

The vector below is asserted by `validators/datum_cbor_conformance_test.ak`
(`test datum_cbor_vector`) under `aiken check`, so it is ground truth from the
toolchain. The sample datum: `per_tx_cap=20_000_000`, `daily_cap=50_000_000`,
`window_len=86_400_000`, one declared `AssetCap{policy=…1111, name="TKN", per_tx=500,
daily=1000}`, a two-record `spends` (an ADA record `10_000_000` + a `"TKN"` token
record `300`, both stamped `at=1_000_000_060_000`), `min_principal=5_000_000`,
`max_spends=10`, `expiry=2_000_000_000_000`, `kill=False`.

```
d8799f                                     GuardDatum = Constr 0, [
  581c 00…000a0a                             owner        (28-byte VKH)
  581c 5c48f601…c7d80704                      stt_policy   (28-byte PolicyId = pinned STT)
  581c 00…000b0b                             agent        (28-byte VKH)
  1a01312d00                                 per_tx_cap   20_000_000
  1a02faf080                                 daily_cap    50_000_000
  1a05265c00                                 window_len   86_400_000
  9f                                         token_caps = [
    d8799f                                     AssetCap = Constr 0, [
      581c 00…001111                             policy   (28-byte)
      43 544b4e                                  name     bytestring(3) "TKN"
      1901f4                                     per_tx   500
      1903e8                                     daily    1000
    ff                                         ]
  ff                                         ]
  9f                                         spends = [
    d8799f                                     SpendRecord = Constr 0, [
      40                                           policy   empty bytestring  -> ADA
      40                                           name     empty bytestring  -> ADA
      1b000000e8d4a5fa60                           at       1_000_000_060_000
      1a00989680                                   amount   10_000_000
    ff                                         ]
    d8799f                                     SpendRecord = Constr 0, [
      581c 00…001111                               policy   (28-byte)
      43 544b4e                                    name     "TKN"
      1b000000e8d4a5fa60                           at       1_000_000_060_000
      19012c                                       amount   300
    ff                                         ]
  ff                                         ]
  1a004c4b40                                 min_principal 5_000_000
  0a                                         max_spends    10
  1b000001d1a94a2000                         expiry        2_000_000_000_000
  d87980                                     kill          Constr 0 []  = False   <-- DEFINITE empty
ff                                         ]
```

Full pinned bytes (`cbor.serialise(sample_datum)`):

```
d8799f581c00000000000000000000000000000000000000000000000000000a0a581c5c48f6
01de2cf0a92d20f351e89704ec85871fafff310cebc7d80704581c000000000000000000000000
00000000000000000000000000000b0b1a01312d001a02faf0801a05265c009fd8799f581c0000
0000000000000000000000000000000000000000000000111143544b4e1901f41903e8ffff9fd8
799f40401b000000e8d4a5fa601a00989680ffd8799f581c0000000000000000000000000000000
0000000000000000000111143544b4e1b000000e8d4a5fa6019012cffff1a004c4b400a1b000001
d1a94a2000d87980ff
```

(One contiguous hex string — line-wrapped here only for display; see the test file for
the unwrapped literal.)

---

# Client attestation checklist (4 parts)

The host trusts a guard **hash-only** (no `apply_params` — the validator is one
universal, pinnable script). To attest that a given guard UTxO is a genuine ADAM guard
bound to *this* user with *this* consented cap set, compute all four:

1. **Pin guard scriptHash** — hash the committed compiled guard code from the
   per-asset `plutus.json` and require it equals
   `ecb3ce037188879d7fea47aa5e7eb4cbb1e24479816bf439e57acbc6`. The guard UTxO must sit
   at this script address.

2. **Pin STT policyId** — hash the committed compiled `state_token` code from
   `plutus.json` and require it equals
   `5c48f601de2cf0a92d20f351e89704ec85871fafff310cebc7d80704`. This is the universal
   STT policy for *all* guards.

3. **Recompute the STT name** — apply the STT-name rule
   `blake2b_256(cbor.serialise(genesis_out_ref))` for the guard's genesis outref and
   require the guard UTxO carries exactly one token `(stt_policyId, name)` of quantity
   1. Reproduce `cbor.serialise(OutputReference)` per the "STT-name conformance
   vectors" section above (indefinite array; Plutus `Data`, not CSL). This binds the
   singleton to *this* guard, not just to the shared policy.

4. **Decode the GuardDatum + verify ownership and consent** — decode the inline datum
   per the "GuardDatum CBOR" section above and check
   `datum.owner == myKey` **and** `datum.token_caps == the user-consented set`
   (same policies/names/per_tx/daily the user actually approved). Also sanity-check
   `datum.stt_policy` equals the pinned STT policyId from step 2.

> Threat-model note (fable F-3, LOW, carried forward by design): the guard's
> `no_stt_mint` check pins only its own STT name, so the *singleton* invariant of the
> universal STT policy relies on the **separate, audited `state_token` one-shot minting
> policy** — not on the guard alone. Step 3 (recompute + require quantity 1) is what
> ties the guard you are attesting to a genuine one-shot mint.

---

# Canonical `spends` reconstruction (tx-builder MUST reproduce)

Because `datum_ok` is a full structural equality, the tx-builder's continuation datum
must equal the input datum with **only `spends` changed** — every other field
(owner, stt_policy, agent, all caps, token_caps, min_principal, max_spends, expiry,
kill) is copied verbatim. The new `spends` list is built by exactly this rule (from
`agent_spend_ok` / `meter_tokens` in `lib/guard/logic.ak`):

```
new_spends =
    [ SpendRecord{ "", "", now, ada_outflow } ]        if ada_outflow > 0     (ADA leg first)
 ++ [ SpendRecord{ cap.policy, cap.name, now, outflow } for each token_caps entry
        with outflow > 0, IN token_caps ORDER ]                                (declared-token legs)
 ++ pruned_active                                                              (surviving prior records)
```

Definitions the builder must match bit-for-bit:

- **`now = hi`** — the tx validity-range **upper** bound (`Finite(hi)`). This is the
  window clock; it is ledger-consistent (a tx is only accepted when the real slot is in
  `[lo, hi]` with `hi - lo <= max_skew`), so there is no on-chain fast-forward drain.
- **`ada_outflow = lovelace_of(guard_in) - lovelace_of(cont)`** — an ADA record is
  emitted only when `ada_outflow > 0`.
- **`outflow = quantity_of(guard_in, cap.policy, cap.name) - quantity_of(cont, …)`**
  per declared token — a record is emitted only when its `outflow > 0`, and the records
  appear in `token_caps` declaration order (not input/output order).
- **Prune predicate** for `pruned_active`: keep record `r` iff
  `r.at + window_len >= now - max_skew`, with **`max_skew = 180_000` ms**
  (`lib/guard/logic.ak`). Records older than the trailing window are dropped.
- **Single guard input.** The validator does `expect [guard_in]` — there must be
  **exactly one** input at the universal guard script address. The tx-builder must
  **NEVER** add a second input at the guard address (fail-closed liveness caveat;
  the shared-address double-satisfaction defense depends on it — regressioned in
  `guard_redteam_test.ak`).
- **Continuation asset bound.** The continuation may carry at most `max_assets = 20`
  distinct non-ADA assets (`assets_ok`).
- **Count bound.** `list.length(new_spends) <= datum.max_spends` (`count_ok`).

Undeclared tokens are **acquire-only**: `conserve_undeclared` requires every non-ADA,
non-STT, non-declared input asset to remain on the continuation at `>=` its input
quantity. This (with `token_caps` metering) is what closes fable's F-1/F-2
exfiltration findings — proven rejected in `validators/security_findings_test.ak`.
There is no oracle: a fully-compromised agent controls the whole tx, so
counterparty/DEX-ratio enforcement is void; only the owner-set **quantities** bound the
loss (the agent can cut losses quantity-bounded, never price-bounded, and can never
move more of any asset out than the owner declared, nor touch the STT or the ADA floor
`min_principal`).
