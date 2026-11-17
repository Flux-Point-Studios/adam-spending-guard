//// Opening-datum audit, 2026-11-17. The guard is its own state-token policy, so
//// `stt_policy` below is both the policy id and the guard script hash. Each
//// `fail` test is a mint or spend that must be refused, the plain tests are the
//// honest openings, retunes, exits and burns that must keep passing.

use aiken/builtin
use aiken/cbor
use aiken/collection/dict
use aiken/collection/list
use aiken/crypto.{blake2b_256}
use aiken/interval
use cardano/address
use cardano/assets.{Value}
use cardano/transaction.{
  DatumHash, InlineDatum, Input, NoDatum, Output, OutputReference, Transaction,
}
use guard as guard_validator
use guard/types.{
  AgentSpend, AssetCap, GuardDatum, GuardRedeemer, OwnerSpend, SpendRecord,
}

const owner_key: ByteArray =
  #"0000000000000000000000000000000000000000000000000000000a"

const agent_key: ByteArray =
  #"0000000000000000000000000000000000000000000000000000000b"

const stt_policy: ByteArray =
  #"00000000000000000000000000000000000000000000000000000abc"

const other_policy: ByteArray =
  #"00000000000000000000000000000000000000000000000000000abd"

const other_script: ByteArray =
  #"00000000000000000000000000000000000000000000000000000ddd"

const tok_name: ByteArray =
  #"7777777777777777777777777777777777777777777777777777777777777777"

const genesis_tx_id: ByteArray =
  #"4444444444444444444444444444444444444444444444444444444444444444"

const hi: Int = 1_000_000_060_000

// ── Opening fixtures ────────────────────────────────────────────────────────

fn genesis_ref() -> OutputReference {
  OutputReference { transaction_id: genesis_tx_id, output_index: 3 }
}

fn stt_name() -> ByteArray {
  blake2b_256(cbor.serialise(genesis_ref()))
}

fn genesis() -> Input {
  Input {
    output_reference: genesis_ref(),
    output: Output {
      address: address.from_verification_key(owner_key),
      value: assets.from_lovelace(200_000_000),
      datum: NoDatum,
      reference_script: None,
    },
  }
}

fn guard_address() -> address.Address {
  address.from_script(stt_policy)
}

/// A 28-byte policy id distinct for each `i` in 1..255.
fn pol(i: Int) -> ByteArray {
  builtin.cons_bytearray(
    i,
    #"000000000000000000000000000000000000000000000000000000",
  )
}

fn cap(i: Int) -> AssetCap {
  AssetCap { policy: pol(i), name: tok_name, per_tx: 500, daily: 1000 }
}

fn caps(n: Int) -> List<AssetCap> {
  if n == 0 {
    []
  } else {
    [cap(n), ..caps(n - 1)]
  }
}

fn records(n: Int, at: Int) -> List<SpendRecord> {
  if n == 0 {
    []
  } else {
    [
      SpendRecord { policy: pol(n % 10 + 1), name: tok_name, at, amount: 1 },
      ..records(n - 1, at)
    ]
  }
}

fn opening() -> GuardDatum {
  GuardDatum {
    owner: owner_key,
    stt_policy,
    agent: agent_key,
    per_tx_cap: 20_000_000,
    daily_cap: 50_000_000,
    window_len: 86_400_000,
    token_caps: [cap(1)],
    spends: [],
    min_principal: 5_000_000,
    max_spends: 10,
    expiry: 2_000_000_000_000,
    kill: False,
  }
}

fn stt_value(ada: Int) -> Value {
  assets.from_lovelace(ada) |> assets.add(stt_policy, stt_name(), 1)
}

fn guard_output(d: GuardDatum) -> Output {
  Output {
    address: guard_address(),
    value: stt_value(100_000_000),
    datum: InlineDatum(d),
    reference_script: None,
  }
}

fn mint_tx(outputs: List<Output>) -> Transaction {
  Transaction {
    ..transaction.placeholder,
    inputs: [genesis()],
    outputs,
    mint: assets.from_asset(stt_policy, stt_name(), 1),
    extra_signatories: [owner_key],
  }
}

fn mints(tx: Transaction) -> Bool {
  let redeemer: Data = Void
  guard_validator.guard.mint(redeemer, stt_policy, tx)
}

fn opens(d: GuardDatum) -> Bool {
  mints(mint_tx([guard_output(d)]))
}

fn opens_with(out: Output) -> Bool {
  mints(mint_tx([out]))
}

// ── Honest openings and burns ───────────────────────────────────────────────

test opening_a_valid_guard_mints() {
  opens(opening())
}

test opening_at_a_staked_guard_address_mints() {
  opens_with(
    Output {
      ..guard_output(opening()),
      address: guard_address() |> address.with_delegation_key(owner_key),
    },
  )
}

test opening_at_the_one_hour_window_floor_mints() {
  opens(GuardDatum { ..opening(), window_len: 3_600_000 })
}

test opening_at_the_thirty_day_window_ceiling_mints() {
  opens(GuardDatum { ..opening(), window_len: 2_592_000_000 })
}

test opening_at_the_record_and_token_cap_bounds_mints() {
  opens(GuardDatum { ..opening(), max_spends: 50, token_caps: caps(10) })
}

test opening_with_per_tx_cap_equal_to_daily_cap_mints() {
  opens(GuardDatum { ..opening(), per_tx_cap: 50_000_000 })
}

test opening_with_principal_exactly_at_the_floor_mints() {
  opens(GuardDatum { ..opening(), min_principal: 100_000_000 })
}

test opening_with_a_zero_principal_floor_mints() {
  opens(GuardDatum { ..opening(), min_principal: 0 })
}

test opening_with_twenty_assets_mints() {
  let full = list.foldl(
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19],
    stt_value(100_000_000),
    fn(i, v) { assets.add(v, pol(i), tok_name, 1) },
  )
  opens_with(Output { ..guard_output(opening()), value: full })
}

test burning_needs_nothing_but_the_burn() {
  let redeemer: Data = Void
  guard_validator.guard.mint(
    redeemer,
    stt_policy,
    Transaction {
      ..transaction.placeholder,
      mint: assets.from_asset(stt_policy, stt_name(), -1),
    },
  )
}

// ── One-shot rules that held before ─────────────────────────────────────────

test minting_without_the_genesis_input_is_refused() fail {
  mints(Transaction { ..mint_tx([guard_output(opening())]), inputs: [] })
}

test minting_two_is_refused() fail {
  mints(
    Transaction {
      ..mint_tx([guard_output(opening())]),
      mint: assets.from_asset(stt_policy, stt_name(), 2),
    },
  )
}

// ── Where the token goes ────────────────────────────────────────────────────

test token_sent_to_a_key_address_is_refused() fail {
  opens_with(
    Output {
      ..guard_output(opening()),
      address: address.from_verification_key(owner_key),
    },
  )
}

test token_sent_to_another_script_is_refused() fail {
  opens_with(
    Output {
      ..guard_output(opening()),
      address: address.from_script(other_script),
    },
  )
}

test token_carried_by_no_output_is_refused() fail {
  mints(mint_tx([]))
}

test token_carried_by_two_outputs_is_refused() fail {
  mints(mint_tx([guard_output(opening()), guard_output(opening())]))
}

test opening_with_a_reference_script_is_refused() fail {
  opens_with(
    Output { ..guard_output(opening()), reference_script: Some(other_script) },
  )
}

test opening_with_a_second_state_token_is_refused() fail {
  let other_stt = #"8888888888888888888888888888888888888888888888888888888888888888"
  let carried_in = Input {
    ..genesis(),
    output: Output {
      ..genesis().output,
      value: assets.from_lovelace(200_000_000)
        |> assets.add(stt_policy, other_stt, 1),
    },
  }
  let out = Output {
    ..guard_output(opening()),
    value: stt_value(100_000_000) |> assets.add(stt_policy, other_stt, 1),
  }
  mints(Transaction { ..mint_tx([out]), inputs: [carried_in] })
}

test opening_with_more_than_twenty_assets_is_refused() fail {
  let crowded = list.foldl(
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
    stt_value(100_000_000),
    fn(i, v) { assets.add(v, pol(i), tok_name, 1) },
  )
  opens_with(Output { ..guard_output(opening()), value: crowded })
}

test opening_below_min_principal_is_refused() fail {
  opens(GuardDatum { ..opening(), min_principal: 100_000_001 })
}

test opening_not_signed_by_the_owner_is_refused() fail {
  mints(
    Transaction {
      ..mint_tx([guard_output(opening())]),
      extra_signatories: [agent_key],
    },
  )
}

// ── What the opening datum holds ────────────────────────────────────────────

test opening_datum_by_hash_is_refused() fail {
  opens_with(
    Output {
      ..guard_output(opening()),
      datum: DatumHash(
        #"5555555555555555555555555555555555555555555555555555555555555555",
      ),
    },
  )
}

test opening_without_a_datum_is_refused() fail {
  opens_with(Output { ..guard_output(opening()), datum: NoDatum })
}

test opening_datum_that_is_not_a_guard_datum_is_refused() fail {
  let not_a_guard: Data = 42
  opens_with(
    Output { ..guard_output(opening()), datum: InlineDatum(not_a_guard) },
  )
}

test opening_datum_naming_another_policy_is_refused() fail {
  opens(GuardDatum { ..opening(), stt_policy: other_policy })
}

test opening_with_a_spend_record_is_refused() fail {
  opens(GuardDatum { ..opening(), spends: records(1, hi) })
}

/// Re-audit 2026-11-17 #1: 1,700 opening records push the owner exit past the
/// per-transaction memory limit.
test opening_with_1700_spend_records_is_refused() fail {
  opens(GuardDatum { ..opening(), max_spends: 1700, spends: records(1700, 1) })
}

test opening_killed_is_refused() fail {
  opens(GuardDatum { ..opening(), kill: True })
}

/// Re-audit 2026-11-17 #2: a 1 ms window prunes every record about 180 s after
/// it is stamped.
test opening_with_a_1ms_window_is_refused() fail {
  opens(GuardDatum { ..opening(), window_len: 1 })
}

test opening_with_a_window_just_below_one_hour_is_refused() fail {
  opens(GuardDatum { ..opening(), window_len: 3_599_999 })
}

test opening_with_a_window_above_thirty_days_is_refused() fail {
  opens(GuardDatum { ..opening(), window_len: 2_592_000_001 })
}

test opening_with_a_zero_per_tx_cap_is_refused() fail {
  opens(GuardDatum { ..opening(), per_tx_cap: 0 })
}

test opening_with_per_tx_cap_above_daily_cap_is_refused() fail {
  opens(GuardDatum { ..opening(), per_tx_cap: 50_000_001 })
}

test opening_with_a_zero_daily_cap_is_refused() fail {
  opens(GuardDatum { ..opening(), per_tx_cap: 0, daily_cap: 0 })
}

test opening_with_zero_max_spends_is_refused() fail {
  opens(GuardDatum { ..opening(), max_spends: 0 })
}

test opening_with_max_spends_above_50_is_refused() fail {
  opens(GuardDatum { ..opening(), max_spends: 51 })
}

/// Re-audit #1 adapted: an empty list the agent could grow to 1,700 records.
test opening_with_max_spends_1700_is_refused() fail {
  opens(GuardDatum { ..opening(), max_spends: 1700 })
}

test opening_with_a_negative_min_principal_is_refused() fail {
  opens(GuardDatum { ..opening(), min_principal: -1 })
}

test opening_with_eleven_token_caps_is_refused() fail {
  opens(GuardDatum { ..opening(), token_caps: caps(11) })
}

test opening_with_a_zero_token_per_tx_cap_is_refused() fail {
  opens(
    GuardDatum {
      ..opening(),
      token_caps: [AssetCap { ..cap(1), per_tx: 0, daily: 0 }],
    },
  )
}

test opening_with_token_per_tx_above_daily_is_refused() fail {
  opens(
    GuardDatum {
      ..opening(),
      token_caps: [AssetCap { ..cap(1), per_tx: 1001 }],
    },
  )
}

// ── Agent branch: the same terms after an owner retune ──────────────────────

fn own_ref() -> OutputReference {
  OutputReference {
    transaction_id: #"1111111111111111111111111111111111111111111111111111111111111111",
    output_index: 0,
  }
}

fn guard_input(v: Value, d: GuardDatum) -> Input {
  Input {
    output_reference: own_ref(),
    output: Output {
      address: guard_address(),
      value: v,
      datum: InlineDatum(d),
      reference_script: None,
    },
  }
}

fn continuation(v: Value, d: GuardDatum) -> Output {
  Output {
    address: guard_address(),
    value: v,
    datum: InlineDatum(d),
    reference_script: None,
  }
}

fn agent_tx(inp: Input, out: Output) -> Transaction {
  Transaction {
    ..transaction.placeholder,
    inputs: [inp],
    outputs: [out],
    extra_signatories: [agent_key],
    validity_range: interval.between(hi - 60_000, hi),
  }
}

fn ada_rec(at: Int, amount: Int) -> SpendRecord {
  SpendRecord { policy: #"", name: #"", at, amount }
}

/// Runs the deployed handler on the datum as the ledger hands it over, so the
/// measured budget includes decoding it.
fn handler_ok(d: GuardDatum, redeemer: GuardRedeemer, tx: Transaction) -> Bool {
  let raw: Data = d
  expect decoded: GuardDatum = raw
  guard_validator.guard.spend(Some(decoded), redeemer, own_ref(), tx)
}

/// The agent moves 1 ADA out of a retuned guard.
fn agent_moves_one_ada(start: GuardDatum) -> Bool {
  let after = GuardDatum { ..start, spends: [ada_rec(hi, 1_000_000)] }
  handler_ok(
    start,
    AgentSpend,
    agent_tx(
      guard_input(stt_value(100_000_000), start),
      continuation(stt_value(99_000_000), after),
    ),
  )
}

test agent_spends_at_the_one_hour_window_floor() {
  agent_moves_one_ada(GuardDatum { ..opening(), window_len: 3_600_000 })
}

test agent_refuses_a_window_just_below_one_hour() fail {
  agent_moves_one_ada(GuardDatum { ..opening(), window_len: 3_599_999 })
}

/// Re-audit #2 on the agent branch: under a 1 ms window the full daily cap spent
/// 181 s ago no longer counts, so the agent moves per_tx_cap again.
test agent_refuses_a_1ms_window_that_resets_the_daily_cap() fail {
  let start = GuardDatum {
    ..opening(),
    window_len: 1,
    spends: [ada_rec(hi - 181_000, 50_000_000)],
  }
  let after = GuardDatum { ..start, spends: [ada_rec(hi, 20_000_000)] }
  handler_ok(
    start,
    AgentSpend,
    agent_tx(
      guard_input(stt_value(100_000_000), start),
      continuation(stt_value(80_000_000), after),
    ),
  )
}

test agent_refuses_max_spends_above_50() fail {
  agent_moves_one_ada(GuardDatum { ..opening(), max_spends: 51 })
}

test agent_refuses_more_than_ten_token_caps() fail {
  agent_moves_one_ada(GuardDatum { ..opening(), token_caps: caps(11) })
}

/// The heaviest honest agent spend the bounds admit: 48 live records, ten
/// declared tokens, nine undeclared ones and the state token on the guard, one
/// ADA and one token record added to reach max_spends = 50.
test agent_spends_at_the_record_and_token_cap_bounds() {
  let start = GuardDatum {
    ..opening(),
    daily_cap: 1_000_000_000,
    max_spends: 50,
    token_caps: caps(10),
    spends: records(48, hi - 1_000),
  }
  let held = list.foldl(
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19],
    stt_value(100_000_000),
    fn(i, v) { assets.add(v, pol(i), tok_name, 1000) },
  )
  let left = held
    |> assets.add(#"", #"", -1_000_000)
    |> assets.add(pol(10), tok_name, -10)
  let after = GuardDatum {
    ..start,
    spends: [
      ada_rec(hi, 1_000_000),
      SpendRecord { policy: pol(10), name: tok_name, at: hi, amount: 10 },
      ..start.spends
    ],
  }
  handler_ok(
    start,
    AgentSpend,
    agent_tx(guard_input(held, start), continuation(left, after)),
  )
}

// ── Owner exit ──────────────────────────────────────────────────────────────

/// Everything goes to the owner and the state token is burned.
fn owner_exit_tx(d: GuardDatum) -> Transaction {
  Transaction {
    ..transaction.placeholder,
    inputs: [guard_input(stt_value(100_000_000), d)],
    outputs: [
      Output {
        address: address.from_verification_key(owner_key),
        value: assets.from_lovelace(100_000_000),
        datum: NoDatum,
        reference_script: None,
      },
    ],
    mint: assets.from_asset(stt_policy, stt_name(), -1),
    extra_signatories: [owner_key],
    validity_range: interval.between(hi - 60_000, hi),
  }
}

/// A full spends list at the largest bounds the policy admits.
test owner_exits_at_the_record_and_token_cap_bounds() {
  let d = GuardDatum {
    ..opening(),
    max_spends: 50,
    token_caps: caps(10),
    spends: records(50, hi),
  }
  handler_ok(d, OwnerSpend, owner_exit_tx(d))
}

/// Retuned outside every bound by the owner: the agent is refused, the owner
/// still exits.
test owner_exits_a_guard_retuned_out_of_bounds() {
  let d = GuardDatum {
    ..opening(),
    window_len: 1,
    per_tx_cap: 0,
    max_spends: 1000,
    token_caps: caps(11),
    kill: True,
  }
  handler_ok(d, OwnerSpend, owner_exit_tx(d))
}

// ── Owner spends that keep the state token ──────────────────────────────────
//
// Red-team 2026-11-17: an attacker opens a guard they own, then owner-spends it
// into a copy of the victim's guard (owner = victim, agent = attacker) at the
// victim's stake address. The copy carries a genuine state token, so it passed
// client attestation, and the attacker's agent key drained any top-up.

const attacker_key: ByteArray =
  #"0000000000000000000000000000000000000000000000000000000d"

const attacker_agent: ByteArray =
  #"0000000000000000000000000000000000000000000000000000000e"

const victim_stake: ByteArray =
  #"000000000000000000000000000000000000000000000000000005a5"

fn victim_address() -> address.Address {
  guard_address() |> address.with_delegation_key(victim_stake)
}

fn guard_input_at(addr: address.Address, v: Value, d: GuardDatum) -> Input {
  let inp = guard_input(v, d)
  Input { ..inp, output: Output { ..inp.output, address: addr } }
}

fn guard_output_at(addr: address.Address, v: Value, d: GuardDatum) -> Output {
  Output { ..continuation(v, d), address: addr }
}

fn owner_tx(
  inp: Input,
  outs: List<Output>,
  signers: List<ByteArray>,
) -> Transaction {
  Transaction {
    ..transaction.placeholder,
    inputs: [inp],
    outputs: outs,
    extra_signatories: signers,
    validity_range: interval.between(hi - 60_000, hi),
  }
}

/// The owner of `from` moves its guard, value unchanged, into `out`.
fn owner_moves(from: GuardDatum, out: Output, signers: List<ByteArray>) -> Bool {
  handler_ok(
    from,
    OwnerSpend,
    owner_tx(guard_input(stt_value(6_000_000), from), [out], signers),
  )
}

fn owner_retunes(from: GuardDatum, to: GuardDatum) -> Bool {
  owner_moves(from, continuation(stt_value(6_000_000), to), [from.owner])
}

/// The victim's real terms, as consented.
fn victim_terms() -> GuardDatum {
  opening()
}

fn attacker_opening() -> GuardDatum {
  GuardDatum { ..victim_terms(), owner: attacker_key }
}

fn look_alike() -> GuardDatum {
  GuardDatum { ..victim_terms(), agent: attacker_agent }
}

fn greedy_look_alike() -> GuardDatum {
  GuardDatum {
    ..look_alike(),
    per_tx_cap: 1_000_000_000_000,
    daily_cap: 1_000_000_000_000,
    min_principal: 0,
  }
}

/// The attacker turns their own guard into `d` at the victim's stake address.
fn plant(d: GuardDatum) -> Bool {
  owner_moves(
    attacker_opening(),
    guard_output_at(victim_address(), stt_value(6_000_000), d),
    [attacker_key],
  )
}

/// The attestation clients ran before the fix: pinned script and policy, the
/// one-shot name, owner and token caps.
fn attests(out: Output, me: ByteArray, consented: List<AssetCap>) -> Bool {
  expect InlineDatum(raw) = out.datum
  expect d: GuardDatum = raw
  and {
    out.address.payment_credential == guard_address().payment_credential,
    dict.to_pairs(assets.tokens(out.value, stt_policy)) == [Pair(stt_name(), 1)],
    d.owner == me,
    d.token_caps == consented,
    d.stt_policy == stt_policy,
  }
}

/// The victim tops the plant up, then the plant's agent key moves `drain` out.
fn deposit_and_drain(d: GuardDatum, deposit: Int, drain: Int) -> Bool {
  let small = stt_value(6_000_000)
  let funded = stt_value(6_000_000 + deposit)
  let deposit_ok = handler_ok(
    d,
    OwnerSpend,
    owner_tx(
      guard_input_at(victim_address(), small, d),
      [guard_output_at(victim_address(), funded, d)],
      [owner_key],
    ),
  )
  let after = GuardDatum { ..d, spends: [ada_rec(hi, drain)] }
  let loot = Output {
    address: address.from_verification_key(attacker_key),
    value: assets.from_lovelace(drain),
    datum: NoDatum,
    reference_script: None,
  }
  let drain_ok = handler_ok(
    d,
    AgentSpend,
    owner_tx(
      guard_input_at(victim_address(), funded, d),
      [
        guard_output_at(
          victim_address(),
          stt_value(6_000_000 + deposit - drain),
          after,
        ),
        loot,
      ],
      [attacker_agent],
    ),
  )
  deposit_ok && drain_ok
}

test attacker_cannot_plant_a_victim_owned_look_alike() fail {
  plant(look_alike())
}

test a_look_alike_never_reaches_client_attestation() fail {
  plant(look_alike()) && attests(
    guard_output_at(victim_address(), stt_value(6_000_000), look_alike()),
    owner_key,
    victim_terms().token_caps,
  )
}

test a_look_alike_cannot_drain_a_deposit_within_copied_caps() fail {
  plant(look_alike()) && deposit_and_drain(
    look_alike(),
    100_000_000,
    20_000_000,
  )
}

test a_greedy_look_alike_cannot_drain_a_whole_deposit() fail {
  plant(greedy_look_alike()) && deposit_and_drain(
    greedy_look_alike(),
    1_000_000_000,
    1_004_000_000,
  )
}

test attacker_opens_a_guard_of_their_own() {
  mints(
    Transaction {
      ..mint_tx([guard_output(attacker_opening())]),
      extra_signatories: [attacker_key],
    },
  )
}

test a_retune_without_the_owner_signature_is_refused() fail {
  owner_moves(
    attacker_opening(),
    continuation(stt_value(6_000_000), attacker_opening()),
    [attacker_agent],
  )
}

test a_drain_over_the_copied_cap_is_refused() fail {
  deposit_and_drain(look_alike(), 100_000_000, 20_000_001)
}

test a_fake_policy_plant_fails_attestation() {
  let fake = Output {
    ..guard_output_at(victim_address(), stt_value(6_000_000), look_alike()),
    value: assets.from_lovelace(6_000_000)
      |> assets.add(other_policy, stt_name(), 1),
  }
  !attests(fake, owner_key, victim_terms().token_caps)
}

test owner_cannot_take_the_state_token_to_a_wallet() fail {
  owner_moves(
    victim_terms(),
    Output {
      address: address.from_verification_key(owner_key),
      value: stt_value(6_000_000),
      datum: NoDatum,
      reference_script: None,
    },
    [owner_key],
  )
}

test owner_continuation_must_stay_at_the_guard_script() fail {
  owner_moves(
    victim_terms(),
    Output {
      ..continuation(stt_value(6_000_000), victim_terms()),
      address: address.from_script(other_script),
    },
    [owner_key],
  )
}

test owner_continuation_must_keep_its_terms_in_bounds() fail {
  owner_retunes(victim_terms(), GuardDatum { ..victim_terms(), window_len: 1 })
}

test owner_continuation_must_name_this_policy() fail {
  owner_retunes(
    victim_terms(),
    GuardDatum { ..victim_terms(), stt_policy: other_policy },
  )
}

test owner_continuation_must_carry_its_spend_records_forward() fail {
  let used = GuardDatum {
    ..victim_terms(),
    spends: [ada_rec(hi - 1_000, 50_000_000)],
  }
  owner_retunes(used, GuardDatum { ..used, spends: [] })
}

test owner_continuation_cannot_carry_a_reference_script() fail {
  owner_moves(
    victim_terms(),
    Output {
      ..continuation(stt_value(6_000_000), victim_terms()),
      reference_script: Some(other_script),
    },
    [owner_key],
  )
}

test a_handover_needs_the_new_owner_signature() fail {
  owner_retunes(
    victim_terms(),
    GuardDatum { ..victim_terms(), owner: attacker_key },
  )
}

test owner_retunes_caps_agent_and_expiry_within_bounds() {
  let used = GuardDatum {
    ..victim_terms(),
    spends: [ada_rec(hi - 1_000, 5_000_000)],
  }
  owner_retunes(
    used,
    GuardDatum {
      ..used,
      agent: attacker_agent,
      per_tx_cap: 10_000_000,
      daily_cap: 30_000_000,
      window_len: 3_600_000,
      token_caps: caps(10),
      max_spends: 50,
      expiry: 3_000_000_000_000,
    },
  )
}

test owner_kills_the_guard() {
  owner_retunes(victim_terms(), GuardDatum { ..victim_terms(), kill: True })
}

test owner_tops_up_the_guard() {
  owner_moves(
    victim_terms(),
    continuation(stt_value(106_000_000), victim_terms()),
    [owner_key],
  )
}

test owner_moves_the_guard_to_another_stake_credential() {
  owner_moves(
    victim_terms(),
    guard_output_at(victim_address(), stt_value(6_000_000), victim_terms()),
    [owner_key],
  )
}

test a_handover_signed_by_both_owners_passes() {
  owner_moves(
    victim_terms(),
    continuation(
      stt_value(6_000_000),
      GuardDatum { ..victim_terms(), owner: attacker_key },
    ),
    [owner_key, attacker_key],
  )
}

/// Funds at the guard address without a state token are not a guard: the key
/// in the datum's owner field sweeps them whatever the rest holds.
test owner_sweeps_a_utxo_without_a_state_token() {
  let d = GuardDatum { ..victim_terms(), window_len: -1, kill: True }
  handler_ok(
    d,
    OwnerSpend,
    owner_tx(
      guard_input(assets.from_lovelace(6_000_000), d),
      [
        Output {
          address: address.from_verification_key(owner_key),
          value: assets.from_lovelace(6_000_000),
          datum: NoDatum,
          reference_script: None,
        },
      ],
      [owner_key],
    ),
  )
}

test an_exit_without_the_owner_signature_is_refused() fail {
  let d = victim_terms()
  handler_ok(
    d,
    OwnerSpend,
    Transaction { ..owner_exit_tx(d), extra_signatories: [attacker_key] },
  )
}

test a_sweep_without_the_owner_signature_is_refused() fail {
  let d = victim_terms()
  handler_ok(
    d,
    OwnerSpend,
    owner_tx(
      guard_input(assets.from_lovelace(6_000_000), d),
      [],
      [attacker_key],
    ),
  )
}

test minting_a_name_no_input_hashes_to_is_refused() fail {
  let other = Input {
    ..genesis(),
    output_reference: OutputReference {
      transaction_id: genesis_tx_id,
      output_index: 4,
    },
  }
  mints(Transaction { ..mint_tx([guard_output(opening())]), inputs: [other] })
}
