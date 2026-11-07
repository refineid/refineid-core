<!--
Copyright 2026 Petri Koistinen

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Symbolic models of RAPP v26.11.2

Two symbolic (Dolev-Yao) models of the stamped protocol
[RAPP v26.11.2](../rapp-v26.11.2.md) ("the spec"):

| File | Tool | What it states |
| :--- | :--- | :--- |
| [`rapp-pairing-secrecy-v26.11.2.pv`](rapp-pairing-secrecy-v26.11.2.pv) | ProVerif 2.05 | The pairing (offer, CPace, Noise_XXpsk3, the pairing channel, stored records) with withdrawn records published: secrecy of the PSK, the static keys and the keys of the static agreement. |
| [`rapp-pairing-guessing-v26.11.2.pv`](rapp-pairing-guessing-v26.11.2.pv) | ProVerif 2.05 | The pairing: no offline guessing of the code (`weaksecret`). |
| [`rapp-pairing-agreement-v26.11.2.pv`](rapp-pairing-agreement-v26.11.2.pv) | ProVerif 2.05 | The pairing: pairing cannot complete without the code, and both ends agree on what they store. |
| [`rapp-pairing-withdrawal-v26.11.2.pv`](rapp-pairing-withdrawal-v26.11.2.pv) | ProVerif 2.05 | Stored pairings taken as given, withdrawn records published and verified: withdrawal authenticity. |
| [`rapp-session-secrecy-v26.11.2.pv`](rapp-session-secrecy-v26.11.2.pv) | ProVerif 2.05 | Sessions over stored pairings with one operation each, the card and Carol: secrecy of PIN 1, PIN 2, the CAN and the session keys; session authentication; card commands only on active pairings and only as commanded; card presence. |
| [`rapp-session-requests-v26.11.2.pv`](rapp-session-requests-v26.11.2.pv) | ProVerif 2.05 | Sessions with two operations each and one abstract card command: injective agreement on requests. |
| [`rapp-session-consent-v26.11.2.pv`](rapp-session-consent-v26.11.2.pv) | ProVerif 2.05 | Sessions with one operation each, the card and Carol, and the close: consent for qualified signatures; authenticity of results and close reasons. |
| [`rapp-pairing-v26.11.2.spthy`](rapp-pairing-v26.11.2.spthy) | Tamarin 1.12 | The pairing: offer, CPace, Noise_XXpsk3 and the pairing channel, with the pairing lemmas. |
| [`rapp-session-v26.11.2.spthy`](rapp-session-v26.11.2.spthy) | Tamarin 1.12 | Sessions and operations over stored pairings taken as given, the card and Carol, withdrawn records, and revocation, which needs mutable state. |

The ProVerif model is split so that each part fits a small verification
budget: four pairing files and three session files, one per property
group. Each pairing file has one compromised computer's ceremony beside
any number of honest ones; the withdrawal file, like the session files,
takes stored pairings as given. The session files take a stored pairing as given: fresh
pair-specific static keys on both ends, both records stored, and
`pair_id` known to the attacker. The pairing file checks that a pairing
made with the code gives exactly that: the secrecy file for b1 and b2,
the agreement file for b6. Each session file has
any number of honest pairings and one compromised computer's pairing,
whose Requester static key and display name the attacker chooses, and
which serves any number of sessions. Each session file keeps only what
its properties use:

- **Secrecy file.** One operation per session. A further operation
  reuses the same PINs and gives the attacker nothing an earlier one did
  not.
- **Requests file.** Two operations per session, so that the sequence
  numbers and the `operation_id` check are exercised. The card is one
  abstract signing command, since the property is about the request,
  not the PIN that authorizes it.
- **Consent file.** One operation per session, and the close.

Each property is tied to the losses (L), hazards (H), unsafe control
actions (UCA) and controller constraints (CC) of the
[RAPP STPA record](../../security/stpa-rapp.md), and to the state
machine invariants (INV, X) of
[rapp-state-machine-v26.11.2.yaml](../rapp-state-machine-v26.11.2.yaml).
The models follow the spec. Where the engine in `crates/rapp` does
something the spec does not state, the model follows the spec.

## What is modelled

**Roles.** Alice the phone (Custodian), Bob the computer (Requester),
Carol the cardholder and the card.

- Carol types the pairing code shown on Alice into a computer once per
  ceremony. She reads PIN prompts on Alice and answers them with PIN 2.
- The card holds an authentication key and a qualified signature key. It
  signs a digest only when it receives the CAN (the PACE channel) and the
  matching PIN: PIN 1 for authentication, PIN 2 for a qualified signature.
- Alice runs offers, CPace attempts, the Noise_XXpsk3 pairing handshake,
  the pairing channel, stored pairing records, routing, Noise_KK
  sessions, `session.ready`, `card.status`, two operations per session,
  the close, discovery hints and withdrawn records.
- Bob runs the same ceremony from the Requester side. He also runs
  sessions with two operations, checks the close, and checks withdrawn
  records.

**Channels.** Every RAPP transport (BLE, the stream transport, the
Apple peer-to-peer link) is one public channel. Alice reaches the card
(NFC or her reader) and her own screen over private channels. In the
Tamarin model these are linear facts.

**Attacker.** Dolev-Yao on every transport: he reads, drops, delays,
reorders, replays, reflects and forges every frame, serves forged offers,
and runs any number of sessions in parallel. He also learns every
certificate. Alice, the card and Carol are honest. A computer is one of
two kinds:

- **honest**: Bob, into whom Carol typed the code;
- **compromised**: the code Carol typed is given to the attacker. He
  completes the pairing with keys of his own, holds a legitimate pairing
  record on Alice, and asks for operations through it. Alice prompts
  Carol and commands the card as for any computer.

Both kinds run at the same time, against one card and one Carol. Each
property states which pairings it covers. A property marked "honest"
holds for pairings made with Bob, while compromised pairings run
beside them.

**Abstraction.**

- **Diffie-Hellman.** X25519 (Noise and the static agreement) and
  Ristretto255 (CPace) are distinct types, each with its own equation:
  `xdh(xpk(x), y) = xdh(xpk(y), x)` with the fixed base, and
  `cdh(cpt(b, x), y) = cdh(cpt(b, y), x)` with a variable base, since
  the CPace generator `h2g(code, C, SID)` depends on the code (spec
  §6.1.2) and only a holder of the code can compute it. The ProVerif
  attacker sends only well-typed values. The groups are unrelated, and no
  honest computation relates a value of one to a value of the other, so
  typing removes only meaningless confusions. Tamarin uses its built-in
  Diffie-Hellman theory. Identity points are excluded there by a
  restriction, as spec §6.1.1 and §6.3 reject them.
- **Hashes.** SHA-256, SHA-512, HMAC and the HKDF steps are free one-way
  functions. Each input is labelled as the spec labels it.
- **AEAD.** ChaCha20-Poly1305 is `aead(key, nonce, ad, plaintext)` with
  its decryption. The envelope sequence is the nonce (spec §7.2 item 3).
- **CPace (spec §6.1).** Kept as specified: generator from code, context
  C and SID; ISK; transcript hash; PRK; PSK, K_A, K_B; T_B and T_A.
  Attempts under one offer share the SID and the code and are unbounded,
  so the model covers the spec's multi-attempt composition assumption
  (§3.3 item 5).
- **Noise_XXpsk3 and Noise_KK (spec §6.2, §6.3).** Every token is kept
  in the spec's order: `e`, `ee`, `s`, `es`, `s`, `se`, `psk` for
  XXpsk3, and `e`, `es`, `ss`, then `e`, `ee`, `se` for KK. The chaining
  key and the cipher keys follow MixKey and MixKeyAndHash, with Split()
  at the end. The prologues are those of spec §4.3 items 1 and 5. In
  ProVerif, MixHash of a ciphertext is modelled as MixHash of its nonce
  and plaintext, which keeps the symbolic handshake hash small. Every
  input of the real handshake hash is public, so each endpoint publishes
  its final handshake hash, and `session_id` and `pair_id` are known to
  the attacker as they would be to an eavesdropper. In Tamarin, each key
  is a hash over the tokens and public values mixed so far.
- **Pairing channel (spec §4.3 items 2 to 4, §7.1 items 1 to 4).**
  `pairing.hello` with the echoed parameters and display name,
  `pairing.confirm` and its echo, `grants_hash`, and `pairing.stored`
  with `pair_id`. A pairing is active only after both stores.
- **Announcements.** Alice publishes withdrawn records for any instance
  name and counter, and Bob verifies them. The discovery hint (hierarchy
  §4.3) is a MAC of the epoch alone under `K_disc`. The models query the
  secrecy of `K_disc`, and the ProVerif model does not run the hint as an
  oracle.
- **Sessions.** The routing preamble keyed by the static agreement
  (spec §2.2.1). Then `session.ready` with parameters and a fresh nonce,
  `card.status` with the certificate fingerprint, `session.hello`, two
  `operation.request` / `operation.result` pairs at sequences 1, 2 and
  2, 3, and a `session.close` at 4. Each request carries a fresh
  `operation_id`, and a second request reusing one is refused (spec
  §8.1 item 1).
- **Operations.** A `sign_document` request under a granted
  document-signing profile prompts Carol with the stored display name,
  the document name and the digest; her PIN 2 goes to the card. A
  `browser_authenticate` request under a granted authentication profile
  uses the PIN 1 that Alice holds in memory, without a prompt (spec §11
  item 2, STPA R-4). Profile, action, context and digest are any values
  a local program chooses. The prompt renders from a snapshot of the
  request (spec §8.2 item 3), and Carol's PIN entry answers that prompt,
  so in the ProVerif models her entry carries the name, document name and
  digest the prompt showed.
- **Offer profiles.** The offer lists the three registered profiles
  (spec §9). Bob reads them from the unauthenticated bootstrap, so a
  forged offer is part of the model.
- **Tamarin theories.** Secret scalars read from state facts carry the
  fresh sort, since only `Fr` values reach those facts; this bounds the
  Diffie-Hellman variants of each rule. An envelope's fields are its AEAD
  associated data and its plaintext is a constant; AEAD binds both alike,
  and the fields are values the attacker chose or can derive, a fresh
  ready nonce, or a card signature, which has no destructor in the theory,
  so no lemma rests on him reading them. The Custodian's record is a
  persistent fact. Revocation adds a linear token that sessions and card
  commands consume and reproduce, present only with `-D=REVOCATION`;
  without it the phone serves regardless of revocation, which only adds
  traces. The session theory takes stored pairings as given, like the
  ProVerif session files.
- **ProVerif phases.** The ProVerif model hands each phase to the next
  through tables: the CPace PSK, the opened pairing channel, and the
  stored pairing record. This keeps the Horn-clause translation finite
  in practice. Because a table entry is persistent, one CPace run may
  seed several Noise runs in the abstraction. Pairing agreement is
  therefore stated per pairing (`pair_id` and keys), not as one pairing
  per ceremony. Fresh names are drawn before the inputs of their
  process.

## Properties

In "Checked by", Ps is `rapp-pairing-secrecy-v26.11.2.pv`, Pg is
`rapp-pairing-guessing-v26.11.2.pv`, Pa is
`rapp-pairing-agreement-v26.11.2.pv`, Pw is
`rapp-pairing-withdrawal-v26.11.2.pv`, Ss is
`rapp-session-secrecy-v26.11.2.pv`, Sr is
`rapp-session-requests-v26.11.2.pv`, Sc is
`rapp-session-consent-v26.11.2.pv`, Tp is `rapp-pairing-v26.11.2.spthy`
and Ts is `rapp-session-v26.11.2.spthy`.

| # | Property | Checked by | Spec | STPA and state machine |
| :--- | :--- | :--- | :--- | :--- |
| a1 | PIN 1 is never known to the attacker, with honest and compromised computers paired. | Ss, Ts | §11 item 4, §10.2 | L-1, L-2, H-1, CC-66, INV-09 |
| a2 | PIN 2 likewise. | Ss, Ts | §11 items 2 and 4 | L-1, L-2, L-5, H-1, CC-66, INV-09 |
| a3 | The CAN likewise. | Ss, Ts | §11 item 4 | L-4, INV-09 |
| b1 | The CPace PSK of an honest ceremony is secret, on both ends. | Ps, Tp | §6.1.3, §6.1.4 | H-1, H-4 |
| b2 | The pair-specific static private keys of an honest pairing are secret. | Ps, Tp, Ts | §4.3 item 4 | H-1, H-4, UCA-102 |
| b3 | The keys of the static agreement (`K_route`, `K_disc`, `K_wd`) are secret, so routing tags, discovery hints and withdrawal hints identify the pairing to its two ends only. | Ps, Ts | §2.2.1, §4.3 item 5, §4.5 item 1 | H-6, L-4, UCA-14 |
| b4 | The session transport keys of an honest pairing are secret. | Ss, Ts | §6.3 | H-1, H-6 |
| b5 | Offline guessing: after any run the attacker cannot tell the code from a random value (`weaksecret`). | Pg | §3.3 "Guessing Bound", §12 | CC-107, Story 14 |
| b6 | Pairing cannot complete without the code, and both ends agree. When Alice holds an honest pairing active, Bob stored that pairing (same `pair_id`, grants hash, both static keys, Bob's display name). When Bob holds it active, Alice stored it. | Pa, Tp | §3.3 item 5, §4.3 items 3 and 4 | H-4, CC-1, CC-119, CC-120, UCA-8, UCA-120 |
| b7 | Session authentication: a session Bob holds ready is one that Alice opened for the same pairing. | Ss, Ts | §6.3, §7.1 items 5 and 6 | CC-4, UCA-102 |
| c, e | Injective agreement on the request. Every card command Alice issues on an honest pairing's session answers one distinct request that Bob sent on that same session, with the same `operation_id`, profile, action, context and digest. A replayed, reflected or cross-session request obtains no second command. | Sr, Ts | §7.2 items 2 and 3, §8.1 item 1 | H-1, H-2, UCA-15, CC-104 |
| d1 | No card command outside an active pairing, for any computer: the command belongs to a pairing that Alice stored and saw confirmed. | Ss, Ts | §4.3 item 4, §8.2 item 1 | CC-1, UCA-8, X-03, INV-01 |
| d2 | The card signs only what Alice commanded. | Ss, Ts | §11 item 4 | H-1 |
| d3 | A result Bob accepts is one that Alice returned for that request on that session. | Sc, Ts | §8.2 item 5 | H-3 |
| f1 | Consent. Every qualified signature runs under Carol's PIN 2 entry on a prompt that named the paired computer by its stored display name and showed that request's document name and digest. In ProVerif the correspondence is injective: one entry per signature. | Sc, Ts | §8.2 item 3, §11 items 1 and 2 | L-1, L-5, H-1, CC-66, CC-75, CC-85, UCA-1, UCA-73, INV-03 |
| f2 | Card presence comes from Alice on the authenticated session: a `card.status` that Bob accepts is one that Alice sent on that session. | Ss, Ts | §8.4 items 1 to 4 | H-3, CC-4, CC-60, UCA-16, UCA-63 |
| f3 | A close reason Bob acts on (`pairing_revoked`, `service_withdrawn`, `card_unavailable` and the rest) is one that Alice sent on that session. | Sc, Ts | §4.5 item 6, §4.6 item 4, §7.1 item 7 | H-4, H-7, CC-2, CC-22, CC-114 |
| f4 | A withdrawn record that Bob verifies was published by Alice for that pairing, instance and counter. The agreement is not injective: a replay inside the counter window is the limit that spec §4.5 item 7 accepts. | Pw, Ts | §4.5 items 1, 2, 6 and 7 | H-7, CC-114, UCA-112 |
| f5 | Revocation. After Alice revokes a pairing, it opens no session and the card is commanded for no request of it. | Ts | §4.6 | UCA-102, CC-106, H-4 |

The STPA record names no hazard for the PINs reaching the wire. Rule 1
of [AGENTS.md](../../../AGENTS.md) and spec §11 item 4 state it, and
items a1 to a3 cite the losses and the custody constraint it protects.

## Running

### ProVerif

```sh
proverif rapp-pairing-secrecy-v26.11.2.pv
proverif rapp-pairing-guessing-v26.11.2.pv
proverif rapp-pairing-agreement-v26.11.2.pv
proverif rapp-pairing-withdrawal-v26.11.2.pv
proverif rapp-session-secrecy-v26.11.2.pv
proverif rapp-session-requests-v26.11.2.pv
proverif rapp-session-consent-v26.11.2.pv
```

Each file is checked on its own and reports the queries of its group.
Each line of a verification summary is expected to end in `is true.`;
the guessing file reports `Weak secret code_w is true.`.
`proverif -parse-only <file>` checks syntax alone.

### Tamarin

```sh
tamarin-prover --prove rapp-pairing-v26.11.2.spthy
tamarin-prover --prove rapp-session-v26.11.2.spthy
tamarin-prover -D=REVOCATION --prove=no_service_after_revocation rapp-session-v26.11.2.spthy
```

`--prove=<lemma>` proves one lemma. The revocation lemma and the
revocation token exist only with `-D=REVOCATION`.

## Verification status

Runs on a 12-core host with ProVerif 2.05, one ProVerif at a time,
under `nice -n 10`, with `ulimit -v 16000000` and a 40-minute timeout.
Time is wall-clock and peak memory is the maximum resident set size,
both as reported by GNU `time`.
The session files here differ from the copies that ran only in their
opening comments.

### `rapp-session-secrecy-v26.11.2.pv`: complete, 114 s, peak 1.74 GiB

```
RESULT not attacker_bitstring(pin1[]) is true.
RESULT not attacker_bitstring(pin2[]) is true.
RESULT not attacker_bitstring(can[]) is true.
RESULT not attacker_bitstring(sec_sess_r[]) is true.
RESULT not attacker_bitstring(sec_sess_c[]) is true.
RESULT event(RequesterSessionReady(pid_4,ssid_2)) ==> event(CustodianSessionReady(honest,pid_4,ssid_2)) is true.
RESULT event(CustodianCommandsCard(k,pid_4,ssid_2,op,nm_3,pr,ac,cx,d_3)) ==> event(CustodianPairingActive(k,pid_4,gh_4,pkc_4,pkr_4,nm_3)) is true.
RESULT event(CardSigns(ac,d_3)) ==> event(CustodianCommandsCard(k,pid_4,ssid_2,op,nm_3,pr,ac,cx,d_3)) is true.
RESULT event(RequesterAcceptsCardStatus(pid_4,ssid_2,fp_2)) ==> event(CustodianSentCardStatus(honest,pid_4,ssid_2,fp_2)) is true.
```

### `rapp-session-requests-v26.11.2.pv`: complete, 580 s, peak 6.20 GiB

```
RESULT inj-event(CustodianCommandsCard(honest,pid_4,ssid_2,op,nm_2,pr,ac,cx,d)) ==> inj-event(RequesterSendsOp(pid_4,ssid_2,op,pr,ac,cx,d)) is true.
```

### `rapp-session-consent-v26.11.2.pv`: complete, 59 s, peak 0.99 GiB

```
RESULT inj-event(CustodianCommandsCard(k,pid_4,ssid_2,op,nm_3,prof_docsign,act_sign_document,cx,d_3)) ==> inj-event(HolderConsents(nm_3,cx,d_3)) is true.
RESULT event(RequesterGetsResult(pid_4,ssid_2,op,s)) ==> event(CustodianSentResult(honest,pid_4,ssid_2,op,s)) is true.
RESULT event(RequesterAcceptsClose(pid_4,ssid_2,r_1)) ==> event(CustodianSentClose(honest,pid_4,ssid_2,r_1)) is true.
```

### `rapp-pairing-secrecy-v26.11.2.pv`: complete, 38 s, peak 0.89 GiB

```
RESULT not attacker_bitstring(sec_psk_r[]) is true.
RESULT not attacker_bitstring(sec_psk_c[]) is true.
RESULT not attacker_bitstring(sec_static_r[]) is true.
RESULT not attacker_bitstring(sec_static_c[]) is true.
RESULT not attacker_bitstring(sec_route_r[]) is true.
RESULT not attacker_bitstring(sec_route_c[]) is true.
RESULT not attacker_bitstring(sec_disc_c[]) is true.
RESULT not attacker_bitstring(sec_wd_c[]) is true.
```

### `rapp-pairing-guessing-v26.11.2.pv`: complete, 169 s, peak 1.49 GiB

```
RESULT Weak secret code_w is true.
```

### `rapp-pairing-agreement-v26.11.2.pv`: complete, 45 s, peak 1.23 GiB

```
RESULT event(CustodianPairingActive(honest,pid_4,gh_2,pkc_4,pkr_4,nm_1)) ==> event(RequesterStored(pid_4,gh_2,pkc_4,pkr_4,nm_1)) is true.
RESULT event(RequesterPairingActive(pid_4,gh_2,pkc_4,pkr_4,nm_1)) ==> event(CustodianStored(honest,pid_4,gh_2,pkc_4,pkr_4,nm_1)) is true.
```

### `rapp-pairing-withdrawal-v26.11.2.pv`: complete, under 0.1 s, peak 13 MiB

```
RESULT event(RequesterVerifiedWithdrawal(pid_4,ins_2,ctr_2)) ==> event(CustodianWithdrew(honest,pid_4,ins_2,ctr_2)) is true.
```

The wall-clock time of the whole command, `nix shell` start-up included,
was 51 ms.

### The earlier single pairing file

A run of the earlier single pairing file, which these four files replace,
reported the same eight secrecy results above, all true. Its remaining
queries were still saturating after more than three hours at about
9.7 GiB, and its log ends there with no further result.

### Tamarin

Tamarin 1.12 with Maude 3.5.1 on the same host, one run at a time, under
`nice -n 10`, with `ulimit -v 16000000` and a timeout per run. "Out of
memory" means Tamarin stopped at that limit.

`rapp-pairing-v26.11.2.spthy`, one run of four lemmas, all wellformedness
checks successful with the derivation check untimed: 34 s, peak
1.72 GiB.

| Lemma | Result |
| :--- | :--- |
| `scalars_secret` | verified (17 steps) |
| `honest_code_secret` | verified (2 steps) |
| `requester_psk_secret` | verified (141 steps) |
| `custodian_psk_secret` | verified (72 steps) |
| `pairing_agreement_requester` | no result: out of memory after 278 s |
| `pairing_agreement_custodian` | no result: out of memory after 203 s |
| `custodian_keys_secret`, `requester_keys_secret` | no result in this file: out of memory or 300 s timeout in the earlier single theory |

`rapp-session-v26.11.2.spthy`, one run of eleven lemmas, derivation check
untimed and successful: 13 s, peak 0.77 GiB; `pin1_secret` and
`pin2_secret` in a second run: 13 s, peak 0.34 GiB.

| Lemma | Result |
| :--- | :--- |
| `scalars_secret` | verified (12 steps) |
| `pin1_secret`, `pin2_secret`, `can_secret` | verified (2 steps each) |
| `custodian_keys_secret` | verified (42 steps) |
| `requester_keys_secret` | verified (22 steps) |
| `session_authentication` | verified (14 steps) |
| `command_needs_active_pairing` | verified (22 steps) |
| `card_signs_only_commanded` | verified (18 steps) |
| `card_status_authentication` | verified (25 steps) |
| `consent_for_qualified_signature` | verified (11 steps) |
| `withdrawal_authentication` | verified (10 steps) |
| `result_authentication` | no result: 300 s timeout |
| `close_authentication` | no result: out of memory after 88 s |
| `request_agreement_injective` | no result: out of memory after 297 s |
| `no_service_after_revocation` (`-D=REVOCATION`) | no result: out of memory after 289 s |
| `executable_signature` | no result: out of memory after 160 s in the earlier single theory |

The single-theory Tamarin model these two files replace never reached a
lemma. Its first run was stopped after 4 h 51 min, Tamarin having used
8 s of CPU and Maude the rest. In a run that logged Maude's input and
output, Maude's variant computation for the rule `Requester_XX_Msg3` had
produced 4,924 variants and was still running when a five-minute limit
ended it; the rules before it had 1 to 48 variants each.

### Reachability of the premises

Each correspondence above could hold only because its premise never
happens, so each premise event was also queried for reachability, on
scratch copies of the files whose queries are replaced by the plain event
(not part of this directory: a reachable event reports `is false`). Same
host and limits as above. Every line below reports `is false` with
`A trace has been found.`, without any assumed hypothesis. The session
copies omit the `hh` resolution hint, which changes no derivable fact and
which otherwise keeps ProVerif from completing traces.

| Copy of | Premises shown reachable | Time | Peak memory |
| :--- | :--- | :--- | :--- |
| `rapp-pairing-agreement` | `CustodianPairingActive(honest, ...)`, `RequesterPairingActive` | 34 s | 0.99 GiB |
| `rapp-pairing-withdrawal` | `RequesterVerifiedWithdrawal` | under 0.1 s | 13 MiB |
| `rapp-session-secrecy` | `RequesterSessionReady`; `CustodianCommandsCard` for an honest document signature, an honest browser authentication and a compromised pairing; `CardSigns` for both actions; `RequesterAcceptsCardStatus` | 7 s | 0.26 GiB |
| `rapp-session-requests` | `CustodianCommandsCard(honest, ...)` | 53 s | 0.53 GiB |
| `rapp-session-consent` | `CustodianCommandsCard` for a document signature, honest and compromised | 9 s | 0.30 GiB |
| `rapp-session-consent`, minimal scenario | `RequesterGetsResult`, `RequesterAcceptsClose` | 5 s | 0.20 GiB |

The minimal scenario has one honest pairing, one session on each side and
no compromised pairing; a trace in it is a trace of the full file, whose
other processes can stay idle. On the full file ProVerif found derivations
for these two premises but did not complete a trace within about ten
minutes, and those runs were stopped.

`rapp-pairing-secrecy` and `rapp-pairing-guessing` have no correspondence
queries, so they have no premises to check.

## What the models leave out

- **Timing.** The 500 ms attempt spacing, the 5-second attempt deadline,
  the offer's 5-minute life, the post-PAKE deadlines, the liveness and
  silence limits, the redial window, the identity grace, idle expiry and
  the revocation attempt bound. A symbolic attacker never guesses the
  code online. The online guessing bound of spec §3.3 (at most 600 tries
  per offer) is arithmetic, not a symbolic property.
- **Discovery.** BLE advertisements, DNS-SD names, TXT records,
  candidate trying across Custodians, the busy refusal (`pairing-busy`)
  and the 8-connection limit. These are unauthenticated by design, and
  the attacker can produce or suppress any of them.
- **The routing replay memory** of 256 nonces. It bounds work and
  timing leaks; a replayed preamble reaches Noise_KK and fails there, as
  the model shows.
- **BLE SAR framing and stream framing.** These are below the symbolic
  layer.
- **UI, presentation and lifecycle machines.** What each screen shows,
  withdrawal ordering, the operation queue across sessions, progress
  events, the retry floor and PIN try counters, card swaps, readers.
- **Liveness and denial of service.** The attacker can always drop
  frames.
- **Equivalence properties** beyond the code's offline-guessing
  resistance: unlinkability of routing tags and hints across connections
  (spec §4.3 item 5 "Routing privacy") is not modelled. b3 checks only
  the secrecy of their keys.
- **Identity and low-order points.** ProVerif's Diffie-Hellman
  abstraction has no identity or low-order element, so the ProVerif
  models cannot exercise the rejection of such points that spec §6.1.1
  and §6.3 require (an identity CPace generator, peer point or shared
  point, an all-zero X25519 key). They assume it. The Tamarin model
  states the same assumption as a restriction that excludes the neutral
  element.
- **Compromise of the phone or the card**, and forward secrecy after a
  static key leaks.
- **What a compromised computer may ask for.** A computer that holds a
  pairing obtains signatures by design. Within the model it can never
  obtain a PIN, the CAN, or a qualified signature without Carol's PIN 2
  entry. What digest and document name it sends is its own (STPA UCA-15,
  CC-109).
