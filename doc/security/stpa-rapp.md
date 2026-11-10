# STPA of the Remote Authorization Proxy Protocol

**Applies to:** RAPP v26.11.8 ([rapp-v26.11.8.md](../protocols/rapp-v26.11.8.md),
written "spec" below), the
[transport and discovery hierarchy](../protocols/rapp-transport-and-discovery-hierarchy.md)
("hierarchy"), and the phone and computer applications built on them.

> Reasonable, smart and smooth engineering that delivers robust software:
> easy to operate, never failing in unexpected ways, and when it does
> fail, failing with clear feedback.
>
> -- Petri Koistinen, on what this analysis is for

This is the safety record for RAPP. It opens with the idea in plain
words, tells what went wrong in practice as short office stories, and
ends with the reference tables. The method is System-Theoretic Process
Analysis (STPA); [../stpa.md](../stpa.md) explains it. In one sentence:
losses come less from broken parts than from a part acting on a wrong
picture of the others, because nobody told it what changed.

## The Smart Card Office

RAPP lets a computer use the identity card that lies on a phone. Think of
it as a small office. The staff carry the customary names of
cryptography literature, where Alice and Bob talk over lines that
others can hear.

- **Alice, the phone** (the *custodian*). She keeps the card at her desk
  and is the only one who ever touches it, over NFC or through a card
  reader plugged into her.
- **Bob, the computer** (the *requester*). He sits at the front desk and
  serves visitors. He never touches the card; he asks Alice.
- **Carol, the cardholder.** The card and the PINs are hers. She approves
  a login or a signature by typing her PIN on Alice's screen, never on
  Bob's.
- **Dave, Erin and Frank, the visitors** (the *local programs*): Dave
  the browser logs in to websites, Erin the PDF signer signs documents,
  Frank the command line does both from a terminal.
- **Eve**, the eavesdropper. She hears every radio advertisement and
  every packet on the network, and must learn nothing from them.
- **Mallory**, the active attacker. He relays, forges and replays
  messages, and pretends to be a phone.
- **Craig**, the password cracker. He guesses pairing codes.
- **Sybil**, who shows up under many identities at once.
- **Oscar**, an opponent who means no harm: a neighbouring phone that
  happens to be in pairing mode too, or simply busy.
- **Peggy and Victor**, the prover and the verifier. At pairing, Alice
  and Bob each prove to the other that they know Carol's code without
  saying it; later, Victor checks a signature before anyone relies on
  it.
- **Ivan**, the card issuer. The card's last two PIN tries are his.
- **Olivia**, the oracle: the phone's or computer's operating system,
  whose answers come out of a black box.

A normal day: Dave asks Bob for a login. Bob passes the request to
Alice. Alice asks Carol for PIN 1 if she does not already hold it, has
the card sign, and hands the signature back to Bob, who gives it to
Dave. A document signature for Erin goes the same way, except that
Carol types PIN 2 on Alice's screen every time and sees the document
names there. The document itself never leaves Bob's desk; only its
fingerprint (hash) travels. No PIN ever travels at all.

Bob and Alice talk over a private channel. They became colleagues
through one introduction (*pairing*): Alice shows a six-character code,
Carol types it at Bob's desk, and from that moment they share keys that
nobody else has. Every conversation (*session*) after that is encrypted
with fresh keys. Eve can see that someone is talking, but not who or
what about, and Craig, without the code, gets one guess at a time and
no more. Alice can work with several computers at once; each computer
works with one phone.

## Three office rules

1. **The channel is private, and both sides know who is on it.** The
   pairing keys prove who Bob and Alice are; session keys protect each
   conversation. A name on a door is only a label: nobody is
   recognised, replaced or thrown out because of a name.
2. **Everyone announces their own changes.** "I'm taking the card home,
   bye." "Thanks for letting me know." Whoever stops, leaves, forgets a
   colleague or changes the card says so, with a reason, so the other
   side never has to guess from silence. No ghosting. The thanks is
   said out loud: the receiver answers the goodbye with the same words,
   then hangs up, so the sender knows it was heard.
3. **Silence has a time limit.** Someone who walks out without a word is
   treated as gone after a bounded wait. Bob redials for at most two
   minutes (the redial window, 120 s) and keeps the visitor's badge for
   the same two minutes. Nobody keeps calling an empty desk.

Rule 2 is the normal path. Rule 3 is the safety net for the day a
colleague cannot speak: a crash, a dead battery, a lost radio.

## Who controls what

```
                        Carol, the cardholder
          remote use on/off,  ^                     ^   PINs, the card,
          pairing code        | "the remote card"   |   forget a computer
                 |            |  or "no remote card"|        |
                 v            |                     |        v
 +----------+  asks  +-------------+   RAPP    +-------------+  commands +------+
 | Visitors |------->| Bob         |==========>| Alice       |---------->| Card |
 | browser, |<-------| the computer|<==========| the phone   |<----------|      |
 | PDF, CLI | answers| (requester) |  private  | (custodian) |  answers  +------+
 +----------+        +-------------+  channel  +-------------+
                            ^                         |
                            +---- "I'm here" ---------+
                              discovery record, BLE advertisement
                              (Eve hears these; they name nobody)
```

| Who | Controls | Hears back |
| :--- | :--- | :--- |
| Carol | Bob's remote-use switch, the pairing code, her PINs, the card, Alice's list of computers | Bob: the remote card or none. Alice: PIN prompts, tries left, the list of computers |
| Visitors | Requests to Bob | A signature, a certificate, or a refusal |
| Bob | Dialing Alice, sending requests, offering the card's identity to visitors | Alice's announcements, the session, `card.status`, close reasons, progress, results |
| Alice | The card, her service on or off, her PIN prompts | The card's answers, the platform's NFC and Bluetooth state, Bob's close reasons |

Every story below is one of these feedback lines failing: missing, late,
or saying something that was not true.

## Stories from the Smart Card Office

Each story is a real failure, in costume. When a colleague behaves
badly, it is because the office rules let them; the fix is always a
rule, never a person. After each story, the dry part names the loss (L),
hazard (H), unsafe control action (UCA) and controller constraint (CC),
and where the rule lives in the spec.

### 1. The empty desk

**The good day.** Alice goes off duty. She tells every computer she is
talking to "I'm stopping, bye", pins a note on the board that only her
colleagues can read, and keeps her contact list. Bob answers "Bye,
thanks for letting me know", hangs up, tells Dave there is no remote
card today, and does not dial again until Alice announces she is back.

**The bad day.** Alice left without a word. By his rules, Bob read the
silence as a dropped call. He kept Dave's badge out, then dialed, and
dialed, and his sign said "Connecting to the phone…" all afternoon.
Worse, Alice's way of going off duty had also shredded her contact list,
so when she came back she had nobody to serve.

The same holds the other way. When Bob closes for the day, or a card
in his own reader takes over, he tells Alice "I'm off", and she answers
"Bye!". She then shows him as off, not as lost.

Why answer at all? A goodbye said into a line that has already gone
quiet is lost, and the speaker cannot tell: he goes home sure that
the other side knows. A goodbye nobody answers might not have been
heard. So the sender
waits for the echo within the time it already allows itself, and with
no echo it knows only what it knew before: the stated limit applies.

**Lesson:** a planned goodbye is a statement, not a fault, and it
needs an answer, because every control action needs feedback; calling
an empty desk stops after a bounded time.

- L-3; H-3, H-4, H-5. UCA-110, UCA-111, UCA-112, UCA-113, UCA-114,
  UCA-95, UCA-124.
- CC-113, CC-114, CC-115, CC-98, CC-123.
- Spec §4.5 items 3, 4, 6, 8 and 9; §8.3; §4.7; the echo of CC-123 is
  §7.1 item 7.

### 2. Ghosting on goodbye

**The bad day.** Carol turned Bob's remote use off, which forgets the
pairing. No conversation was open, so Bob threw away his keys and said
nothing. Alice kept Bob in her list and kept serving a pairing that no
longer existed. When Carol paired Bob again, Alice listed him twice,
with nothing to tell the two apart.

The mirror case: Alice forgot Bob, but Bob's notebook still said
"paired". He dialed, got turned away, and dialed again.

**The good day.** Whoever forgets says so, and the other side answers
with the same words. With a conversation open, Bob sends "we're done"
and waits up to a second for Alice's "we're done" back. With none open,
or when the echo did not come, Bob keeps the forgotten pairing in a
backlog, serving nothing from it, and watches for Alice. Days later she
walks back into the office; Bob sees her, says it as the first thing,
hears the echo, and only then destroys his keys. Had she never come back,
Bob would have let the pairing go thirty days after their last
conversation, as Alice does on her side. When Alice forgets Bob, she
tells him in the open conversation or as the first thing in the next
one, and Bob marks his notebook before he dials again. Bob then shows
one line: the phone forgot this computer.

**Lesson:** no ghosting, but no stalking either: say goodbye the next
time you meet, never by calling on a timer, and let go when the pairing
would have expired anyway.

- L-3; H-4, H-5. UCA-9, UCA-116, UCA-123, UCA-18, UCA-42.
- CC-2, CC-118, CC-123, CC-22, CC-40, CC-116.
- Spec §4.6 items 1 to 4 and 6; §4.6 item 7 says the phone forgets the
  computer the next time they meet (residual R-2).

### 3. The nameless colleague

**The bad day.** A pairing record on Bob's side had lost Alice's name.
Bob showed her as "Paired device", and Carol could not find where to
pair another phone. The name lived in a separate place from the
record, and the record outlived it. A tempting repair was to recognise
colleagues by name; but two computers can carry the same name, and one
would silently lose its pairing to the other.

**The good day.** Every introduction carries both names. The name is
part of the pairing record, stored and destroyed with it in one step.
Every new conversation carries both current names, so a renamed device
shows its new name from its next session. Names are labels only.

**Lesson:** a name belongs in the record it labels, stays current, and
identifies nothing.

- L-3; H-4, H-5. UCA-119, UCA-117, UCA-118.
- CC-119, CC-120.
- Spec §4.3 items 3 and 4; §7.1.

### 4. The note that was never filed

**The bad day.** Bob's disk was full. The pairing record could not be
written, the pairing failed without a word, and Carol only learned of
it much later.

**The good day.** Each side files its record and then says "filed".
The pairing is active only when both have heard it. A failed write
ends the pairing at once, and Carol is told that the pairing could not
be stored, with the cause.

**Lesson:** a failed write is never silent.

- L-3; H-4, H-5. UCA-120, UCA-8.
- CC-1, CC-121.
- Spec §4.3 item 4.

### 5. Crying wolf

**The bad day.** Bob's sign said "Connecting to the phone…" whether
Alice was at lunch, gone home, busy with another computer, or waiting
for Carol to type a PIN. Another sign said "phone connected" while no
card could be used. After a week nobody read the signs, and nobody
could act on them. In another build Bob went the other way: after a
failed login he quietly refused Dave's retries for fifteen seconds, so
Carol's own retry did nothing and nothing said why.

**The good day.** Bob shows one thing: the remote card, or no remote
card. Dialing, scanning and redialing happen in the background and are
never shown. The messages that name Alice are ones Carol can use: the
phone forgot this computer, which she can act on, and, right after Carol
typed Alice's code, that Bob is connecting to her. That one answers Carol's own action
and ends when Alice's card shows, Alice has none, or the redial window
ends; showing the
empty code entry instead told Carol the pairing she had just made had
failed.

**Lesson:** a status that is always on is noise. Show the result; speak
up only when the reader can do something about it, or when silence would
read as the failure of what they just did.

- L-3; H-5. UCA-114, UCA-64, UCA-7, UCA-92, UCA-53, UCA-49.
- CC-116, CC-62 (the states stay distinct on the wire, where programs
  read them).
- Spec §4.7, "Presenting the Custodian on a Requester".

### 6. One colleague, one queue

**The bad day.** Alice could talk to one computer at a time. While
a laptop held Alice's line all day for a browser that merely ran, Bob was hung up on every two seconds. He could not tell "busy"
from "gone", so he redialed at once, and his sign said the phone was
connected. The same happened between two programs on one computer.

**The good day.** Alice talks to every paired computer at once. The
card is one, so its work joins one queue: first come, first served, one
whole operation at a time. A computer that has to wait is told
"queued". The PIN prompt names the computer whose operation holds the
card. Each computer keeps one line to Alice, not one per program.

**Lesson:** never turn a colleague away in silence; queue the work and
say so.

- L-3; H-5, H-7. UCA-51, UCA-60, UCA-66, UCA-73, UCA-74, UCA-75, UCA-76.
- CC-58, CC-59, CC-74, CC-75, CC-76, CC-77, CC-78.
- Spec §8.2 items 2 and 3; §8.3; §11 item 1.

### 7. The visitor with the old photo

**The bad day.** Carol swapped the card on Alice's desk. Bob kept
handing out the old card's certificate. Dave presented it, the new card
signed, and the website refused a signature that did not match the
photo on the badge.

**The good day.** Every card report from Alice carries the card's
fingerprint. When it changes, Bob reads the certificate again before
he offers anything. He also checks each signature against the
certificate before he hands it to Dave.

**Lesson:** tell which card, not only that there is a card.

- L-3; H-3. UCA-16, UCA-61, UCA-63.
- CC-60, CC-61, CC-19.
- Spec §8.4 items 1 and 2.

### 8. The visitor who never asks twice

**The bad day.** Dave came in the moment Bob opened, before he had
reached Alice. Bob had no badge to give, so Dave went on without one.
The website let him in anonymously, and from then on Dave reused that
visit and never asked for a badge again until he was restarted. The
card was ready seconds later, and every login failed.

**The good day.** Bob offers the identity Alice last confirmed, also
between conversations. A request with no conversation open makes him
dial and wait, within Dave's own deadline. He takes the badge back
after two minutes with no word that the card is there, and at once when
Alice withdraws, the pairing ends, or another card appears.

**Lesson:** some visitors only ask once; have the answer ready, and
bound how long a stale answer may live.

- L-3; H-5, H-7. UCA-50, UCA-27, UCA-62, UCA-126.
- CC-64, CC-125.
- Spec §8.4 item 3. Residual R-3.

### 9. The PIN asked twice

**The bad day.** Carol typed PIN 1 on Alice and held the card to her.
The tap did not register. Alice said "card not found" and offered Retry.
Retry started over and asked for the PIN again. Carol, now in a hurry,
was one slip away from a wrong PIN that the card would count. In a
related case, Alice's reader had quietly switched off while Carol
answered a notification, and the screen still said "hold the card".

**The good day.** A missed tap is not a failure. Alice keeps the typed
PIN for the whole attempt, keeps waiting for the card, re-arms her
reader when she comes back to the front, and says so when it is not
listening. She asks for the PIN again only when the card refused it,
the holder cancelled, or the attempt ended.

**Lesson:** do not make the person repeat what the card never saw.

- L-2, L-3; H-5. UCA-32, UCA-33, UCA-34, UCA-36, UCA-37, UCA-40.
- CC-30, CC-31, CC-32, CC-34, CC-36, CC-38. These are rules of the
  phone application; the spec adds the tries left on a wrong PIN (§10.2).

### 10. The PIN said twice

**The bad day.** Three versions of one mistake. Alice remembered PIN 1
and sent it again after the card had refused it, spending a try. On the
organisation card, a parsing error after the card's first answer in the
secure-channel handshake cost a try. And once Alice skipped the PIN
check because she remembered doing it, but the card forgets after every
signature; the card refused, and Alice reported the outcome as unknown.

**The good day.** A remembered PIN ends when the card refuses it. Alice
reads the tries left before any PIN command, and again after any
outcome she could not see; with two or one tries left, or a count she
cannot read, she sends nothing and tells Carol why. With no tries left
the card answers for itself and spends nothing. She checks PIN 1 before
every signature.
A refusal is reported as a refusal.

**Lesson:** a PIN try is Carol's, not the software's. Never spend one on
a guess, and keep the last two for Ivan, the card issuer, whose
unblocking key works outside RAPP.

- L-2; H-1, H-5. UCA-121, UCA-35, UCA-47, UCA-41.
- CC-66, CC-33, CC-43, CC-39.
- Spec §10.2 (the retry floor); §11 item 2.

### 11. The desk that goes cold

**The bad day.** On the phone with NFC, every login opened a new
contact with the card and ran the full secure-channel handshake, which
takes seconds. A website that wants several signatures in one login met
a cold desk each time: the platform had switched the field off seconds
after the last command, and refuses a new one for several seconds after
the last one ends. Alice believed the card was still at hand, found it
gone only when the next request arrived, and answered "no card" with the
card lying on the phone.

**The good day.** Alice watches the platform's slot instead of
believing her own timer. While she holds the card she sends a harmless
command every few seconds to keep it warm, and the field stays as long
as the platform keeps the slot (at most 50 seconds). When the slot goes
she ends the session at once, so the platform's pause falls in idle
time. A refused slot is retried within the request's deadline, never
reported as no card. The field ends before a PIN prompt shows, and when
Alice goes to the background.

**Lesson:** follow the platform's real state, not a timer that guesses
it.

- L-3; H-3, H-5, H-7. UCA-43, UCA-44, UCA-45, UCA-46, UCA-88, UCA-89,
  UCA-90.
- CC-41, CC-42, CC-90, CC-91, CC-92, CC-93. These are rules of the
  phone application; the spec has none for the NFC field. Residual R-5.

### 12. The drawer that stayed shut

**The bad day.** Another program held a card session on Bob's own
reader. The token driver waited 60 seconds, retried, and blocked every
later card event. The app then told Carol to remove the card.

**The good day.** Every wait ends when the card leaves, is bounded,
and holds one slot only. A held card session that no longer holds a
card ends at once.

**Lesson:** one stuck drawer must not lock the office.

- L-3; H-3, H-7. UCA-122.
- CC-41.

### 13. The announcement nobody heard

**The bad day.** Bob shouted across the open-plan floor (multicast on
Wi-Fi): "Alice, are you there?" The wireless network drops such shouts
in bursts, and a phone saving power hears them only now and then. Bob
heard nothing six times in a row and said "no phone found". Alice was at
her desk the whole time, and a direct call to her number would have
been answered.

**The good day.** Bob remembers where Alice answered from and calls
there as well as shouting.

**Lesson:** a lost shout is not an empty room; call the number you know.

- L-3; H-3, H-5, H-7. UCA-48, UCA-49.
- CC-44, CC-116.
- Hierarchy §3.2.

### 14. Two receptionists, one code

**The bad day.** Alice and Oscar, two phones, were both showing pairing
codes. Carol typed Alice's code; Bob went to Oscar, who did not
recognise it, and Bob reported "code not accepted". The code was right.
In another case Alice was busy with another computer's attempt, closed
Bob's call, and Bob again reported a wrong code. And for a while Alice
locked her door after three failed attempts, as if Craig were at it,
though most of them were Oscar's visitors trying the wrong desk.

**The good day.** Bob tries every phone in pairing mode, one at a
time, before he says the code is wrong. A busy phone says "busy, try in
a moment", and Bob quietly does. Alice keeps no count of failures.
Against Craig the guard is the code's five-minute life, one attempt at a
time and half a second between attempts: at most 600 guesses of a 30-bit
code. Against Sybil's crowd of fake phones, or Mallory dressed as one,
Bob opens at most eight connections per typed code; they can delay him,
but they gain no guess and no pairing.

**Lesson:** "not this desk" and "not now" are different answers from
"wrong code".

- L-3; H-5. UCA-81, UCA-82, UCA-104, UCA-103, UCA-12.
- CC-83, CC-84, CC-108, CC-107.
- Spec §3.3; §4.2, "Busy Refusal" and "Trying Each Custodian in Pairing
  Mode". Residual R-7.

### 15. The badge that said "Lobby"

**The bad day.** Alice's PIN prompt showed who was asking with a line
taken from Bob's request. On a Mac that line read "macOS
CryptoTokenKit": the plumbing, not the website. Carol was asked to
approve a login on a name that said nothing.

**The good day.** The prompt names the paired computer, by the name
stored in its pairing record, and nothing Bob cannot vouch for. Bob
never invents the website's name.

**Lesson:** show only what you can stand behind.

- L-1; H-1, H-5. UCA-83, UCA-58, UCA-24.
- CC-85, CC-55, CC-25.
- Spec §11 item 1.

### 16. The reader that went home

**The bad day.** The card reader had been unplugged from the phone.
Bob still told Carol to insert the card into the phone's reader.

**The good day.** Alice reports whether a reader is attached. Bob
mentions the reader only while one is there; otherwise he asks Carol
to present the card to the phone.

**Lesson:** give instructions that can be followed now.

- L-3; H-5. UCA-79, UCA-80.
- CC-81, CC-82.
- Spec §8.4 items 1 and 6.

### 17. Two cards, one person

**The bad day.** Carol had a card in Bob's own reader and another on
Alice. Bob offered Dave both identities of one person, and kept Alice
busy for a computer that had a card of its own.

**The good day.** A card in Bob's own reader wins. While it is there,
Bob tells Alice "I'm off" (story 1), offers no phone identity, and
dials nothing. When it leaves, Bob picks up Alice again with the same
pairing.

**Lesson:** the card in front of you outranks the card down the hall.

- L-3; H-5, H-7. UCA-84, UCA-85, UCA-86.
- CC-86, CC-87, CC-88, CC-102.
- Hierarchy §5.2; spec §4.5 item 8.

### 18. What Olivia says

**The bad day.** Three times a colleague took Olivia's word as fact.
Bob asked her directory (the keychain) whether the badge existed; it said no while Dave was using it, and Bob took the
badge back twice. A glitched exchange with a card that sat in the
reader made Alice blank Carol's identity on her own screen, in the
middle of a PIN entry. And for days a failing NFC signature on a warm
phone was blamed first on the operating system and then on the app;
Olivia tells nobody when her NFC field is degraded.

**The good day.** Olivia's answer is a hint, not evidence. Presence
is the card Alice holds: a reader card from insertion to removal, an NFC
card from when Carol adds it until she removes it. An exchange the card
did not answer is a failed operation ("card error"), and the next one
asks for the card again. Before blaming a part, measure.

**Lesson:** a glitch is not an absence, and an answer from the platform
is not the truth.

- L-3; H-3, H-7. UCA-4, UCA-65, UCA-13, UCA-39, UCA-69.
- CC-10, CC-65, CC-70.
- Spec §8.4 item 1. Residual R-6.

### 19. The signature that looked wrong

**The bad day.** A website using TLS 1.2 asked for ECDSA with SHA-384
over a P-256 key, which TLS 1.2 allows. Bob's check guessed the hash
from the digest's length, then read the guess as a fixed pairing of
hash and curve, demanded a P-384 key, and threw away a correct
signature. Victor, the check inside Bob, was right to look and wrong
about what he saw. The failure was reported as if the card were the
wrong one,
so the search went to the card and the phone first.

**The good day.** Inside Bob, a request names the hash and nothing
about the key; the curve comes from the key. On the wire the key
profile and the algorithm are separate fields, and a P-256 key may sign
a SHA-384 digest (spec §9.2). Every local check ships with test
vectors for each curve and hash a browser can ask for, and a refusal
by the check is reported as the check's own.

**Lesson:** never store a guess as a fact, and never dress one failure
in another failure's clothes.

- L-3; H-5. Closed by CC-48, CC-49 (the check itself is CC-19).
- Spec §9.2.

### 20. Alice in the meeting room

**The bad day.** When Alice steps away from the screen, the phone's
system soon stops her network listener, but she still answers over
Bluetooth. Bob's directory still showed her network address, so Bob
kept calling it and never tried Bluetooth. An NFC card command from the
background was refused by the system, and Carol never learned that a
card was wanted.

**The good day.** In the background Alice takes down her network
listing and serves over Bluetooth. A failed network call while the
directory still shows her sends Bob's next call over Bluetooth. A card
command from the background first calls Carol with a notification and
waits a bounded time.

**Lesson:** when you move, update the directory; when a call fails,
try the other line.

- L-3; H-5, H-7. UCA-67, UCA-71, UCA-68, UCA-52.
- CC-68, CC-72, CC-69, CC-50.
- Spec §8.2 item 4 (`waiting_for_card`); §4.7 (`custodian_service` state
  `limited`). Residual R-11.

## Reference tables

Identifiers are never reused. An identifier no longer in force is listed
under "Retired identifiers" with the rule that holds instead.
[document-verification.md](../architecture/document-verification.md)
adds L-6 and H-8 for document verification.

### Losses

| ID | Loss |
| :--- | :--- |
| L-1 | A card operation (authentication or qualified signature) runs without the cardholder's current, informed consent. |
| L-2 | The card's PIN tries are spent, or the card is blocked, by operations the cardholder did not intend. |
| L-3 | The cardholder cannot log in or sign when they want to, and cannot tell why. |
| L-4 | The cardholder's presence, activity or identity is disclosed to a third party. |
| L-5 | A document other than the one the cardholder approved is signed. |

### Hazards

| ID | Hazard | Losses | The system must |
| :--- | :--- | :--- | :--- |
| H-1 | A command that spends a PIN try or uses a private key runs without consent for that command. | L-1, L-2, L-5 | Run such a command only under the holder's PIN entry for that request's frozen content, while it is current. |
| H-2 | One authorized operation runs on the card more than once. | L-1, L-2 | Run each authorization at most once, whatever the transport does. |
| H-3 | The computer offers an identity the phone cannot serve now. | L-3 | Offer an identity only while the phone can serve it, within a bounded grace. |
| H-4 | The two ends of a pairing disagree on whether it exists or what it grants. | L-1, L-3 | Keep both ends in agreement; a change on one side reaches the other. |
| H-5 | A person is shown a state that is not the system's, or cannot tell apart states that need different actions. | L-1, L-2, L-3 | Show the system's real state, and show differently what needs a different remedy. |
| H-6 | Something a third party can observe reveals a pairing, a card event or a person. | L-4 | Derive nothing observable from a stable identifier. |
| H-7 | The computer withholds or withdraws an identity the phone can serve. | L-3 | Withdraw an identity only on evidence that the phone cannot serve it. |

### Unsafe control actions

Type: N not provided when needed, P provided when unsafe, T too early
or too late, D applied too long. "Phone" is the custodian, "computer"
the requester; a part named after a colon is one program of it.

| ID | Controller | Unsafe control action | Type | Hazard | Closed by |
| :--- | :--- | :--- | :--- | :--- | :--- |
| UCA-1 | Phone | Commands the card with a key or PIN when the consent was for another request, or the deadline passed while suspended. | P | H-1 | CC-6, CC-66 |
| UCA-3 | Computer | Offers the identity when the phone cannot serve: card gone, service off, app quit, other network, pairing revoked. | P | H-3 | CC-4, CC-64, CC-114 |
| UCA-4 | Computer | Withdraws the identity on a wrong keychain answer. | P | H-7 | CC-10 |
| UCA-5 | Computer | Withdraws the identity long after the card left. | T | H-3 | CC-64; R-3 |
| UCA-6 | Computer | Dials a suspended phone whose record is still seen, and the dial hangs. | P | H-3, H-5 | CC-11, CC-72 |
| UCA-7 | Computer | Shows "phone not reachable" for many different causes. | P | H-5 | CC-116 |
| UCA-8 | Computer | Keeps a pairing the phone did not store. | P | H-4 | CC-1 |
| UCA-9 | Either | Does not tell the peer that it forgot the pairing. | N | H-3, H-4 | CC-2, CC-118 |
| UCA-11 | Phone | Does not show the PIN prompt (suspended), and the operation expires silently. | N | H-5 | CC-6 |
| UCA-12 | Computer | Takes a typed code after the offer has lapsed and reports a generic failure. | T | H-5 | CC-83 |
| UCA-13 | Phone | Reports a card present when no card can answer. | P | H-3 | CC-65 |
| UCA-14 | Phone | Publishes a discovery or withdrawal value derivable from a stable identifier. | P | H-6 | Spec §4.1, §4.3, §4.5 |
| UCA-15 | Computer | Sends a digest that is not of the document the user chose. | P | H-1 | CC-12, CC-109 |
| UCA-16 | Computer: browser module | Offers the certificate it holds in memory while another card is on the phone. | P | H-3, H-5 | CC-19, CC-60 |
| UCA-17 | Computer: browser module | Holds a session for hours with no login wanted. | D | H-6, H-7 | R-10 |
| UCA-18 | Computer: browser module | Redials after `pairing_revoked` before the record is marked revoked. | P | H-4 | CC-22 |
| UCA-19 | Computer: browser module | Holds the pairing lock while the record lacks a certificate, so nothing fetches it. | P | H-5, H-7 | CC-18 |
| UCA-20 | Computer: browser module | Sends a signature request the browser will stop waiting for. | P | H-2, H-5 | CC-20 |
| UCA-22 | Computer: browser module | Does not redial after a short loss. | N | H-7 | CC-115 |
| UCA-23 | Computer | Rewrites the pairing store while another process holds the record. | P | H-4 | CC-23 |
| UCA-24 | Computer: browser module | Sends an operation context that names a site it cannot know. | P | H-1, H-5 | CC-25, CC-55 |
| UCA-25 | Computer: browser module | Accepts `C_Login` with no token present. | P | H-5 | CC-27 |
| UCA-26 | Computer: browser module | Serves objects under old handles after the record changed. | P | H-3, H-5 | CC-27 |
| UCA-27 | Computer: browser module | Does not withdraw the token when the phone cannot serve. | N | H-3 | CC-64 |
| UCA-28 | Computer: browser module | Withdraws the token while an operation is in flight. | P | H-2, H-5 | CC-28 |
| UCA-29 | Computer | Forgets the pairing while another process holds the session, unknown to it. | P | H-4 | CC-23 |
| UCA-30 | Computer: browser module | Redials in a loop while the phone is not in sight. | D | H-6 | CC-115 |
| UCA-31 | Computer | Opens a session without the pairing's lock. | P | H-2, H-4 | CC-29, CC-78 |
| UCA-32 | Phone | Asks PIN 1 again after an attempt ended for a reason the PIN had no part in. | P | H-5 | CC-30 |
| UCA-33 | Phone | Says "card not found" when no card answered, and Retry restarts at the PIN. | P | H-5 | CC-31 |
| UCA-34 | Phone | Times out the attempt before the person could tap. | T | H-5 | CC-32 |
| UCA-35 | Phone | Resends the held PIN after an unknown outcome without reading the tries left. | P | H-5 | CC-33 |
| UCA-36 | Phone | Asks the PIN again without showing the tries left. | P | H-5 | CC-34 |
| UCA-37 | Phone | Does not re-arm the reader on resume. | N | H-5 | CC-36 |
| UCA-38 | Phone | Shows a computer's PIN prompt over a local one. | P | H-1, H-5 | CC-35 |
| UCA-39 | Phone | Reports the card present from the last tag event. | P | H-3 | CC-65 |
| UCA-40 | Phone | Repeats the secure channel with a CAN the card rejected. | P | H-5 | CC-38 |
| UCA-41 | Phone | Keeps a verified PIN past its purpose or for another card. | P | H-1, H-5 | CC-39, CC-66 |
| UCA-42 | Computer | Shows the phone as paired after the phone forgot the computer. | P | H-5 | CC-40, CC-116 |
| UCA-43 | Phone | Keeps a card session on an NFC field that has gone idle. | P | H-3 | CC-41, CC-93 |
| UCA-44 | Phone | Opens the NFC slot inside the platform's pause. | T | H-3 | CC-42 |
| UCA-45 | Phone | Answers "card unavailable" for a pause it caused. | P | H-5 | CC-42 |
| UCA-46 | Phone | Ends a dead card session only when the next request arrives. | N | H-3 | CC-41 |
| UCA-47 | Phone | Skips the PIN check, trusting its memory of an earlier one. | P | H-3, H-5 | CC-43 |
| UCA-48 | Computer | Searches for the phone by multicast alone. | P | H-3, H-7 | CC-44 |
| UCA-49 | Computer | Reports no phone after a search that never reached it. | P | H-5 | CC-44, CC-116 |
| UCA-50 | Computer: browser module | Offers no token before the session opens, and the browser never asks again. | N | H-5, H-7 | CC-64, CC-125 |
| UCA-51 | Phone | Refuses a second computer's session. | N | H-5, H-7 | CC-58, CC-74 |
| UCA-52 | Computer | Releases an idle Bluetooth link to a backgrounded phone. | P | H-5, H-7 | CC-50 |
| UCA-53 | Computer | Says the phone is not found when it is only in the background. | P | H-5 | CC-116 |
| UCA-54 | Computer | Closes a too-small Bluetooth link without naming the cause. | P | H-5 | CC-52 |
| UCA-55 | Computer | Dials strangers' phones again and again in a crowded room. | P | H-7 | CC-53 |
| UCA-56 | Computer | Asks the operating system to bond with the phone. | P | H-5, H-6 | CC-54 |
| UCA-57 | Phone | Signs a login without a prompt when a program other than the browser asks. | P | H-1 | CC-56; R-4 |
| UCA-58 | Computer | Names a website it cannot know in the operation context. | P | H-1, H-5 | CC-55, CC-85 |
| UCA-59 | Phone | Admits only pairing on its Bluetooth peripheral. | N | H-5, H-7 | CC-57 |
| UCA-60 | Phone | Serves one computer and drops another without a word. | P | H-5, H-7 | CC-58, CC-74 |
| UCA-61 | Phone | Reports the card gone only on the session it is serving. | N | H-3 | CC-61 |
| UCA-62 | Computer | Keeps offering the identity after its session closed. | D | H-3 | CC-64; R-3 |
| UCA-63 | Phone | Reports presence without saying which card. | P | H-3 | CC-60 |
| UCA-64 | Computer | Shows one state for many different situations. | P | H-5 | CC-116, CC-62 |
| UCA-65 | Phone | Reports a reader card absent after one glitched exchange. | P | H-3, H-7 | CC-65 |
| UCA-66 | Phone | Admits a session on a second transport that cuts an operation. | P | H-5, H-7 | CC-74 |
| UCA-67 | Phone | Keeps its network listener published while suspended. | P | H-5, H-7 | CC-68 |
| UCA-68 | Phone | Commands an NFC card from the background. | P | H-5, H-7 | CC-69 |
| UCA-69 | Phone | Reports the card absent while locked only because protected data is unavailable. A locked phone admits the session and answers card status, but starts no credential use (`credential-custody.md`). | P | H-7 | CC-70 |
| UCA-70 | Computer | Opens a second Bluetooth link from another of its programs. | P | H-5, H-7 | CC-78 |
| UCA-71 | Computer | Keeps dialing the network address of a suspended phone. | P | H-7 | CC-72 |
| UCA-72 | Phone | Refuses a Bluetooth write with an error that starts operating-system bonding. | P | H-5 | CC-73 |
| UCA-73 | Phone | Names a computer other than the one whose operation holds the card. | P | H-1, H-5 | CC-75 |
| UCA-74 | Phone | Does not release the card's turn after an operation expired or lost its session. | N | H-5, H-7 | CC-76 |
| UCA-75 | Phone | Takes down another session's prompt. | P | H-5, H-7 | CC-77 |
| UCA-76 | Computer | Opens extra sessions, or redials on a short fixed timer. | P | H-7 | CC-78 |
| UCA-77 | Computer | Ends the Mac app when its window closes. | P | H-7 | CC-79 |
| UCA-78 | Phone | Holds unauthenticated connections without a bound. | D | H-7 | CC-80 |
| UCA-79 | Computer | Asks for the card in a reader the phone does not have. | P | H-5 | CC-81, CC-82 |
| UCA-80 | Computer | Gives no instruction that can be followed when card and reader are gone. | N | H-5 | CC-82 |
| UCA-81 | Computer | Reports the code as not accepted before trying every phone in pairing mode. | P | H-5 | CC-83 |
| UCA-82 | Computer | Names a phone before the code is accepted. | P | H-5 | CC-84 |
| UCA-83 | Phone | Shows the computer's operation context in the PIN prompt. | P | H-1, H-5 | CC-85 |
| UCA-84 | Computer | Uses the phone while a card is in its own reader. | P | H-5, H-7 | CC-86 |
| UCA-85 | Computer | Keeps the phone suppressed after the local card left. | D | H-5, H-7 | CC-87, CC-102 |
| UCA-86 | Computer | Sends a signature to the phone while a local card is present but not ready. | P | H-5 | CC-88 |
| UCA-87 | Cardholder | Forgets a pairing by a slip. | P | H-4, H-5 | CC-89 |
| UCA-88 | Phone | Keeps the NFC field while a PIN prompt shows under the system sheet. | P | H-5, H-7 | CC-90 |
| UCA-89 | Phone | Commands the card through a warm field from the background. | P | H-5, H-7 | CC-91 |
| UCA-90 | Phone | Summons the holder while a warm field already holds the card. | P | H-7 | CC-92 |
| UCA-91 | Computer | Talks to the phone while remote use is off. | P | H-3, H-5, H-6 | CC-100 |
| UCA-92 | Computer | Shows the switch as connected when no session is open. | P | H-5 | CC-116 |
| UCA-93 | Computer | Asks for network or Bluetooth permission at launch while remote use is off. | P | H-5 | CC-96 |
| UCA-95 | Computer | Stops using the phone without telling it. | N | H-5 | CC-98 |
| UCA-96 | Cardholder | Turns remote use off meaning only to pause. | P | H-7 | R-8 |
| UCA-97 | Computer | Does not tell the phone that a local card suspended remote use. | N | H-5 | R-9 |
| UCA-98 | Either | Expires a pairing that is in use. | P | H-4, H-7 | CC-103 |
| UCA-99 | Either | Never expires a pairing whose peer is gone for good. | N | H-1, H-6 | CC-103 |
| UCA-100 | Phone | Remembers operation identifiers without a bound. | P | H-3 | CC-104 |
| UCA-101 | Either | Admits a batch whose result cannot fit one frame. | P | H-2, H-5 | CC-105 |
| UCA-102 | Either | Serves a session after its pairing was forgotten. | P | H-1, H-4 | CC-106 |
| UCA-103 | Phone | Ends the offer after failed attempts that were not guesses. | P | H-5 | CC-107 |
| UCA-104 | Computer | Reports the code as not accepted when the phone was only busy. | P | H-5 | CC-108 |
| UCA-105 | Computer | Sends a digest that is not of the octets the document format signs. | P | H-1 | CC-109 |
| UCA-106 | Computer | Shows a document name that does not match the digest at its position. | P | H-1, H-5 | CC-110 |
| UCA-107 | Computer | Writes a document as signed with a signature that does not belong to it. | P | H-5 | CC-111 |
| UCA-108 | Computer | Builds the documents on a certificate that is not the signing certificate. | P | H-5 | CC-112 |
| UCA-109 | Computer | Writes documents before every signature of the batch is checked. | T | H-5 | CC-111 |
| UCA-110 | Phone | Stops serving without saying so. | N | H-3, H-5 | CC-113 |
| UCA-111 | Phone | Revokes every pairing when the holder only meant to stop serving. | P | H-4, H-7 | CC-113 |
| UCA-112 | Computer | Keeps offering the identity after a verified withdrawal. | D | H-3 | CC-114 |
| UCA-113 | Computer | Keeps dialing without end. | D | H-5, H-6 | CC-114, CC-115 |
| UCA-114 | Computer | Shows the phone's state ("Connecting to the phone…") when the holder can do nothing with it. | P | H-5 | CC-116 |
| UCA-115 | Computer | Dials late after the phone serves again. | T | H-7 | CC-117 |
| UCA-116 | Computer | Does not tell the phone it forgot the pairing when no session is open. | N | H-4, H-5 | CC-118; R-2 |
| UCA-117 | Phone | Replaces an older pairing because a new one has the same name. | P | H-4, H-7 | CC-119 |
| UCA-118 | Phone | Lists one computer twice. | N | H-5 | CC-118, CC-119; R-2 |
| UCA-119 | Either | Shows the peer without a name, or under an old one. | P | H-5 | CC-120 |
| UCA-120 | Either | Reports the pairing made when its own store failed. | P | H-4, H-5 | CC-121 |
| UCA-121 | Phone | Sends a remembered PIN 1 again after the card refused it. | P | H-1 | CC-66, CC-43; spec §10.2 |
| UCA-122 | Phone | Holds a card session that blocks every later card event. | D | H-3, H-7 | CC-41 |
| UCA-123 | Computer | Keeps trying to deliver its revocation past the pairing's idle expiry, or dials for it on a timer rather than when the phone appears. | D | H-4, H-6 | CC-118 | Every forget a computer's user makes marks the record forgotten and keeps its key for the `pairing_revoked` close alone, in a revocation backlog apart from the one active pairing; a forgotten record offers no identity, starts no operation, presents no card and is never selected. The close goes out at once on an open session; otherwise, and when its echo did not come within 1 s, the computer watches for the phone's discovery hint or BLE advertisement and opens one connection each time the phone appears, never on a timer. The key and record go on the phone's echo, or 30 days after the pairing's last established session, whichever is first. Several forgotten pairings may wait at once. Automatic drops send nothing. | §4.6 items 3 and 6 |
| UCA-124 | Either | Acts as if the peer received its goodbye (`service_withdrawn` or `pairing_revoked` close) when the peer never did. | P | H-4, H-5 | CC-123 |
| UCA-125 | Computer | Sends a made-up file name, or one the asking program supplied, for a signature whose program named no document. | P | H-1, H-5 | CC-124 |
| CC-125 | Every browser-module call that can show whether the phone's token is there or what it holds reads the phone first, as a request for the card: with no session open the computer dials, and the call waits at most 3 s for a session to confirm the card. No call is granted a wait for 5 s after a wait that raised the token, nor for 30 s after one that raised none; a call during a wait shares it; the non-blocking event poll never waits. The token stands only on a certificate the phone confirmed on a session. | §8.4 item 3 |
| UCA-126 | Computer: browser module | Answers the browser's question about the phone's token from what it held before the question, without asking the phone, so a handshake that lists no slots finds no token. | N | H-7 | CC-125 |

### Controller constraints in force

| ID | Constraint | Spec |
| :--- | :--- | :--- |
| CC-1 | Each side sends `pairing.stored` after storing its record; a pairing is active only when both were exchanged, and a record left unconfirmed is revoked. | §4.3 item 4 |
| CC-2 | An endpoint that revokes a pairing tells its peer with a `pairing_revoked` close, in session or on the next one. | §4.6 items 1, 2 |
| CC-4 | The phone reports card presence in `card.status` on the session. | §8.4 item 1 |
| CC-6 | The phone sends `consent_shown` once a PIN prompt is on screen, and runs an operation's deadline on a clock that keeps going through suspension; an operation past its deadline is cancelled with no prompt. | §8.1 item 2, §8.2 item 3 |
| CC-10 | The computer treats keychain and token queries as hints and never withdraws an identity on their answer alone. | |
| CC-11 | The computer bounds every dial and every operation with its own deadline, so a local program always gets an answer. | |
| CC-12 | The computer's path from the chosen file to the digest it sends is analysed and tested as its own loop (CC-109 to CC-112). | |
| CC-18 | Whichever process on the computer holds the session reads a missing certificate on it and holds it in memory only; no store keeps it ([certificate custody](certificate-custody.md)), and the read spends no PIN try. | |
| CC-19 | The computer checks every signature against the confirmed certificate's key before handing it on; a signature that fails is a device error, never handed on, and the certificate is dropped so the next session reads the card again. | |
| CC-20 | The browser module's operation deadline is one named constant below the browsers' handshake timeouts, sent as the operation's lifetime; a late result ends with its session. | §8.1 |
| CC-22 | A `pairing_revoked` close marks the record revoked before any new dial. | §4.6 item 4 |
| CC-23 | The pairing lock is a session lock that the kernel releases when its holder exits; record rewrites are atomic renames after a re-read; the session holder re-reads the record at every ping and ends a revoked pairing's session with `pairing_revoked`. | §4.6 item 1 |
| CC-25 | The operation context names the computer and nothing it cannot know; no program invents a website. | §11 item 1 |
| CC-27 | `C_Login` succeeds only while the token is present; a changed record withdraws the token and offers a new one, so no handle outlives its object. | |
| CC-28 | A withdrawal during an operation waits for that operation's result or deadline; the operation is never resent. | |
| CC-29 | Every process on the computer opens a session only under the pairing's lock; one that cannot take it opens nothing. | |
| CC-30 | The phone keeps the typed PIN for the whole preparation and sends it only to the card first seen; it asks again only when the card refused it, the tries left fell, the holder cancelled or the dialog ended. | |
| CC-31 | A tap that did not happen is not a failure; "card not found" is never shown; Retry starts from the tap. | |
| CC-32 | The attempt's timeout counts from the last reader change, only in the foreground with the reader armed; leaving the foreground ends nothing. | |
| CC-33 | The phone reads the tries left before the first PIN command and after every unknown outcome; holding PIN 1 across operations starts only at the five-try limit, and any other reading destroys the held PIN 1. | §10.2, §11 item 2 |
| CC-34 | Every PIN prompt shows the tries left once the card has told them. | §10.2 |
| CC-35 | One PIN prompt is on screen at a time; a computer's request waits behind a local dialog, within its own deadline. | |
| CC-36 | The reader is re-armed when the app resumes, and the dialog says so when it is not armed. | |
| CC-38 | A CAN the card rejected is asked again before the next secure-channel attempt. | |
| CC-39 | A retained PIN is bound to the card that verified it and to its purpose. | §11 item 2 |
| CC-40 | A computer process that holds no session re-reads the pairing record at an interval, so a revocation another process recorded reaches its screen. | |
| CC-41 | The phone's held card session follows the platform's NFC slot: it watches the slot, ends the session at once when the slot loses the card, and keeps an idle session alive with a harmless command every few seconds. | |
| CC-42 | Opening the NFC slot retries through the platform's pause, within the request's deadline; that refusal is never reported as no card. | |
| CC-43 | The phone keeps no belief about the card's security status between operations: PIN 1 is verified before every signature, and a refused command is reported as refused. | §11 item 2 |
| CC-44 | The computer remembers the addresses its phone answered from and sends every search to them as well as to the group; the cache goes with the pairing. | Hierarchy §3.2 |
| CC-48 | Inside the computer, a signature request names the hash of its digest and nothing about the key; the curve is read from the key; where no hash is named (PKCS#11 `CKM_ECDSA`) the request carries the digest's length as a length. On the wire this maps to `key_profile` from the key and `algorithm` from the hash. | §9.2 |
| CC-49 | Every local signature check ships with test vectors for each curve and hash a browser can ask for, and its refusal is reported as its own. | |
| CC-50 | Over Bluetooth the computer holds the link and session while the pairing is usable and remote use is on, and never releases it for idleness. | §8.3 |
| CC-52 | The computer reads the negotiated ATT MTU before its first write; below 512 it drops the connection and records that cause apart from other failures. | §5.2 item 1 |
| CC-53 | Over Bluetooth the computer dials first the advertiser that last routed its preamble, then others by signal strength, each at most once per scan window. | |
| CC-54 | No link-layer bonding: the computer never asks for it, and the phone's characteristics need no link-layer security. | |
| CC-55 | The operation context never names a website the computer cannot know. | §11 item 1 |
| CC-56 | Because the phone may hold PIN 1 and then sign logins without a prompt, the computer lets only its user's own processes reach its requester. | |
| CC-57 | The phone's Bluetooth peripheral admits session preambles and routes them as the stream transport does. | §2.2.1 |
| CC-58 | The phone serves every paired computer at once, one session per connection, with no quota; a refusal is a close with a reason, never a silent drop. | §8.3 |
| CC-59 | The card runs one whole operation at a time, first come first served across sessions; a waiting operation is told `queued`. | §8.2 item 2 |
| CC-60 | `card.status` carries the authentication certificate's fingerprint; the computer reads the certificate again when it changes. | §8.4 item 2 |
| CC-61 | Every change of card presence goes to every open session. | §8.4 item 1 |
| CC-62 | Every state a peer needs is distinct on the wire: queued, waiting for the card, PIN prompt shown, and each close reason. Busy and gone are never the same message. | §7.1, §8.2 |
| CC-64 | The computer offers an identity on a fingerprint the phone confirmed, also between sessions; a request with no session dials and waits within the program's deadline. It withdraws after 120 s with no session or with absence reported, and at once on a forget or revocation, its own withdrawal, the phone's verified withdrawal or `card_unavailable` close, or a different card. | §8.4 item 3 |
| CC-65 | Presence is the card the phone holds: a reader card from insertion to removal, an NFC card from the holder adding it to removing it. An operation the card did not answer ends with `card_error` and leaves presence unchanged. | §8.4 item 1 |
| CC-66 | PIN 1 is asked once and held only in memory, starting only at the five-try limit. It is discarded if the card returns any other counter reading, is removed or replaced, the holder clears it, the process ends, or the device restarts. PIN 2 is asked for every signature or batch. The PIN prompt is the consent. | §8.2 item 3, §11 item 2 |
| CC-68 | In the background, with Bluetooth serving, the phone closes an idle stream session and unpublishes its stream listener; it publishes again in the foreground. | |
| CC-69 | An NFC card command from the background first summons the holder (a notification and `waiting_for_card`) for a bounded wait; otherwise the operation ends with `card_error`. | §8.2 item 4 (`waiting_for_card`) |
| CC-70 | While the phone is locked and protected data is unavailable, it keeps the card status it last read. It admits the session and answers card status, but starts no credential use (`credential-custody.md`). | §8.2 item 3 |
| CC-72 | A stream dial that fails while discovery still shows the phone sends the next dial over Bluetooth. | |
| CC-73 | A refused or closed Bluetooth link answers writes with "write not permitted", never an authentication or encryption error. | |
| CC-74 | No session is displaced or refused for being busy, on any transport, and no session cuts another's admitted operation. | §8.2 item 2, §8.3 |
| CC-75 | The PIN prompt and the summons name the computer whose operation holds the card. | §11 item 1 |
| CC-76 | An operation that expires or loses its session releases the card's turn and takes down its prompt at once. | §8.1 |
| CC-77 | Ending one session takes down only that session's prompt. | |
| CC-78 | A computer holds at most one session to its phone across its transports and programs; on a Mac only the app holds it and the extension hands its operations over; failed dials back off from 2 to 32 s. | |
| CC-79 | The Mac app keeps running without its window and starts at login. | |
| CC-80 | An unauthenticated connection that sends no whole frame in 5 s is closed, and at most 8 wait at once. | |
| CC-81 | `card.status` says whether a contact reader is attached to the phone. | §8.4 item 1 |
| CC-82 | The computer names the phone's reader only while the card is absent and a reader is attached; otherwise it asks for the card to be presented to the phone. | §8.4 item 6 |
| CC-83 | The computer tries every phone in pairing mode with the typed code, one at a time, at most 8 connections, before it reports the code as not accepted. | §4.2 |
| CC-84 | Until a code is accepted the computer names no phone. | §4.2 |
| CC-85 | The PIN prompt names the paired computer by its stored display name and never a website; the operation context is not shown. | §11 item 1 |
| CC-86 | While a card is in a reader attached to the computer, the computer holds no phone session, dials and scans nothing, and offers no phone identity; local presence is read at each decision. The only exception is the revocation backlog of CC-118. | Hierarchy §5.2 |
| CC-87 | When the local card leaves, discovery and dialing resume at once with the same pairing. | Hierarchy §5.2 |
| CC-88 | A signature goes to the local card whenever one is in a local reader; the phone signs only when none is. | |
| CC-89 | Forgetting asks no confirmation, and the display then follows what is stored. | |
| CC-90 | The NFC field ends before any PIN prompt shows. | |
| CC-91 | Going to the background ends the NFC field. | |
| CC-92 | An operation that finds a warm field still holding the card runs on it while the app is only inactive under its own sheet, with no summons. | |
| CC-93 | The NFC field has no idle limit of its own: it ends when the slot is gone, a keep-alive or operation goes unanswered, 50 s after it was asked for, serving stops, or the last session closes. | |
| CC-96 | The computer asks for network and Bluetooth permission only when the holder turns remote use on. | Hierarchy §5.2 |
| CC-98 | A computer that withdraws, for a local card or on quitting, sends `service_withdrawn` on every open session and keeps its pairing; quitting waits at most 1 s. The phone shows that computer as off until its next session. | §4.5 items 8, 9 |
| CC-100 | The holder's click turning remote use off forgets the pairing: it closes sessions, withdraws every phone identity, halts discovery apart from the revocation backlog of CC-118, and asks no confirmation. Apart from pairing another phone, it is the computer's only forget. | §4.6 item 6, hierarchy §5.2 |
| CC-102 | A local card suspends remote use while present: the computer withdraws as CC-98 says and tries no pairing code; when the card leaves, remote use resumes with the same pairing. | §4.5 item 8, hierarchy §5.2 |
| CC-103 | Each endpoint revokes a pairing with no established session for 30 days, by its own clock and never during a session; the recorded time only moves forward; expiry sends nothing. | §4.6 item 5 |
| CC-104 | The phone remembers at most 4096 operation identifiers per session; past that, a fresh identifier closes that session alone. | |
| CC-105 | A batch is admitted only when its largest possible result fits one frame; any other is refused before the card or the holder is asked. | |
| CC-106 | The operation bridge checks the pair record under its lock at every call; a forgotten record turns the call into the `pairing_revoked` close. | §4.6 |
| CC-107 | The phone keeps no count of failed pairing attempts; only the offer's lifetime, its use, or the holder ends it. | §3.3 |
| CC-108 | A phone that cannot admit an attempt answers `pairing-busy` with a wait; the computer tries it again later and shows nothing meanwhile. | §4.2, "Busy Refusal" |
| CC-109 | Each digest comes from the document plan built around the phone's certificate, with the algorithm taken from that certificate's key. | §9.3 |
| CC-110 | Document names and package entries are sent in order, never shortened or dropped; a package is alone in its request. | §9.3 |
| CC-111 | Nothing is written until every signature verifies at its own position; otherwise the whole batch is refused. | |
| CC-112 | The phone's certificate is admitted only with non-repudiation key usage and an RSA 2048 or 3072 or P-384 key. | |
| CC-113 | The phone's remote access off is withdrawal only: every pairing is kept, and turning it on again serves at once under a fresh instance name. | §4.5 items 3, 4 |
| CC-114 | On `service_withdrawn`, `card_unavailable` or a matched withdrawn record, the computer withdraws the identity at once and dials nothing until the phone announces itself again. | §4.5 item 6, §8.4 item 5 |
| CC-115 | The computer dials only when the phone appears, when a local program asks, or within the 120 s redial window after a loss or a first failed dial; a protocol violation opens no window; no dial runs on a free-running timer. | §8.3 |
| CC-116 | The computer presents the phone only through its card: the identity while a session confirms it, otherwise "no remote card" with no reason. Dialing and scanning are never shown. The exceptions are the line that the phone forgot this computer, and, from a pairing ceremony this computer's user completed until the phone's identity or a request for its card is shown, the phone reports no card, or `redial_window_ms` passes, that it is connecting to the phone just paired. The switch shows on or off, and blocked for the computer's own Bluetooth or permissions. | §4.7 |
| CC-117 | Discovery runs continuously while remote use is on, and a session record that appears is dialed at once, before any Bluetooth scan. | §8.3 |
| CC-118 | A computer's forget is agreed, not assumed: the forgotten pairing keeps its key for the `pairing_revoked` close alone, in the revocation backlog. The close goes out at once on an open session; otherwise, or without its echo within 1 s, the computer opens one connection each time the phone appears, by the route that appeared, whose first message is the close. Only the phone's echo, or its own `pairing_revoked`, destroys the key and the record; the pairing's idle expiry ends the wait untold. Automatic drops send nothing. | §4.6 items 3 and 6, §7.1 item 7 |
| CC-119 | Nothing finds, matches, replaces or revokes a pairing by its display name or anything else the peer says about itself. | §4.3 item 3 |
| CC-120 | Every `pairing.hello` carries the sender's display name, stored in the pair record in the same commit; every session carries both current names, and a changed name replaces the stored one. | §4.3 items 3, 4; §7.1 |
| CC-121 | A failed store of the pair record ends the pairing with `pairing.abort` and tells the user why. | §4.3 item 4 |
| CC-122 | Only the holder's click moves the computer's remote-use switch; a revocation by the phone or idle expiry leaves it on and offers the code entry. | §4.7, hierarchy §5.2 |
| CC-123 | A goodbye is acknowledged: the receiver of a `session.close` answers with its own close carrying the same reason, then closes the transport. The sender waits for the echo within its existing bound (1 s) and treats a goodbye without the echo as not known to be delivered: a computer keeps a forgotten pairing whose close was not echoed in its revocation backlog (CC-118), and otherwise the stated limit for that case applies (R-1, R-2, R-9). | §7.1 item 7; §4.5 items 8 and 9; §4.6 item 4; X-12 |
| CC-124 | A signature a program asks for with a digest alone carries, as its `document_name`, a description the computer composes: the program as the computer identifies its image, the computer, and that no document was named. Refusing the request instead would leave the holder no way to sign from such a program. | §9.3; §11 item 1 |

### Retired identifiers

| ID | The rule in force |
| :--- | :--- |
| UCA-2, UCA-21 | None needed: an operation lives inside its session and a repeated read or signature changes nothing on the card (§8.1 item 3). |
| UCA-10 | A wrong PIN is handled on the phone, and the computer learns nothing of it (§10.2). |
| UCA-94 | CC-102, CC-122. |
| CC-3, CC-7, CC-24, CC-51, CC-95 | CC-116 (and CC-2 for a forgotten pairing). |
| CC-5 | §8.1: no acknowledgements; a computer without a result starts a new operation. |
| CC-8, CC-37, CC-63 | CC-65. |
| CC-9, CC-15 | No constraint; residual R-6. |
| CC-13, CC-14 | CC-41, CC-93. |
| CC-16, CC-21, CC-46 | CC-64, CC-115. |
| CC-17 | CC-118. |
| CC-26 | CC-115 (§8.3). |
| CC-45 | CC-44, CC-116. |
| CC-47, CC-67 | CC-58, CC-74. |
| CC-71 | CC-78. |
| CC-94 | CC-100. |
| CC-97, CC-99, CC-101 | CC-102, CC-122. |

### Residual risks, accepted

| ID | Risk | Bound |
| :--- | :--- | :--- |
| R-1 | An endpoint that crashes, is killed by its operating system or loses power sends nothing: no withdrawal, no revocation. | The peer sees a loss: 30 s of silence ends the session, and the redial window and identity grace end after 120 s. A pairing it meant to forget lasts until idle expiry (§4.6 item 8). |
| R-2 | A computer that does not meet the phone again before the forgotten pairing's idle expiry passes cannot deliver its revocation: the phone lists the computer, twice after a new pairing, since fresh keys make the two unlinkable. | Idle expiry, at most 30 days after the pairing's last session (§4.6 items 5 and 7). The computer destroys its key at the same time, so nobody can use the old pairing. |
| R-3 | A computer may offer an identity whose phone has left. | 120 s; a login then fails after the program's deadline (§8.4 item 3). |
| R-4 | While the phone holds PIN 1, a paired computer can obtain login signatures without a prompt: one per tap for an NFC card, several within one warm field, none needed for a card in a reader. | Ends when the card is removed or replaced, refuses the PIN, the process ends or the device restarts; a warm field lasts at most 50 s (CC-93). Spec §11 item 2. |
| R-5 | The platform's NFC slot has its own life and pause; a request that meets its end pays the pause. | Retried within the request's deadline (CC-42). |
| R-6 | The platform gives no feedback when its NFC field is degraded. | The failure is reported as `card_error`, and the next operation asks for the card again. |
| R-7 | A device that keeps the pairing slot busy, or rogues that take up the 8 connections, deny pairing for one code. | No extra guess is gained; the offer ends after 5 minutes (§3.3, §12). |
| R-8 | A slip on the remote-use switch forgets the pairing. | One new pairing ceremony. |
| R-9 | A local card inserted while no session is open tells the phone nothing, and a withdrawal close whose echo does not come within its second may not have reached it. | The phone sees a loss, or nothing until the next session. |
| R-10 | The browser module keeps a session open while the phone is in sight, at some battery cost. | Chosen so that a login can start at once (§8.3). |
| R-11 | Over Bluetooth a Mac reaches the phone only while its app runs, and an NFC command from the background needs the holder to answer a notification. An iPad's extension dials its own session beside its app's. | The phone serves all of them (CC-58). |
| R-12 | The phone's own preparation of a reader card may run between two card exchanges of one operation. | It never splits one exchange and sends no PIN. |
| R-13 | A wall clock set far ahead expires pairings early; one set back delays expiry. | A new pairing; the recorded time never moves back. |
| R-14 | A card other than the one read that shares the access number signs one login challenge that is never delivered; a renewed card costs one failed login. | The check of CC-19 drops the certificate. |
| R-15 | A timestamp authority that refuses one document of a batch leaves the others written. | The refused one is reported. |
