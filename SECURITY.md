# Security policy

## Reporting a bug

Open an issue. That is the entire process — no embargo policy, no channel to
find, no gatekeeping, and nothing to fill in beyond the finding itself.

Security-sensitive findings may go through GitHub's **Report a vulnerability**
action on the repository Security tab if you prefer, but it is neither required
nor faster. Public is fine.

Report what is broken: `file:line`, the quoted code, a concrete scenario, and
plainly what you could not establish. You do not need a working exploit to file,
and you do not need to soften the finding — "I could not confirm this" is more
useful than a confident guess. Severity is your honest judgement, not a
formality.

## Never in a report

Do not post real credentials, personal data, or anything that identifies an
individual — in a public issue or anywhere else. Synthetic values and
structural descriptions are enough to work from.

## Inviolable Rule #1: PIN codes never travel over the network

PIN codes (PIN1 and PIN2) NEVER leave the mobile device when accessed via RAPP.
RAPP must absolutely deny and preclude all attempts to transport PIN codes
anywhere:

- The protocol wire format has no field or message for PIN codes.
- PIN1 remains in protected on-device cache on the phone.
- PIN2 prompts appear exclusively on the mobile device's screen.
- The host computer operates via a protected authentication path without any
  PIN prompts or transport.

## Inviolable Rule #2: Zero PIN and PIN-length logging across all environments

PIN codes (PIN1, PIN2), PUK, and CAN are never logged in any development, test,
staging, or production context. Furthermore, PIN lengths and candidate digit
counts must never be logged or rendered in error messages or diagnostic traces.
Length disclosures leak secret entropy and reduce keyspace security. Diagnostic
output (`diag!`), tracing, event logs, and `Display`/`Error` formatting must
never include PIN values, PIN lengths, or candidate digit counts.

If specialized debugging is ever needed, it is done via temporary private
harnesses and never checked into the repository.

## Status

The public tree is pre-release. No released version is currently designated as
security-supported.
