# refineid-pcsc

PC/SC smart card transport adapter and reader backend for RefineID.

This crate provides the platform PC/SC integration over WinSCard on Windows,
`PCSC.framework` on macOS, and `pcsc-lite` on Linux:

- **`PcscBackend`**: Reader enumeration, presence detection, and exclusive session opening.
- **`PcscCard`**: Connected card handle implementing `refineid_apdu::CardTransport`.
- **T=0 protocol loop**: Handles `SW=61xx` response chaining via `GET RESPONSE` and bounded `SW=6Cxx` wrong-Le correction on opted-in read commands.
- **Credential transport**: Single-shot transmission of `CredentialCommand` without retry or logging.
- **Transaction isolation**: Wraps APDU exchanges inside PC/SC transactions so concurrent card consumers cannot disturb session state.
