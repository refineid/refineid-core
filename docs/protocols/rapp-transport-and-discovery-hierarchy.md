# Remote Authorization Proxy Protocol (RAPP)
## Transport and Discovery Hierarchy Specification

- **Document Version**: `26.10.3`
- **Protocol Versions**: `26.9.28`, `26.10.1`
- **Status**: Normative Specification / Architecture Blueprint
- **Change Controller**: RefineID Project
- **Applies To**: `refineid-core`, `refineid-unix`, `refineid-windows`, `refineid-apple`, `refineid-android`
- **Supersedes**: Connection direction in Section 16.1 of `rapp-v26.9.28.md`

---

## 1. Abstract and Motivation

The Remote Authorization Proxy Protocol (RAPP) enables a desktop or laptop requester to leverage an identity card (e.g., FINEID Citizen Certificate) held in physical custody by a mobile phone over NFC, without exporting the private keys, PIN codes, or credential secrets.

Earlier iterations of the stream transport profile (`fi.refineid.stream.v1` in `rapp-v26.9.28.md` §16.1) incorrectly specified that the workstation should host the listening TCP socket while the mobile device dials in. On desktop operating systems—most notably Windows and desktop Unix/Linux distributions—requiring an inbound listening port introduces unacceptable security risks:
1. It exposes unauthenticated listening ports on desktop workstations, increasing the attack surface for local network port scans and lateral exploit movement.
2. It requires administrative UAC elevation and firewall modifications (e.g. Windows Firewall `netsh` rule creation, or `iptables`/`nftables`/`firewalld` rule modifications).
3. It contradicts the fundamental security hierarchy: the mobile device (possessing hardware-backed keystores, biometric presence verification, and strict app sandboxing) is the **Sovereign Custodian**, while the workstation is an untrusted or semi-trusted **Requester**.

This specification defines the normative **3-Tier Discovery and Transport Hierarchy** and inverts the connection direction for local network stream transport: the phone acts as the listener/advertiser (when explicitly enabled), and workstations connect strictly as outbound clients. Furthermore, it establishes strict **UX Hygiene Rules** ensuring desktop applications function as standard local smart card readers by default.

---

## 2. Asymmetric Device Security & Architectural Roles

```
┌────────────────────────────────────────────────────────────────────────┐
│                        SOVEREIGN CUSTODIAN                             │
│                      (iOS / Android Phone)                             │
│                                                                        │
│  • Hardware Security Root: Secure Enclave / StrongBox / TEE / Biometrics│
│  • Physical Custody: NFC interface to FINEID Identity Card             │
│  • Rule #1: PIN codes NEVER leave the phone; zero PIN transport.       │
│  • Rule #2: Zero PIN and candidate PIN-length logging.                 │
│  • Explicit Gate: "Allow Remote Reader" toggle controls listener.      │
│  • Network Role: Listener & Advertiser (Ephemeral port, mDNS/DNS-SD)   │
└───────────────────────────────────▲────────────────────────────────────┘
                                    │
                                    │ Outbound Client Connection
                                    │ (Zero open ports on Requester)
                                    │ (Zero firewall rules needed)
                                    │ (Zero UAC elevation needed)
                                    │
┌───────────────────────────────────┴────────────────────────────────────┐
│                             REQUESTER                                  │
│                 (Linux/BSD, Windows 10/11, macOS)                      │
│                                                                        │
│  • First-Class Workstations: refineid-unix, refineid-windows, apple    │
│  • Default State: Pure Local Card Reader (PC/SC via CCID / slot)       │
│  • UX Hygiene: "Remote Phone Reader" MUST be explicitly turned ON      │
│  • Discovery: Browses mDNS / BLE only when remote reader is enabled    │
│  • Network Role: Outbound Client Only (connects to Custodian)          │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.1 The Sovereign Custodian (Phone)
The mobile device is the authoritative security anchor:
- **Custody of Secrets**: It interacts directly with the physical smart card over ISO/IEC 7816 / ISO/IEC 14443 contactless NFC.
- **Biometric Presence & Protected Path**: PIN1 is verified locally via Secure Enclave / KeyStore caching or user entry. PIN2 (Qualified Electronic Signature) prompts appear exclusively on the phone's protected display.
- **Listener Gating**: The phone **MUST NOT** bind any network listening socket or broadcast advertisements unless the user has explicitly enabled "Allow Remote Card Reader" in application settings. When disabled, the listener is immediately terminated and unannounced.

### 2.2 The Requester (Workstation)
Desktop platforms (`refineid-unix`, `refineid-windows`, macOS):
- **Zero Inbound Ports**: Workstations **MUST NOT** open inbound listening TCP ports, bind network sockets for incoming traffic, or prompt users for administrative firewall modifications.
- **Outbound Client Model**: Workstations establish outbound connections (`connect()`) to the Custodian's advertised endpoint. State-tracked outbound traffic requires zero incoming firewall permissions.
- **Zero PIN Knowledge**: Workstations operate via `CKF_PROTECTED_AUTHENTICATION_PATH` and never handle, log, or prompt for card PINs.

---

## 3. The 3-Tier Discovery & Transport Hierarchy

When a Requester attempts to discover and pair with an authorized Custodian, transports and discovery mechanisms MUST be evaluated in strict priority order:

```
Tier 1: Apple Native (Direct P2P)
   │
   ├─► Available (Apple ↔ Apple)? ──► Use MultipeerConnectivity / AWDL / NWListener
   │
   ▼ Fallback / Non-Apple
Tier 2: Bluetooth / BLE Proximity Transport
   │
   ├─► Available (Hardware BLE / BT)? ──► Use BLE GATT / L2CAP CoC (or Classic RFCOMM)
   │
   ▼ Fallback (No Bluetooth / VM / Constrained)
Tier 3: Local IP Stream via mDNS / DNS-SD
   │
   └─► Local Wi-Fi / Subnet ──► Discover via RFC 6762/6763; Outbound TCP Connect
```

### 3.1 Tier 1: Apple-to-Apple Native Direct Transport (`apple-peer-v1`)
- **Applicability**: Exclusively between Apple devices (iPhone Custodian ↔ Mac Requester).
- **Underlay**: `MultipeerConnectivity` and `Network.framework` over Apple Wireless Direct Link (AWDL).
- **Properties**: Operates over peer-to-peer Wi-Fi without requiring an external access point or shared router. Provides hardware-accelerated direct proximity with minimal latency and high power efficiency.
- **Priority**: Primary tier whenever both peers are within the Apple platform ecosystem.

### 3.2 Tier 2: Bluetooth / BLE Proximity Transport (`fi.refineid.rapp.ble.v1`)
- **Applicability**: Standard cross-platform proximity transport across all supported platforms (iOS, Android, Linux/BSD, Windows, macOS).
- **Specification**: Governed normatively by RAPP v26.10.1 §2–§5.
- **Physical Proximity**: Operates over 2.4 GHz Bluetooth Low Energy with an advisory proximity gate ($\ge -55\text{ dBm}$ RSSI). Enforces physical co-location (~5–10 meters) by laws of radio propagation, preventing cross-office or cross-building session hijacking.
- **Zero Infrastructure**: Completely independent of local IP networks, routers, or Internet connectivity.
- **Legacy Fallback (Classic Insecure RFCOMM)**: On legacy workstations equipped only with Bluetooth 2.0/3.0 BR/EDR hardware lacking BLE modems (e.g., ThinkPad R61 Broadcom BCM2045B controllers), the platform MAY negotiate unauthenticated RFCOMM (`listenUsingInsecureRfcommWithServiceRecord`). Because link-layer authentication is omitted, zero OS-level PIN pairing dialogs are presented; complete mutual authentication and forward secrecy are enforced at Layer 7 by CPace and Noise.

### 3.3 Tier 3: Local IP Stream via mDNS / DNS-SD Fallback (`fi.refineid.stream.v1`)
- **Applicability**: Universal cross-platform fallback when Bluetooth hardware is absent, disabled, restricted (e.g. inside virtual machines or containers), or when devices operate across dual-band Wi-Fi setups.
- **Underlay**: Single reliable ordered byte stream (TCP) over local IP.
- **Discovery Standard**: IETF Multicast DNS ([RFC 6762](https://www.rfc-editor.org/rfc/rfc6762.html)) and DNS-Based Service Discovery ([RFC 6763](https://www.rfc-editor.org/rfc/rfc6763.html)).
- **Connection Direction**:
  - Custodian runs `StreamRelayListener` on a dynamic, ephemeral TCP port (`bind(0)`).
  - Custodian advertises service type `_refineid-stream._tcp.local.` via mDNS.
  - Requester runs `StreamRelayBrowser`, receives the PTR/SRV/TXT records, and initiates an **outbound** TCP `connect()` to the phone's advertised IP and port.

---

## 4. Discovery Privacy & RFC 8882 Compliance

Because mDNS discovery broadcasts on multicast UDP port 5353 (IPv4 `224.0.0.251`, IPv6 `ff02::fb`), packets are visible to all devices on the local Layer 2 broadcast domain. In compliance with IETF [RFC 8882](https://www.rfc-editor.org/rfc/rfc8882.html) (*DNS-SD Privacy and Security Requirements*) and RefineID rules:

1. **Zero Personally Identifiable Information (PII)**:
   - Service instance names and TXT records **MUST NOT** contain personal names, identity codes, citizen IDs, card numbers, or persistent device identifiers.
2. **Opaque Rendezvous Tokens**:
   - The DNS-SD TXT record carries only protocol versioning and an ephemeral, cryptographically random rendezvous token derived from the current pairing state:
   ```text
   PTR:  _refineid-stream._tcp.local. -> [RandomInstance]._refineid-stream._tcp.local.
   SRV:  0 0 [EphemeralPort] [PhoneHost].local.
   TXT:  v=1 token=[32-byte-hex-rendezvous-token]
   ```
3. **Application-Layer Cryptographic Security**:
   - The IP network and mDNS records are treated as an untrusted wire.
   - Initial pairing is authenticated via `CPaceRistretto255` KC2 profile using a 6-character Crockford Base32 human factor, followed by `Noise_XXpsk3` channel binding.
   - Subsequent operational sessions authenticate via `Noise_KK` with pre-shared static keys and derive independent per-session keys.

---

## 5. Workstation UX Hygiene Specification

To maintain clean, unobtrusive operation on enterprise and personal workstations:

### 5.1 Local Card Reader by Default
- On launch, RefineID desktop applications (`refineid-unix`, `refineid-windows`, `refineid-apple`) MUST operate strictly as **Local Card Reader Software**.
- The application monitors local PC/SC smart card readers (integrated laptop slots, USB CCID readers via `pcscd` or `winscard`).
- Background radio scanning, mDNS service browsing, and network polling **MUST NOT** run by default.

### 5.2 Explicit Remote Phone Reader Opt-In
- Workstations MUST provide an explicit user setting:
  ```
  [ ] Enable Remote Phone Reader
      Allow discovering and using your phone as a wireless card reader.
  ```
- Only when this setting is enabled:
  1. The Requester activates Tier 2 (BLE scanner) and/or Tier 3 (mDNS browser).
  2. Discovered Custodians configured for remote use appear in the reader selection list.
  3. Outbound connections are established on-demand when the card is consulted.
- Disabling the setting immediately halts background scanners, closes any idle outbound sockets, and purges transient discovery caches.

---

## 6. Implementation & Repository Alignment Matrix

| Repository | Platform Role | Discovery / Transport Actions Required |
| :--- | :--- | :--- |
| **`refineid-core`** | Protocol Core | Standardize 3-tier hierarchy and update `fi.refineid.stream.v1` stream profile framing to designate Custodian as listener and Requester as dialer. |
| **`refineid-unix`** | Requester (Linux, BSD) | Keep `pcscd` default; implement outbound `StreamRelayBrowser` using native mDNS (`avahi` / `systemd-resolved`); provide GUI toggle in `refineid-gui-fltk`; maintain zero open listening ports. |
| **`refineid-windows`** | Requester (Windows 10/11) | Remove `FirewallService.cs` and inbound TCP listener (port 47110); implement outbound `StreamRelayBrowser` using WinRT `DnssdServiceWatcher`; add explicit opt-in toggle in `RefineID-winui`. |
| **`refineid-apple`** | Custodian (iOS) & Requester (macOS) | Implement Tier 1 `MultipeerConnectivity` direct P2P for Apple-to-Apple; maintain `StreamRelayListener` on iOS gated by "Allow Remote Reader" setting. |
| **`refineid-android`** | Custodian (Android) | Maintain `StreamRelayListener` (`_refineid-stream._tcp` via `NsdManager`) gated by "Allow Remote Reader" setting; support BLE peripheral and unauthenticated RFCOMM fallback. |
