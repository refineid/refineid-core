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
1. It exposes unauthenticated application TCP listening ports on desktop workstations, increasing the attack surface for local network port scans and lateral exploit movement.
2. It requires administrative UAC elevation and inbound firewall modifications (e.g. Windows Firewall `netsh` rule creation, or `iptables`/`nftables`/`firewalld` rule modifications).
3. It places the listening socket on the workstation, whereas placing the listener and advertisement on the mobile device (which holds hardware custody of the card and controls per-operation authorization prompts) allows workstations to operate strictly as outbound clients without inbound application firewall holes.

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
                                    │ (No application TCP listener on Requester)
                                    │ (No inbound TCP firewall rules needed)
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
- **No Inbound Application TCP Listeners**: Workstations **MUST NOT** open inbound application TCP listening ports, bind network sockets for incoming TCP traffic, or prompt users for administrative inbound firewall modifications. Discovery operates via outbound queries and standard OS-level multicast reception (UDP port 5353) or platform discovery services.
- **Outbound Client Model**: Workstations establish outbound TCP connections (`connect()`) to the Custodian's advertised endpoint. Outbound connections eliminate the need for application-specific inbound TCP firewall rules (though enterprise egress policies or network discovery filters may still apply).
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
   ├─► Available (Hardware BLE / BT)? ──► Use BLE GATT (or Classic RFCOMM fallback)
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
- **Applicability**: Standard cross-platform proximity transport across supported platforms (iOS, Android, Linux/BSD, Windows, macOS).
- **Normative Specification**: Governed normatively by RAPP v26.10.1 §2–§5.
- **Wire Profile**: The canonical cross-platform wire profile is GATT-based `fi.refineid.rapp.ble.v1`:
  - Primary Service UUID: `7E39FD01-A6B5-4D78-9E11-37E28E9545F1`
  - Channel Characteristic UUID: `7E39FD02-A6B5-4D78-9E11-37E28E9545F1` (Requester writes via `ATT_WRITE_REQ`; Custodian indicates via `ATT_HANDLE_VALUE_IND`)
  - Bootstrap Characteristic UUID: `7E39FD03-A6B5-4D78-9E11-37E28E9545F1` (Requester reads via `ATT_READ_REQ`)
  - Framing: Mandates ATT MTU Exchange ($\ge 512$ bytes) and RAPP BLE SAR framing (6-byte header: Total Frame Length, Chunk Sequence, Flags, Reserved).
- **Advisory Proximity Gating (RAPP v26.10.1 §4.4)**:
  - The Requester enforces an advisory RSSI discovery gate ($\ge -55\text{ dBm}$ filtered median over at least 3 packets, configurable down to $-85\text{ dBm}$ strictly in isolated developer testing).
  - **Threat Model & Non-Guarantee**: RSSI is strictly an **advisory discovery heuristic** and defense-in-depth barrier. It does NOT constitute a cryptographic proof of physical co-location and CANNOT defeat transparent RF wormholes, relays, or directional power amplifiers that preserve authenticated frames. Real-world protection against relay attacks is enforced at Layer 7 by explicit per-operation user authorization on the Custodian phone screen and PACE/CAN boundaries.
- **Platform Capability Constraints & L2CAP CoC Distinction**:
  - Windows 10/11 user-space APIs (WinRT `Windows.Devices.Bluetooth.GenericAttributeProfile`) support GATT, but provide no public user-space API for BLE L2CAP Connection-Oriented Channels (CoC).
  - Linux BlueZ supports GATT over D-Bus without requiring raw socket capabilities.
  - L2CAP CoC is NOT wire-compatible with GATT and cannot share the `fi.refineid.rapp.ble.v1` profile identifier. If a credit-based L2CAP CoC transport is introduced in the future, it must be specified as a separate, distinct profile (e.g. `fi.refineid.rapp.ble-coc.v1`) with explicit PSM discovery via GATT, platform capability tests, and independent qualification.
- **Legacy Fallback (Classic Insecure RFCOMM)**:
  - On legacy workstations equipped only with Bluetooth 2.0/3.0 BR/EDR hardware lacking BLE modems (e.g., ThinkPad R61 Broadcom BCM2045B controllers), the platform MAY negotiate unauthenticated RFCOMM (`listenUsingInsecureRfcommWithServiceRecord`). Because link-layer authentication is omitted, zero OS-level PIN pairing dialogs are presented; complete mutual authentication and forward secrecy are enforced at Layer 7 by CPace and Noise.

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

Because mDNS discovery broadcasts on multicast UDP port 5353 (IPv4 `224.0.0.251`, IPv6 `ff02::fb`), packets are visible to all devices on the local Layer 2 broadcast domain. In compliance with IETF [RFC 8882](https://www.rfc-editor.org/rfc/rfc8882.html) (*DNS-SD Privacy and Security Requirements*) and RefineID privacy rules:

### 4.1 Separation of Discovery Identifiers and Persistent Routing Tokens
- **Persistent Reconnect Routing Token (`rendezvous_token`)**:
  - As defined in RAPP v26.10.1 §4.3, `rendezvous_token` is a 16-byte cryptographically derived value (`first 16 bytes of SHA-512("RAPP-rendezvous-v1" || h)`), stored permanently in the local pairing trust record.
  - **Zero Public Broadcast**: The 16-byte `rendezvous_token` **MUST NEVER** be published in mDNS PTR, SRV, or TXT records, nor broadcast in unauthenticated BLE advertising packets.
  - The token is transmitted strictly point-to-point over the established TCP stream (or BLE Channel Characteristic) during initial connection routing in `Phase::Routing` (§5.2).

### 4.2 Public DNS-SD Identifiers and Ephemeral Lifecycle
- **Zero Personally Identifiable Information (PII)**:
  - Service instance names, host targets, and TXT records **MUST NOT** contain personal names, identity codes, citizen IDs, card numbers, IMEI, hardware serials, or persistent MAC addresses.
- **Ephemeral Randomized Instance Name**:
  - The DNS-SD service instance name MUST be freshly generated as a random hex identifier whenever advertising starts or restarts:
    `refineid-[random_8_hex]._refineid-stream._tcp.local.` (e.g., `refineid-7f2a1c84._refineid-stream._tcp.local.`).
  - Deriving instance names deterministically from persistent pairing tokens or pair IDs is strictly prohibited, preventing cross-network tracking and location correlation per RFC 8882 §3.1.
- **Ephemeral Randomized SRV Host Target**:
  - The SRV record target MUST use an anonymized, ephemeral local host label:
    `refineid-[random_8_hex].local.` (e.g., `refineid-b3d90e15.local.`), preventing leakage of operating system hostnames or user names (e.g. `Petris-iPhone.local`).

### 4.3 DNS-SD TXT Record Formats and Discovery Modes
The Custodian publishes two distinct discovery modes:

1. **Pairing Mode (`mode=pairing`)**:
   - Active strictly during an explicit user-initiated pairing ceremony on the phone, bounded by the 60-second offer TTL.
   - TXT Attributes:
     ```text
     v=1
     mode=pairing
     offer=[16-byte-hex-offer-id]
     ```
   - `offer` contains the 16-byte random, ephemeral `offer_id` from the active `pairing-offer` (Section 4.1 of RAPP v26.10.1). It is destroyed upon offer completion or timeout, ensuring zero persistent linkage.

2. **Session Reconnect Mode (`mode=session`)**:
   - Active when "Allow Remote Card Reader" is enabled and the phone is ready for operational card requests.
   - **Default Minimal Record (Maximum Privacy)**:
     ```text
     v=1
     mode=session
     ```
     No pairing tokens, hashes, or hints are published. Requesters on the local subnet with "Enable Remote Phone Reader" active connect to the advertised endpoint and present their 16-byte `rendezvous_token` inside the point-to-point stream in `Phase::Routing`. If the Custodian does not recognize the token, the TCP connection is immediately closed.
   - **Optional Rotating Discovery Hints (Multi-Device Coexistence)**:
     To avoid trial connections in high-density enterprise environments with multiple active Custodians, the Custodian MAY publish truncated, rotating HMAC hints for up to 4 stored pairings:
     $$\text{hint}_i = \text{first 8 bytes of }\text{HMAC-SHA-256}(K_{\text{disc}, i}, \text{epoch})$$
     where $K_{\text{disc}, i} = \text{HKDF-Expand}(\text{rendezvous\_token}_i, \text{"RAPP-discovery-hint-v1"}, 32)$, and $\text{epoch} = \lfloor \text{unix\_time} / 900 \rfloor$ (15-minute rotation window).
     TXT Attribute: `hints=[hint1_hex],[hint2_hex]`
     Requesters evaluate candidate hints for the current and adjacent epoch ($\text{epoch} \pm 1$) against their stored pairings before initiating TCP connections.

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
| **`refineid-core`** | Protocol Core | Standardize 3-tier hierarchy and update `fi.refineid.stream.v1` stream profile framing to designate Custodian as listener and Requester as dialer. Define RFC 8882 discovery token formats and rotation. |
| **`refineid-unix`** | Requester (Linux, BSD) | Keep `pcscd` default; implement outbound `StreamRelayBrowser` using native mDNS (`avahi` / `systemd-resolved`); provide GUI toggle in `refineid-gui-fltk`; maintain zero open listening ports. |
| **`refineid-windows`** | Requester (Windows 10/11) | Remove `FirewallService.cs` and inbound TCP listener (port 47110); implement outbound `StreamRelayBrowser` using supported `Windows.Devices.Enumeration` or Win32 `DnsServiceBrowse`; add explicit opt-in toggle in `RefineID-winui`. |
| **`refineid-apple`** | Custodian (iOS) & Requester (macOS) | Implement Tier 1 `NWListener(includePeerToPeer: true)` / `NWBrowser` direct P2P for Apple-to-Apple; maintain `StreamRelayListener` on iOS gated by "Allow Remote Reader" setting; adhere to RFC 8882 ephemeral discovery names. |
| **`refineid-android`** | Custodian (Android) | Maintain `StreamRelayListener` (`_refineid-stream._tcp` via `NsdManager`) gated by "Allow Remote Reader" setting; support BLE peripheral GATT `fi.refineid.rapp.ble.v1` and unauthenticated RFCOMM fallback. |
