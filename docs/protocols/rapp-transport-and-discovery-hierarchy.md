# Remote Authorization Proxy Protocol (RAPP)
## Transport and Discovery Hierarchy Specification

- **Document Version**: `26.10.21`
- **Protocol Versions**: `26.10.21`
- **Status**: Normative Specification / Architecture Blueprint
- **Change Controller**: RefineID Project
- **Applies To**: `refineid-core`, `refineid-unix`, `refineid-windows`, `refineid-apple`, `refineid-android`

---

## 1. Abstract and Motivation

The Remote Authorization Proxy Protocol (RAPP) enables a desktop or laptop requester to leverage an identity card (e.g., Finnish Electronic Identification (FINEID) Citizen Certificate) held in physical custody by a mobile phone over Near Field Communication (NFC), without exporting the private keys, personal identification number (PIN) codes, or credential secrets.

The mobile device listens and the workstation dials. On desktop operating systems—most notably Windows and desktop Unix/Linux distributions—an inbound listening port would introduce unacceptable security risks:
1. It exposes unauthenticated application Transmission Control Protocol (TCP) listening ports on desktop workstations, increasing the attack surface for local network port scans and lateral exploit movement.
2. It requires administrative User Account Control (UAC) elevation and inbound firewall modifications (e.g. Windows Firewall `netsh` rule creation, or `iptables`/`nftables`/`firewalld` rule modifications).
3. It places the listening socket on the workstation, whereas placing the listener and advertisement on the mobile device (which holds hardware custody of the card and controls per-operation authorization prompts) allows workstations to operate strictly as outbound clients without inbound application firewall holes.

This specification defines the normative **Discovery and Transport Preference**: for local network stream transport the phone acts as the listener/advertiser (when explicitly enabled), and workstations connect strictly as outbound clients. It also fixes the workstation defaults: desktop applications function as ordinary local smart card readers until paired.

---

## 2. Asymmetric Device Security & Architectural Roles

In the diagram, Bluetooth Low Energy (BLE) is the Bluetooth transport; discovery on the local network uses the Domain Name System (DNS) in its multicast form (mDNS) with DNS Service Discovery (DNS-SD); a Chip Card Interface Device (CCID) is the class of Universal Serial Bus (USB) smart card reader; and a Trusted Execution Environment (TEE) is the phone's hardware security root.

```
┌────────────────────────────────────────────────────────────────────────┐
│                               CUSTODIAN                                │
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
│  • Default:    a phone is used only once paired by its code            │
│  • Discovery: Browses mDNS / BLE only while a pairing exists           │
│  • Network Role: Outbound Client Only (connects to Custodian)          │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.1 The Custodian (Phone)
The mobile device is the authoritative security anchor:
- **Custody of Secrets**: It interacts directly with the physical smart card over ISO/IEC 7816 / ISO/IEC 14443 contactless NFC.
- **Biometric Presence & Protected Path**: PIN1 is verified locally via Secure Enclave / KeyStore caching or user entry. PIN2 (Qualified Electronic Signature) prompts appear exclusively on the phone's protected display.
- **Listener Gating**: The phone must not bind any network listening socket or broadcast advertisements unless the user has explicitly enabled "Allow Remote Card Reader" in application settings. When disabled, the listener is immediately terminated and unannounced.

### 2.2 The Requester (Workstation)
Desktop platforms (`refineid-unix`, `refineid-windows`, macOS):
- **No Inbound Application TCP Listeners**: Workstations must not open inbound application TCP listening ports, bind network sockets for incoming TCP traffic, or prompt users for administrative inbound firewall modifications. Discovery operates via outbound queries and standard operating system (OS)-level multicast reception (UDP port 5353) or platform discovery services.
- **Outbound Client Model**: Workstations establish outbound TCP connections (`connect()`) to the Custodian's advertised endpoint. Outbound connections eliminate the need for application-specific inbound TCP firewall rules (though enterprise egress policies or network discovery filters may still apply).
- **Zero PIN Knowledge**: Workstations operate via `CKF_PROTECTED_AUTHENTICATION_PATH` and never handle, log, or prompt for card PINs.

---

## 3. Discovery and Transport Preference

When a Requester discovers and reaches a Custodian, it tries the transports in this order and uses the first one available. In the diagram, the Internet Protocol (IP) stream is the local-network transport; a Request for Comments (RFC) is an Internet Engineering Task Force (IETF) standard; a virtual machine (VM) is a computer without a radio of its own; and the Generic Attribute Profile (GATT) is Bluetooth's data layer.

```
Apple-to-Apple direct (peer-to-peer Wi-Fi)
   │
   ├─► Both peers Apple? ──► Stream profile over the peer-to-peer link (AWDL)
   │
   ▼ Otherwise
Local IP stream (mDNS / DNS-SD)
   │
   ├─► Shared local network? ──► Discover via RFC 6762/6763; outbound TCP connect
   │
   ▼ No usable IP network (no Wi-Fi, VM or container without one, no router)
Bluetooth (BLE)
   │
   └─► BLE hardware present ──► Use BLE GATT
```

### 3.1 Apple-to-Apple Direct (the stream profile over the peer-to-peer link)
- **Applicability**: Exclusively between Apple devices (iPhone Custodian ↔ Mac Requester).
- **Underlay**: The stream profile (`fi.refineid.stream.v1`, §3.2) carried by `Network.framework` over Apple Wireless Direct Link (AWDL): the Custodian's listener and the Requester's browser both enable peer-to-peer, so the same TCP stream, framing and routing preamble reach the phone without an access point or shared router.
- **Properties**: Operates over peer-to-peer Wi-Fi without requiring an external access point or shared router. Provides hardware-accelerated direct proximity with minimal latency and high power efficiency.
- **Priority**: First choice whenever both peers are Apple devices.

### 3.2 Local IP Stream via mDNS / DNS-SD (`fi.refineid.stream.v1`)
- **Applicability**: The cross-platform path whenever the devices share a local IP network; the default outside Apple-to-Apple.
- **Underlay**: Single reliable ordered byte stream (TCP) over local IP.
- **Discovery Standard**: IETF Multicast DNS ([RFC 6762](https://www.rfc-editor.org/rfc/rfc6762.html)) and DNS-Based Service Discovery ([RFC 6763](https://www.rfc-editor.org/rfc/rfc6763.html)).
- **Connection Direction**:
  - Custodian runs `StreamRelayListener` on a dynamic, ephemeral TCP port (`bind(0)`).
  - Custodian advertises service type `_refineid-stream._tcp.local.` via mDNS.
  - Requester runs `StreamRelayBrowser`, receives the PTR (pointer), SRV (service) and text (TXT) (text) records, and initiates an **outbound** TCP `connect()` to the phone's advertised IP and port.
- **Wire Profile**: Governed normatively by RAPP v26.10.21 §2.2.2. Each frame is a 2-byte unsigned big-endian length followed by 1 to 65535 payload bytes. The Requester's first frame is the routing preamble `["RAPP-stream-v1", purpose, routing]` (RAPP v26.10.21 §2.2.1). After a `"pairing"` preamble the Custodian's first frame is the encoded `pairing-offer` (§4.2); after a `"session"` preamble the Custodian routed the Requester sends `Noise_KK` message 1.

### 3.3 Bluetooth / BLE Proximity Transport (`fi.refineid.rapp.ble.v1`)
- **Applicability**: The last resort: a proximity transport for when no IP network is shared (no Wi-Fi, a virtual machine or container without a usable network, no router), across supported platforms (iOS, Android, Linux/BSD, Windows, macOS).
- **Normative Specification**: Governed normatively by RAPP v26.10.21 §2–§5.
- **Wire Profile**: The canonical cross-platform wire profile is GATT-based `fi.refineid.rapp.ble.v1`:
  - Primary Service Universally Unique Identifier (UUID): `7E39FD01-A6B5-4D78-9E11-37E28E9545F1`
  - Channel Characteristic UUID: `7E39FD02-A6B5-4D78-9E11-37E28E9545F1` (Requester writes via `ATT_WRITE_REQ`; Custodian indicates via `ATT_HANDLE_VALUE_IND`)
  - Bootstrap Characteristic UUID: `7E39FD03-A6B5-4D78-9E11-37E28E9545F1` (Requester reads via `ATT_READ_REQ`)
  - Framing: Mandates Attribute Protocol (ATT) Maximum Transmission Unit (MTU) Exchange ($\ge 512$ bytes) and RAPP BLE Segmentation and Reassembly (SAR) framing (6-byte header: Total Frame Length, Chunk Sequence, Flags, Reserved).
- **Platform Capability Constraints & Logical Link Control and Adaptation Protocol (L2CAP) CoC Distinction**:
  - Windows 10/11 user-space APIs (WinRT `Windows.Devices.Bluetooth.GenericAttributeProfile`) support GATT, but provide no public user-space application programming interface (API) for BLE L2CAP Connection-Oriented Channels (CoC).
  - Linux BlueZ supports GATT over D-Bus without requiring raw socket capabilities.
  - L2CAP CoC is NOT wire-compatible with GATT and cannot share the `fi.refineid.rapp.ble.v1` profile identifier. If a credit-based L2CAP CoC transport is introduced in the future, it must be specified as a separate, distinct profile (e.g. `fi.refineid.rapp.ble-coc.v1`) with explicit PSM discovery via GATT, platform capability tests, and independent qualification.

---

## 4. Discovery Privacy & RFC 8882 Compliance

Because mDNS discovery broadcasts on multicast UDP port 5353 (IPv4 `224.0.0.251`, IPv6 `ff02::fb`), packets are visible to all devices on the local Layer 2 broadcast domain. In compliance with IETF [RFC 8882](https://www.rfc-editor.org/rfc/rfc8882.html) (*DNS-SD Privacy and Security Requirements*) and RefineID privacy rules:

### 4.1 No Stable Pairing Identifier on the Wire
- **Keys from the static agreement**: Every value that names a stored pairing outside its encrypted channel -- discovery hints (§4.3), withdrawal hints (§4.3), revocation hints (§4.3) and session routing tags -- is keyed by the pairing's static X25519 agreement (X25519 is the Diffie-Hellman function over Curve25519, RFC 7748) under its own Hash-based Message Authentication Code (HMAC)-based Key Derivation Function (HKDF) label (RAPP v26.10.21 §4.3). Only the pairing's two endpoints can compute or recognise these values.
- **Fresh per connection**: The Requester's session routing preamble carries a fresh random nonce and the routing tag it keys (RAPP v26.10.21 §2.2.1), sent point-to-point over the established TCP stream or BLE Channel Characteristic in `Phase::Routing`. No routing value recurs across connections, so preambles cannot be linked to one another or to discovery records.
- **Zero Public Broadcast of stable values**: `pair_id`, static public keys, and any other stable per-pairing value must never be published in mDNS PTR, SRV, or TXT records, nor broadcast in unauthenticated BLE advertising packets.

### 4.2 Public DNS-SD Identifiers and Ephemeral Lifecycle
- **Zero Personally Identifiable Information (PII)**:
  - Service instance names, host targets, and TXT records must not contain personal names, identity codes, citizen IDs, card numbers, International Mobile Equipment Identity (IMEI), hardware serials, or persistent Media Access Control (MAC) addresses.
- **Ephemeral Randomized Instance Name**:
  - The DNS-SD service instance name must be freshly generated as a random hex identifier whenever advertising starts or restarts:
    `refineid-[random_8_hex]._refineid-stream._tcp.local.` (e.g., `refineid-7f2a1c84._refineid-stream._tcp.local.`).
  - Deriving instance names deterministically from persistent pairing tokens or pair IDs is strictly prohibited, preventing cross-network tracking and location correlation per RFC 8882 §3.1.
- **Ephemeral Randomized SRV Host Target**:
  - The SRV record target must use an anonymized, ephemeral local host label:
    `refineid-[random_8_hex].local.` (e.g., `refineid-b3d90e15.local.`), preventing leakage of operating system hostnames or user names (e.g. `Petris-iPhone.local`).

### 4.3 DNS-SD TXT Record Formats and Discovery Modes
TXT keys compare case-insensitively ([RFC 6763](https://www.rfc-editor.org/rfc/rfc6763.html) §6.4); a key that appears twice in any case is a repeated key and makes the record malformed. Values compare exactly, and hint lists are lowercase hexadecimal only. A record whose keys are not exactly those its mode lists is malformed. Records are parsed by `refineid-rapp`, never by platform code.

The Custodian publishes three distinct discovery modes:

1. **Pairing Mode (`mode=pairing`)**:
   - Active strictly during an explicit user-initiated pairing ceremony on the phone, bounded by the 5-minute offer time to live (TTL).
   - TXT Attributes:
     ```text
     v=1
     mode=pairing
     ```
   - Nothing derived from the pairing code or the offer is published. The Requester obtains the offer over the connection (RAPP v26.10.21 §4.2).

2. **Session Reconnect Mode (`mode=session`)**:
   - Active when "Allow Remote Card Reader" is enabled and the phone is ready for operational card requests.
   - **Default Minimal Record (Maximum Privacy)**:
     ```text
     v=1
     mode=session
     ```
     No pairing values, hashes, or hints are published. Requesters on the local subnet that hold a usable pairing connect to the advertised endpoint and present a fresh session routing preamble inside the point-to-point stream in `Phase::Routing` (RAPP v26.10.21 §2.2.1). If no stored pairing keyed its tag, the TCP connection is immediately closed.
   - **Optional Rotating Discovery Hints (Multi-Device Coexistence)**:
     To avoid trial connections in high-density enterprise environments with multiple active Custodians, the Custodian publishes truncated, rotating HMAC hints for the 4 most recently used stored pairings (use time and tie order as for withdrawn records, RAPP v26.10.21 §4.5):
     $$\text{hint}_i = \text{first 8 bytes of }\text{HMAC-SHA-256}(K_{\text{disc}, i}, \text{epoch\_be64})$$
     where:
     - $K_{\text{disc}, i}$ = HKDF-SHA-256 ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html)) with salt $\text{pair\_id}_i$, input keying material the pairing's static X25519 agreement, $\text{info} = $ `"RAPP-discovery-hint-v2"` (ASCII), and $L = 32$ (RAPP v26.10.21 §4.3).
     - $\text{epoch} = \lfloor \text{unix\_time} / 900 \rfloor$ (15-minute rotation window), and $\text{epoch\_be64}$ is that value as an unsigned 64-bit big-endian integer (8 bytes), the entire HMAC message.
     - TXT Attribute: `hints=` followed by at most 4 hints, each 16 lowercase hexadecimal digits, separated by commas without spaces (e.g. `hints=054526c9fdd3b180`).
     - The `discovery_hint` vectors of `vectors/rapp-routing-v26.10.21.json` pin the bytes.
     Requesters evaluate candidate hints for the current and adjacent epoch ($\text{epoch} \pm 1$) against their stored pairings before initiating TCP connections; the window tolerates a clock difference of at least 15 minutes and up to just under 30 minutes, and implementations must not widen it. A record with `hints` holds 1 to 4 entries; an empty `hints` value is malformed. The `discovery_record` and `announcement_selection` vectors of `vectors/rapp-routing-v26.10.21.json` pin parsing and selection.
   - **Revocation Announcements**:
     A Custodian that revoked a pairing within the last 30 days adds `revoked=` with exactly 8 entries of 16 lowercase hexadecimal digits, separated by commas without spaces: the revocation hints of the up to 8 most recently revoked pairings for the current instance and epoch, the rest random fillers, all in random order (RAPP v26.10.21 §4.6). A Requester that finds its pairing's hint among them has a verified revocation and forgets the pairing. A `revoked` value that is not exactly 8 such entries is malformed. A `mode=session` record therefore carries the keys `v` and `mode`, optionally `hints`, and optionally `revoked`, and no other.

3. **Withdrawn Mode (`mode=withdrawn`)**:
   - Published for 2 to 10 seconds on the current service instance after the user turns remote access off or quits the application, once open sessions are closed and connections are no longer accepted; the service is then unregistered (RAPP v26.10.21 §4.5).
   - TXT Attributes, and no others:
     ```text
     v=1
     mode=withdrawn
     withdrawn=<entry_1>,<entry_2>,...,<entry_8>
     ```
   - Exactly 8 entries of 16 lowercase hexadecimal digits, separated by commas without spaces: the withdrawal hints of the 8 most recently used stored pairings, the rest random fillers, all in random order. A withdrawal hint is keyed by the pairing's static X25519 agreement and bound to the instance portion of the service instance name and a one-minute counter.
   - A Requester honours the record only on the instance it associates with the pairing and only while it holds no open session to it; it then withdraws the Custodian's presence at once and does not dial until it discovers `mode=session` again. Anything else is unannounced loss under the Requester's own hold.

---

## 5. Workstation Defaults

To maintain clean, unobtrusive operation on enterprise and personal workstations:

### 5.1 Local Card Reader by Default
- On launch, RefineID desktop applications (`refineid-unix`, `refineid-windows`, `refineid-apple`) must operate strictly as **Local Card Reader Software**.
- The application monitors local Personal Computer/Smart Card (PC/SC) smart card readers (integrated laptop slots, USB CCID readers via `pcscd` or `winscard`).
- Background radio scanning, mDNS service browsing, and network polling must not run by default.

### 5.2 Pairing Is the Opt-In
- The user's decision to use a phone as a card reader is the pairing itself: typing the code the phone shows (RAPP §3) pairs the workstation with that phone, and forgetting a pairing withdraws the decision for it. Workstations must not present a separate switch for the remote reader.
- Only while at least one usable stored pairing exists:
  1. The Requester activates the mDNS browser and/or the BLE scanner.
  2. Paired Custodians appear in the reader selection list when discovered.
  3. Outbound connections are established on demand when the card is consulted or, under the offering rule (RAPP §8.4), held while an identity is offered.
- Forgetting the last pairing immediately halts background scanners, closes any idle outbound sockets, and purges transient discovery caches.

---

## 6. Implementation & Repository Alignment Matrix

| Repository | Platform Role | Discovery / Transport Actions Required |
| :--- | :--- | :--- |
| **`refineid-core`** | Protocol Core | Standardize 3-tier hierarchy and update `fi.refineid.stream.v1` stream profile framing to designate Custodian as listener and Requester as dialer. Define RFC 8882 discovery token formats and rotation. |
| **`refineid-unix`** | Requester (Linux, BSD) | Keep `pcscd` default; implement outbound `StreamRelayBrowser` using native mDNS (`avahi` / `systemd-resolved`); provide graphical user interface (GUI) toggle in `refineid-gui-fltk`; maintain zero open listening ports. |
| **`refineid-windows`** | Requester (Windows 10/11) | Remove `FirewallService.cs` and inbound TCP listener (port 47110); implement outbound `StreamRelayBrowser` using supported `Windows.Devices.Enumeration` or Win32 `DnsServiceBrowse`; add explicit opt-in toggle in `RefineID-winui`. |
| **`refineid-apple`** | Custodian (iOS) & Requester (macOS) | Implement the Apple-to-Apple direct transport `NWListener(includePeerToPeer: true)` / `NWBrowser` direct peer-to-peer (P2P) for Apple-to-Apple; maintain `StreamRelayListener` on iOS gated by "Allow Remote Reader" setting; adhere to RFC 8882 ephemeral discovery names. |
| **`refineid-android`** | Custodian (Android) | Maintain `StreamRelayListener` (`_refineid-stream._tcp` via `NsdManager`) gated by "Allow Remote Reader" setting; support BLE peripheral GATT `fi.refineid.rapp.ble.v1`. |
