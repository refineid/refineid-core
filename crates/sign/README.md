# refineid-sign

Card-side signing for FINEID cards.

The card holds the private key and performs the private-key operation;
the host computes the digest and drives the MANAGE SECURITY ENVIRONMENT /
PERFORM SECURITY OPERATION choreography. MSE:SET pins the key and
algorithm in the digital-signature template -- the only template the
specification sets for PSO:COMPUTE DIGITAL SIGNATURE, for either key. The
chain's shape follows the resolved card family (`SignScheme`): the citizen
card loads the digest with PSO:HASH and signs an empty PSO:CDS, while the
organizational card carries the digest inline in a single PSO:CDS and
names its qualified key by the local DF.ESIGN reference. The signing
commands carry no credential material and ride the plain transport path,
so the same operations work over a PACE secure-messaging transport
unchanged.

A signature is made through a `SigningKey`, which borrows the transport
exclusively and signs one digest. `SignOps::authentication_key` names the
authentication key, whose PIN 1 the caller has verified.
There are two ways to the qualified key, both where PIN 2 was presented
for it. `SignOps::unlock_qualified_key` takes the `Pin2`, and on the
organizational card -- whose qualified key and PIN 2 are local to
DF.ESIGN (FINEID S4-2 v4.0 section 4.2) -- first selects DF.ESIGN by name
from the MF, then verifies PIN 2 there; the citizen card is sent PIN 2
where the caller selected. `Pin2ChannelSignOps::qualified_key_after_pin2_pace`
exists only on `SmTransport<_, OpenedByPin2>`, a secure channel PACE
opened with PIN 2, which the card counts as PIN 2 verified (section 6):
it selects DF.ESIGN the same way and sends no PIN, spending the
channel's one PIN 2 presentation. A channel the CAN or PIN 1 opened has
no such method. While the key lives no other command can reach the
card, so the MSE:SET and PSO:CDS run in the directory PIN 2 was
presented for.

`SigningKey::sign_prehashed_sha256_rsa`, `sign_prehashed_sha384_rsa`, and
`sign_prehashed_sha512_rsa` cover the RSA keys under RSASSA-PKCS1;
the corresponding `sign_prehashed_*_rsa_pss` methods cover the same
SHA-256, SHA-384, and SHA-512 digests under RSASSA-PSS. All return an
RSA-3072 signature. The
`sign_prehashed_sha256_ecdsa` plus `sign_prehashed_sha384_ecdsa` cover
the newer P-384 keys with the SHA-256 and SHA-384 schemes TLS peers can
negotiate (raw `r || s`). PSS is a card-native scheme: the card applies
the padding from the digest, so the choreography matches the pre-hashed
chain with a different algorithm reference. The signature bytes are
returned in an algorithm-typed container.

`SignOps::decipher_rsa` recovers an RSA cryptogram: it sets the
confidentiality template and ships the modulus-wide cryptogram by command
chaining (its data field exceeds the short form), and the card returns the
recovered plaintext. `DecipherAlgRef` names the padding (PKCS#1 v1.5 or
RSAES-OAEP-SHA256).

A signature that fits the short response carries its exact length as Le,
which a T=0 card requires to answer directly; the wider RSA-3072
signature uses the maximum-length encoding and the adapter chains the
61xx response.

The SHA-256 PSS, decipher, and SHA-384 ECDSA paths are hardware-validated:
on the older card the authentication key produced a SHA-256 PSS signature
that verified against its certificate and recovered a message encrypted to
it, and on the newer card the authentication key produced a P-384 ECDSA
signature that verified against its certificate. On an Idemia Cosmo X
organization card the same command sequence the two organizational keys
now drive was observed through these crates: the authentication key's
inline-digest PSS signature, and -- with DF.ESIGN selected by name, PIN 2
verified there, and the DF.ESIGN-local key reference -- the qualified
key's inline-digest RSASSA-PKCS1-v1_5 SHA-256 signature, each verifying
against its certificate. `unlock_qualified_key`, which composes that
qualified sequence, is covered by scripted-transport tests. The other
PKCS#1, SHA-384/SHA-512 PSS, SHA-256 ECDSA, and organizational ECDSA
chains rest on scripted-transport tests until each is observed on
hardware. Constants and the command choreography are traced to the
[DVV FINEID specifications](https://dvv.fi/en/fineid-specifications) (S1
sections 3.6 through 3.9, S4-1, S4-2) and ISO/IEC 7816-4 and -8.
