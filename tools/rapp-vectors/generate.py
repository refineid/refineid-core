#!/usr/bin/env python3
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
"""Derive the RAPP conformance corpora from their inputs.

Usage:
  tools/rapp-vectors/generate.py [--write]

Every corpus under doc/protocols/vectors holds inputs (fixed keys, offer
identifiers, pairing codes, times, instance names) and values derived from
them by the specification. This tool recomputes the derived values with the
standard-library primitives of primitives.py, never with the engine. Without
--write it fails when a corpus differs from its derivation; with --write it
rewrites the corpora.
"""

import copy
import json
import os
import struct
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from primitives import (  # noqa: E402
    Q, cbor, cbor_decode, decode, encode, from_uniform_bytes, hkdf256, hmac256, hmac512, noise_kk,
    noise_xxpsk3, scalar_mult, selftest, sha256, sha512, x25519, x25519_public,
)

VERSION = [26, 10, 29]
DOCUMENT = "26.10.29"
OFFER_TTL_MS = 300000
BLE = "fi.refineid.rapp.ble"
STREAM = "fi.refineid.stream"
CANDIDATE = {BLE: "ble", STREAM: "stream"}
DOMAIN = {BLE: "rapp-ble", STREAM: "rapp-stream"}
SERVICE_UUID = "7E39FD01-A6B5-4D78-9E11-37E28E9545F1"
PAIRING_SUITE = "CPACE-RISTR255-SHA512-RAPP-KC2 + Noise_XXpsk3_25519_ChaChaPoly_SHA512"
SESSION_SUITE = "Noise_KK_25519_ChaChaPoly_SHA512"
CPACE_DSI = b"CPaceRistretto255"
CPACE_ISK_DSI = b"CPaceRistretto255_ISK"
SHA512_BLOCK = 128
DISCOVERY_EPOCH_SECONDS = 900
WITHDRAWAL_COUNTER_SECONDS = 60
GENERATOR = "tools/rapp-vectors/generate.py"
# Rejected envelopes that test the version field itself keep their own; every
# other one carries the stamped version, so it fails for its stated reason.
VERSION_ENVELOPE_VECTORS = ("missing-version", "wrong-version-type", "unsupported-version")
PRIMITIVE_CHECKS = "RFC 7748 section 6.1, RFC 8439 section 2.8.2 and RFC 9496 appendix A.1"

VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "doc", "protocols", "vectors")


def h(x):
    return bytes.fromhex(x)


def provenance(sections):
    return (f"Derived by {GENERATOR} from the inputs in this file and RAPP v{DOCUMENT} {sections}, "
            f"with standard-library primitives checked against {PRIMITIVE_CHECKS}; the engine is not used.")


# ---------------------------------------------------------------- CPace KC2 (section 6.1)


LEB128_PAYLOAD_MASK = 127
LEB128_CONTINUATION = 128


def leb128(n):
    out = bytearray()
    while True:
        b = n & LEB128_PAYLOAD_MASK
        n >>= 7
        out.append(b | (LEB128_CONTINUATION if n else 0))
        if not n:
            return bytes(out)


def lv(b):
    return leb128(len(b)) + b


def lv_cat(*items):
    return b"".join(lv(i) for i in items)


def cpace(e):
    profile = e["transport_profile"]
    c = cbor(["rapp-pairing-context", VERSION, PAIRING_SUITE, profile, e["candidate_id"],
              h(e["offer_hash_hex"]), "requester", "custodian"])
    sid = h(e["offer_id_hex"])
    prs = e["pairing_code"].encode()
    zero_padding = bytes(SHA512_BLOCK - 1 - len(lv(prs)) - len(lv(CPACE_DSI)))
    g = from_uniform_bytes(sha512(lv_cat(CPACE_DSI, prs, zero_padding, c, sid)))
    xa = int.from_bytes(h(e["test_only_initiator_random_hex"]), "little") % Q
    xb = int.from_bytes(h(e["test_only_responder_random_hex"]), "little") % Q
    ya, yb = encode(scalar_mult(xa, g)), encode(scalar_mult(xb, g))
    k = encode(scalar_mult(xb, decode(ya)))
    assert k == encode(scalar_mult(xa, decode(yb)))
    isk = sha512(lv_cat(CPACE_ISK_DSI, sid, k) + lv_cat(ya, b"") + lv_cat(yb, b""))
    th = sha512(lv_cat(b"rapp-cpace-transcript", sid, c, ya, yb))
    prk = hmac512(th, isk)

    def expand(info):
        return hmac512(prk, info + bytes([1]))[:32]

    ka, kb = expand(b"rapp-cpace-confirm-a-key"), expand(b"rapp-cpace-confirm-b-key")
    tb = hmac512(kb, lv_cat(b"rapp-cpace-confirm-b", th))[:32]
    ta = hmac512(ka, lv_cat(b"rapp-cpace-confirm-a", th))[:32]
    return {"context_hex": c.hex(), "context_length": len(c), "generator_hex": encode(g).hex(),
            "step1_hex": ya.hex(), "step2_hex": (yb + tb).hex(), "step3_hex": ta.hex()}


# ---------------------------------------------------------------- offer, grants, identifiers, Noise (sections 4.2, 4.3, 6.2, 6.3)


def offer(e):
    transports = []
    for profile in sorted(e["transport_profiles"]):
        parameters = {"service_uuid": SERVICE_UUID} if profile == BLE else {}
        transports.append({"profile": profile, "candidate_id": CANDIDATE[profile], "parameters": parameters})
    body = cbor({"scheme": "rapp", "version": VERSION, "offer_id": h(e["offer_id_hex"]),
                 "suites": [PAIRING_SUITE], "profiles": e["profiles"], "transports": transports,
                 "offer_ttl_ms": OFFER_TTL_MS})
    return {"encoded_hex": body.hex(), "encoded_length": len(body), "offer_hash_hex": sha256(body).hex()}


def grants(e):
    canonical = cbor(sorted(set(e["profiles"]), key=lambda s: s.encode()))
    return {"canonical_cbor_hex": canonical.hex(), "sha256_hex": sha256(canonical).hex()}


def identifiers(handshake_hash):
    return (sha512(b"rapp-session-id" + handshake_hash)[:16].hex(),
            sha512(b"rapp-pair-id" + handshake_hash)[:16].hex())


def noise(e):
    i_s, r_s = h(e["test_only_initiator_static_private_hex"]), h(e["test_only_responder_static_private_hex"])
    i_e, r_e = h(e["test_only_initiator_ephemeral_private_hex"]), h(e["test_only_responder_ephemeral_private_hex"])
    out = {"initiator_static_public_hex": x25519_public(i_s).hex(),
           "responder_static_public_hex": x25519_public(r_s).hex()}
    if e["suite"] == SESSION_SUITE:
        prologue = cbor(["rapp-session", VERSION, SESSION_SUITE, h(e["pair_id_hex"]), h(e["grants_hash_hex"]),
                         e["transport_profile"]])
        messages, handshake_hash, c1, c2 = noise_kk(prologue, i_s, r_s, i_e, r_e)
        out.update(c1_initiator_to_responder_hex=c1.hex(), c2_responder_to_initiator_hex=c2.hex(),
                   session_id_hex=identifiers(handshake_hash)[0])
    else:
        prologue = cbor(["rapp-pairing", VERSION, PAIRING_SUITE, h(e["offer_hash_hex"]), e["transport_profile"]])
        messages, handshake_hash, _, _ = noise_xxpsk3(prologue, i_s, r_s, i_e, r_e, h(e["test_only_pairing_secret_hex"]))
        out["session_id_hex"], out["pair_id_hex"] = identifiers(handshake_hash)
    out.update(prologue_hex=prologue.hex(), messages_hex=[m.hex() for m in messages],
               handshake_hash_hex=handshake_hash.hex())
    return out


# ---------------------------------------------------------------- keys from the static agreement (sections 2.2.1, 4.3, 4.5)


def pair_key(info, pair_id, own_private, peer_private):
    agreement = x25519(own_private, x25519_public(peer_private))
    return agreement, hkdf256(pair_id, agreement, info)


def routing_tag(key, domain, nonce):
    d = domain.encode()
    return hmac256(key, bytes([len(d)]) + d + nonce)[:16]


def discovery_hint(key, epoch):
    return hmac256(key, struct.pack(">Q", epoch))[:8]


def withdrawal_hint(key, instance, counter):
    i = instance.encode()
    return hmac256(key, bytes([len(i)]) + i + struct.pack(">Q", counter))[:8]


def is_filler(entry):
    return len(entry) == 16 and len(set(entry[i:i + 2] for i in range(0, 16, 2))) == 1


def with_hint(value, hint):
    """Replace every non-filler 16-digit entry of a TXT list with hint, keeping its case."""
    out = []
    for entry in value.split(","):
        if len(entry) == 16 and not is_filler(entry):
            entry = hint.upper() if entry.isupper() else hint
        out.append(entry)
    return ",".join(out)


# ---------------------------------------------------------------- corpora


def main_corpus(d):
    d["format"] = "fi.refineid.rapp.conformance"
    d["protocol_document_version"] = DOCUMENT
    d["provenance"] = provenance("sections 4.2, 4.3, 6.1 to 6.3 and 7.2")
    for e in d["cpace_kc2"]:
        e.update(cpace(e))
    for e in d["pairing_offer"]:
        e.update(offer(e))
    for e in d["grants_hash"]:
        e.update(grants(e))
    for e in d["identifier_derivation"]:
        e["session_id_hex"], e["pair_id_hex"] = identifiers(h(e["handshake_hash_hex"]))
    for e in d["noise_handshake"]:
        e.update(noise(e))
    for e in d["wire_version"]:
        if e["expected"] == "accepted":
            e["version"] = VERSION
    for e in d["deterministic_cbor"]:
        e["encoded_hex"] = cbor(typed(e["value"])).hex()
    for e in d["rejected_envelope"]:
        if e["name"] in VERSION_ENVELOPE_VECTORS:
            continue
        envelope = cbor_decode(h(e["canonical_cbor_hex"]))
        envelope["version"] = VERSION
        e["canonical_cbor_hex"] = cbor(envelope).hex()
    return d


def typed(v):
    """The value a deterministic_cbor vector describes in its typed JSON form."""
    kind = v["kind"]
    if kind in ("unsigned", "negative", "bool", "text"):
        return v["value"]
    if kind == "null":
        return None
    if kind == "bytes":
        return bytes.fromhex(v["hex"])
    if kind == "array":
        return [typed(x) for x in v["items"]]
    if kind == "map":
        return {e["key"]: typed(e["value"]) for e in v["entries"]}
    raise ValueError(kind)


def routing_corpus(d):
    d["format"] = "fi.refineid.rapp.routing-vectors"
    d["protocol_document_version"] = DOCUMENT
    d["provenance"] = provenance("sections 2.2.1 and 4.3 and hierarchy specification section 4.3")
    k = d["pair_keys"][0]
    pair_id = h(k["pair_id_hex"])
    custodian, requester = h(k["custodian_static_private_hex"]), h(k["requester_static_private_hex"])
    agreement, disc = pair_key(b"rapp-discovery-hint", pair_id, custodian, requester)
    agreement_back, route = pair_key(b"rapp-routing", pair_id, requester, custodian)
    assert agreement == agreement_back
    _, withdrawal = pair_key(b"rapp-withdrawal", pair_id, custodian, requester)
    k.update(shared_secret_hex=agreement.hex(), discovery_key_hex=disc.hex(), routing_key_hex=route.hex())
    published = {}
    for e in d["discovery_hint"]:
        e["discovery_hint_hex"] = discovery_hint(disc, e["epoch"]).hex()
        published[e["epoch"]] = e["discovery_hint_hex"]
    for e in d["discovery_acceptance"]:
        if e["name"] == "withdrawal-hint-is-not-a-discovery-hint":
            minute = e["published_epoch"] * DISCOVERY_EPOCH_SECONDS // WITHDRAWAL_COUNTER_SECONDS
            e["published_hint_hex"] = withdrawal_hint(withdrawal, e["withdrawal_instance_name"], minute).hex()
        else:
            e["published_hint_hex"] = published[e["published_epoch"]]
    tags = {}
    for e in d["routing_tag"]:
        e["routing_tag_hex"] = routing_tag(route, DOMAIN[e["transport_profile"]], h(e["nonce_hex"])).hex()
        tags[e["transport_profile"]] = (e["nonce_hex"], e["routing_tag_hex"])
    for e in d["routing_preamble"]:
        value = b""
        if e["purpose"] == "session":
            e["routing_tag_hex"] = routing_tag(route, DOMAIN[e["transport_profile"]], h(e["nonce_hex"])).hex()
            value = h(e["nonce_hex"] + e["routing_tag_hex"])
        e["encoded_hex"] = cbor([DOMAIN[e["transport_profile"]], e["purpose"], value]).hex()
    for e in d["routing_lookup"]:
        nonce, tag = tags[STREAM]
        if e["name"] == "ble-tag-on-stream":
            tag = tags[BLE][1]
        elif e["name"] == "altered-tag":
            flipped = bytearray(h(tag))
            flipped[0] ^= 1
            tag = flipped.hex()
        e["routing_hex"] = nonce + tag
    hint = published[max(published)]
    for e in d["discovery_record"]:
        e["txt"] = [[key, with_hint(value, hint) if key.lower() == "hints" else value] for key, value in e["txt"]]
        if "hints_hex" in e:
            e["hints_hex"] = [hint for _ in e["hints_hex"]]
    return d


def withdrawal_corpus(d):
    d["format"] = "fi.refineid.rapp.withdrawal-vectors"
    d["protocol_document_version"] = DOCUMENT
    d["provenance"] = provenance("section 4.5 and the session-close-body schema of section 7.1")
    k = d["withdrawal_key"][0]
    pair_id = h(k["pair_id_hex"])
    custodian, requester = h(k["custodian_static_private_hex"]), h(k["requester_static_private_hex"])
    agreement, key = pair_key(b"rapp-withdrawal", pair_id, custodian, requester)
    k.update(shared_secret_hex=agreement.hex(), withdrawal_key_hex=key.hex(),
             custodian_static_public_hex=x25519_public(custodian).hex(),
             requester_static_public_hex=x25519_public(requester).hex())
    for e in d["withdrawal_hint"]:
        e["withdrawal_hint_hex"] = withdrawal_hint(key, e["instance_name"], e["counter"]).hex()
    hint = d["withdrawal_hint"][-1]["withdrawal_hint_hex"]
    for section in ("withdrawn_record", "malformed_record"):
        for e in d[section]:
            e["txt"] = [[k2, with_hint(v, hint) if k2.lower() == "withdrawn" else v] for k2, v in e["txt"]]
    for e in d["session_close"]:
        e["body_cbor_hex"] = cbor({"reason": e["reason"]}).hex()
    return d


def ble_sar_corpus(d):
    d["format"] = "fi.refineid.rapp.ble-sar-vectors"
    d["protocol_document_version"] = DOCUMENT
    d["provenance"] = (f"Written independently from RAPP v{DOCUMENT} section 5.3: header layout, flags, "
                       "capacity formula and the receive rules. Timestamps are monotonic milliseconds; error "
                       f"names label the violated receive rule. {GENERATOR} keeps only the metadata current.")
    return d


def operation_corpus(d):
    d["format"] = "fi.refineid.rapp.operation-vectors"
    d["protocol_document_version"] = DOCUMENT
    d["provenance"] = provenance("sections 7.1, 9 and 10.3: the CDDL of every operation message body")
    f = d["fixed_inputs"]
    card, auth, sign = "fi.refineid.card-status", "fi.refineid.authentication", "fi.refineid.document-signing"
    request_id, result_id, error_id = (h(f[k]) for k in ("operation_id_request", "operation_id_result", "operation_id_error"))

    def request(profile, action, context, payload):
        return {"operation_id": request_id, "profile": profile, "action": action, "context": context,
                "payload": payload, "expires_after_ms": f["expires_after_ms"]}

    def result(status, error=None, response=None):
        body = {"operation_id": result_id, "status": status}
        if error is not None:
            body["error"] = error
        if response is not None:
            body["response"] = response
        return body

    def error(name, operation_id):
        body = {"error_name": name, "message": f["error_messages"][name]}
        if operation_id is not None:
            body["operation_id"] = operation_id
        return body

    def card_status(card_present, reader_attached, certificate_fingerprint):
        return {"card_present": card_present, "reader_attached": reader_attached,
                "certificate_fingerprint": certificate_fingerprint}

    fingerprint = sha256(h(f["certificate_der"]))
    vectors = [
        ("request-inspect-card", "OperationRequest", request(card, "inspect_card", {}, {})),
        ("request-read-identity", "OperationRequest", request(card, "read_identity", {}, {})),
        ("request-read-certificate-authentication", "OperationRequest",
         request(auth, "read_certificate", {}, {"kind": "authentication"})),
        ("request-read-certificate-signature", "OperationRequest",
         request(sign, "read_certificate", {}, {"kind": "signature"})),
        ("request-browser-authenticate", "OperationRequest",
         request(auth, "browser_authenticate", {"origin": f["origin"]},
                 {"digest": h(f["digest_sha256"]), "algorithm": "rsa_pkcs1_sha256", "key_profile": "rsa_3072"})),
        ("request-sign-document", "OperationRequest",
         request(sign, "sign_document", {"document_name": f["document_name"]},
                 {"digest": h(f["digest_sha384"]), "algorithm": "ecdsa_sha384", "key_profile": "ecdsa_p384"})),
        ("request-batch-sign-documents", "OperationRequest",
         request(sign, "batch_sign_documents", {"document_names": f["batch_document_names"]},
                 {"digests": [h(x) for x in f["batch_digests_sha256"]], "algorithm": "ecdsa_sha256",
                  "key_profile": "ecdsa_p256"})),
        ("result-completed-inspection", "OperationResult",
         result("completed", response={"atr": h(f["atr"])})),
        ("result-completed-identity", "OperationResult",
         result("completed", response={"card_holder_name": f["holder_name"], "card_id": f["card_id"],
                                       "issuance_date": f["issuance_date"], "expiration_date": f["expiration_date"],
                                       "certificates": [h(f["certificate_der"])]})),
        ("result-completed-certificate", "OperationResult",
         result("completed", response={"certificate": h(f["certificate_der"])})),
        ("result-completed-signature", "OperationResult",
         result("completed", response={"signature": h(f["signature_bytes"])})),
        ("result-completed-batch-signatures", "OperationResult",
         result("completed", response={"signatures": [h(x) for x in f["batch_signatures"]]})),
        ("result-rejected-user-cancelled", "OperationResult", result("rejected", "user_cancelled")),
        ("result-cancelled-operation-expired", "OperationResult", result("cancelled", "operation_expired")),
        ("result-rejected-card-error", "OperationResult", result("rejected", "card_error")),
        ("result-rejected-unsupported-parameter", "OperationResult", result("rejected", "unsupported_parameter")),
        ("result-rejected-invalid-lifetime", "OperationResult", result("rejected", "invalid_lifetime")),
        ("result-rejected-unauthorized", "OperationResult", result("rejected", "unauthorized")),
        ("result-rejected-retry-floor", "OperationResult", result("rejected", "retry_floor")),
        ("result-rejected-operation-failed", "OperationResult", result("rejected", "operation_failed")),
        ("error-busy", "Error", error("busy", error_id)),
        ("error-duplicate-operation", "Error", error("duplicate_operation", error_id)),
        ("error-operation-failed-bare", "Error", error("operation_failed", None)),
        ("progress-queued", "OperationProgress", {"operation_id": result_id, "event": "queued"}),
        ("progress-consent-shown", "OperationProgress", {"operation_id": result_id, "event": "consent_shown"}),
        ("progress-waiting-for-card", "OperationProgress", {"operation_id": result_id, "event": "waiting_for_card"}),
        ("progress-card-wait-ended", "OperationProgress", {"operation_id": result_id, "event": "card_wait_ended"}),
        ("card-status-present-reader-attached", "CardStatus",
         card_status(True, True, fingerprint)),
        ("card-status-present-no-reader", "CardStatus",
         card_status(True, False, fingerprint)),
        ("card-status-absent-reader-attached", "CardStatus",
         card_status(False, True, bytes(len(fingerprint)))),
        ("card-status-absent-no-reader", "CardStatus",
         card_status(False, False, bytes(len(fingerprint)))),
        ("pairing-stored", "PairingStored", {"pair_id": h(f["pair_id"])}),
    ]
    rejected = [
        ("card-status-present-without-fingerprint", "CardStatus",
         card_status(True, True, bytes(len(fingerprint)))),
        ("card-status-absent-with-fingerprint", "CardStatus",
         card_status(False, True, fingerprint)),
        ("card-status-missing-reader-attached", "CardStatus",
         {"card_present": False, "certificate_fingerprint": bytes(len(fingerprint))}),
        ("result-completed-with-error", "OperationResult",
         result("completed", "operation_failed", {"signature": h(f["signature_bytes"])})),
        ("result-rejected-busy", "OperationResult", result("rejected", "busy")),
        ("result-unregistered-error", "OperationResult", result("rejected", "invalid_credential")),
        ("progress-unregistered-event", "OperationProgress", {"operation_id": result_id, "event": "unknown"}),
        ("error-unregistered-name", "Error", {"error_name": "unknown_operation", "message": "Unknown."}),
    ]
    d["vectors"] = [{"name": n, "message_type": m, "body_hex": cbor(b).hex()} for n, m, b in vectors]
    d["rejected"] = [{"name": n, "message_type": m, "body_hex": cbor(b).hex()} for n, m, b in rejected]
    return d


CORPORA = {
    "rapp-v26.10.29.json": main_corpus,
    "rapp-routing-v26.10.29.json": routing_corpus,
    "rapp-withdrawal-v26.10.29.json": withdrawal_corpus,
    "rapp-ble-sar-v26.10.29.json": ble_sar_corpus,
    "rapp-operation-v26.10.29.json": operation_corpus,
}


def render(d):
    return json.dumps(d, indent=2, ensure_ascii=False) + "\n"


def main():
    selftest()
    write = "--write" in sys.argv[1:]
    failed = False
    for name, derive in CORPORA.items():
        path = os.path.join(VECTORS, name)
        with open(path, encoding="utf-8") as f:
            text = f.read()
        derived = render(derive(copy.deepcopy(json.loads(text))))
        if derived == text:
            continue
        if write:
            with open(path, "w", encoding="utf-8") as f:
                f.write(derived)
            print(f"{name}: rewritten")
        else:
            print(f"{name}: differs from its derivation; run {GENERATOR} --write")
            failed = True
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
