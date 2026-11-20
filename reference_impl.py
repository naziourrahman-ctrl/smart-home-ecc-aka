"""
Reference implementation of the intra-domain authenticated key agreement (AKA)
between a sensor node SN_i and its domain gateway GW_j, as specified in
Section V of the manuscript.

Purpose: check that both sides derive the same session key, that tampering is
rejected, and report message sizes. Timings printed here come from whatever
machine runs this script and are NOT the device measurements the paper needs.

Curve: NIST P-256. KDF: HKDF-SHA256. AEAD: AES-128-CCM (8-byte tag).
MAC: HMAC-SHA256 truncated to 16 bytes.
"""
import hmac, hashlib, os, time, statistics
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.exceptions import InvalidTag

CURVE = ec.SECP256R1()
NONCE0 = bytes(13)          # each AEAD key below is used for exactly one message
TAG = 8


def enc_pt(pub):            # 33-byte compressed point
    return pub.public_bytes(serialization.Encoding.X962,
                            serialization.PublicFormat.CompressedPoint)


def dec_pt(b):
    return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, b)


def hkdf(ikm, info, n=32):
    return HKDF(hashes.SHA256(), n, salt=None, info=info).derive(ikm)


def mac(k, *parts):
    return hmac.new(k, b"|".join(parts), hashlib.sha256).digest()[:16]


# ---------- setup / registration (secure commissioning channel) ----------
def register(gw, node_id):
    d = ec.generate_private_key(CURVE)                  # node long-term key
    gw["table"][node_id] = d.public_key()               # GW stores (ID_i, D_i)
    return {"id": node_id, "d": d, "X": gw["x"].public_key(), "gw_id": gw["id"]}


def new_gateway(gw_id):
    return {"id": gw_id, "x": ec.generate_private_key(CURVE), "table": {}}


# ---------- protocol ----------
def sn_msg1(sn):
    r = ec.generate_private_key(CURVE)
    R = enc_pt(r.public_key())
    K1 = r.exchange(ec.ECDH(), sn["X"])                 # r_i * X_j
    k1 = hkdf(K1 + R, b"m1", 16)
    C1 = AESCCM(k1, TAG).encrypt(NONCE0, sn["id"], R)   # hides ID_i
    st = {"r": r, "R": R, "K1": K1}
    return (R, C1), st


def gw_msg2(gw, m1):
    R, C1 = m1
    Rp = dec_pt(R)                                      # also validates the point
    K1 = gw["x"].exchange(ec.ECDH(), Rp)
    k1 = hkdf(K1 + R, b"m1", 16)
    node_id = AESCCM(k1, TAG).decrypt(NONCE0, C1, R)    # raises InvalidTag
    D = gw["table"][node_id]
    rg = ec.generate_private_key(CURVE)
    Rg = enc_pt(rg.public_key())
    Z1 = rg.exchange(ec.ECDH(), Rp)                     # r_g * R_i
    Z2 = rg.exchange(ec.ECDH(), D)                      # r_g * D_i
    sk = hkdf(K1 + Z1 + Z2 + R + Rg + node_id + gw["id"], b"sk", 32)
    Vg = mac(sk[16:], b"GW", R, Rg)
    return (Rg, Vg), {"sk": sk, "R": R, "Rg": Rg, "id": node_id}


def sn_msg3(sn, st, m2):
    Rg, Vg = m2
    Rgp = dec_pt(Rg)
    Z1 = st["r"].exchange(ec.ECDH(), Rgp)               # r_i * R_g
    Z2 = sn["d"].exchange(ec.ECDH(), Rgp)               # d_i * R_g
    sk = hkdf(st["K1"] + Z1 + Z2 + st["R"] + Rg + sn["id"] + sn["gw_id"], b"sk", 32)
    if not hmac.compare_digest(Vg, mac(sk[16:], b"GW", st["R"], Rg)):
        raise ValueError("gateway authentication failed")
    return mac(sk[16:], b"SN", st["R"], Rg), sk


def gw_finish(gst, Vi):
    if not hmac.compare_digest(Vi, mac(gst["sk"][16:], b"SN", gst["R"], gst["Rg"])):
        raise ValueError("node authentication failed")
    return gst["sk"]


def run_once(gw, sn):
    m1, st = sn_msg1(sn)
    m2, gst = gw_msg2(gw, m1)
    m3, sk_sn = sn_msg3(sn, st, m2)
    sk_gw = gw_finish(gst, m3)
    return m1, m2, m3, sk_sn, sk_gw


if __name__ == "__main__":
    gw = new_gateway(b"GW-LIVING")
    sn = register(gw, b"SN000017")                      # 8-byte identity

    m1, m2, m3, a, b = run_once(gw, sn)
    assert a == b, "session keys differ"
    print("Key agreement: OK (both sides hold the same 256-bit key)")
    sizes = (len(m1[0]) + len(m1[1]), len(m2[0]) + len(m2[1]), len(m3))
    print(f"Message sizes (bytes): M1={sizes[0]} M2={sizes[1]} M3={sizes[2]} total={sum(sizes)}")

    # negative tests
    m1, st = sn_msg1(sn)
    bad = (m1[0], bytes([m1[1][0] ^ 1]) + m1[1][1:])
    try:
        gw_msg2(gw, bad); print("FAIL: tampered M1 accepted")
    except InvalidTag:
        print("Tampered M1 rejected: OK")

    rogue = new_gateway(b"GW-LIVING")                   # attacker gateway, wrong key
    rogue["table"][sn["id"]] = sn["d"].public_key()
    m1, st = sn_msg1(sn)
    try:
        gw_msg2(rogue, m1); print("FAIL: rogue gateway read the identity")
    except InvalidTag:
        print("Rogue gateway cannot open M1 (identity stays hidden): OK")

    impostor = {"id": sn["id"], "d": ec.generate_private_key(CURVE),
                "X": sn["X"], "gw_id": sn["gw_id"]}       # knows ID but not d_i
    m1, st = sn_msg1(impostor)
    m2, gst = gw_msg2(gw, m1)
    try:
        sn_msg3(impostor, st, m2); print("FAIL: impostor accepted")
    except ValueError:
        print("Node impersonation without d_i rejected: OK")

    # rough timing on this host (illustrative only)
    t = []
    for _ in range(200):
        s = time.perf_counter(); run_once(gw, sn); t.append(time.perf_counter() - s)
    print(f"Full handshake on this host: median {statistics.median(t)*1e3:.2f} ms over 200 runs")
