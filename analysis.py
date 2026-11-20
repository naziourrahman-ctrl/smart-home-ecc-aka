"""
S3: per-packet cost of the data phase, proposed scheme vs the 2015 thesis design
(per-hop EC-ElGamal header re-encryption + end-to-end EC-ElGamal data).
S5: battery budget of periodic re-keying.
S6: host micro-benchmark of the primitives (this machine, OpenSSL via `cryptography`).
Also draws the paper's figures from results.json.
"""
import json, time, statistics, platform, subprocess, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from params import *
from sim import airtime, ACK_AIR

E = lambda seconds, current: seconds * current * V * 1e3      # mJ

def hop_radio_mJ(payload):
    a = airtime(payload)
    return E(a, I_TX) + E(a, I_RX) + E(ACK_AIR, I_TX) + E(ACK_AIR, I_RX)

READING = 16                      # bytes of sensor data per packet

def proposed(h):
    cpu = E(T_SYM_SN, I_CPU)                                   # one AES-CCM at source
    radio = h * hop_radio_mJ(READING + 8 + 4)                  # tag 8 + counter 4
    return cpu, radio

def thesis(h):
    ct = 66                                                    # EC-ElGamal ciphertext: 2 x 33-byte points
    src = 2 * (T_PM_FIXED_SN + T_PM_VAR_SN)                    # encrypt header and data
    relay = T_PM_VAR_SN + (T_PM_FIXED_SN + T_PM_VAR_SN)        # decrypt + re-encrypt header
    cpu = E(src + (h - 1) * relay, I_CPU)
    radio = h * 2 * hop_radio_mJ(ct)                           # 132 B > 116 B MAC payload: 2 frames
    return cpu, radio

s3 = {}
for h in (1, 2, 3, 4):
    pc, pr = proposed(h); tc, tr = thesis(h)
    s3[h] = {"proposed_mJ": pc + pr, "thesis_mJ": tc + tr, "ratio": (tc + tr) / (pc + pr)}

# S5: battery budget. ASSUMPTION: 2 x AA alkaline, 2500 mAh at 3 V -> 27 kJ.
BATTERY_J = 2.5 * 3600 * 3.0
res = json.load(open("results.json"))
hs_mJ = res["S1"]["1"]["sensor_energy_mJ"][0]
worst_mJ = res["S2"]["30"]["max_energy_mJ"][0]
s5 = {
    "battery_J": BATTERY_J,
    "daily_rekey_pct_per_year": 100 * 365 * hs_mJ / 1e3 / BATTERY_J,
    "hourly_rekey_pct_per_year": 100 * 365 * 24 * hs_mJ / 1e3 / BATTERY_J,
    "worst_coldstart_mJ": worst_mJ,
}

# S6: host micro-benchmark
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
import hmac, hashlib

def bench(fn, n=2000):
    ts = []
    for _ in range(n):
        s = time.perf_counter(); fn(); ts.append(time.perf_counter() - s)
    return 1e6 * statistics.median(ts)

k1, k2 = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
aes = AESCCM(os.urandom(16), 8)
s6 = {
    "cpu": subprocess.run("lscpu | grep 'Model name' | sed 's/.*: *//'", shell=True,
                          capture_output=True, text=True).stdout.strip() or platform.processor(),
    "keygen_us": bench(lambda: ec.generate_private_key(ec.SECP256R1())),
    "ecdh_us": bench(lambda: k1.exchange(ec.ECDH(), k2.public_key())),
    "hkdf_us": bench(lambda: HKDF(hashes.SHA256(), 32, None, b"sk").derive(os.urandom(64))),
    "hmac_us": bench(lambda: hmac.new(b"k" * 16, b"x" * 70, hashlib.sha256).digest()),
    "aesccm_us": bench(lambda: aes.encrypt(bytes(13), b"r" * 16, b"h" * 12)),
}

json.dump({"S3": s3, "S5": s5, "S6": s6}, open("analysis.json", "w"), indent=1)
print(json.dumps({"S3": s3, "S5": s5, "S6": s6}, indent=1))

# ---------------- figures ----------------
plt.rcParams.update({"font.size": 9, "font.family": "serif", "axes.spines.top": False,
                     "axes.spines.right": False})
INK, ACC, GREY = "#222222", "#1f5fae", "#9a9a9a"

# Fig. 2: cold start vs room size
ns = [5, 10, 15, 20, 30]
mk = [res["S2"][str(n)]["makespan"] for n in ns]
ml = [res["S2"][str(n)]["mean_latency"] for n in ns]
fig, ax = plt.subplots(figsize=(3.5, 2.4))
ax.errorbar(ns, [m for m, _ in mk], yerr=[c for _, c in mk], marker="o", ms=3.5, color=ACC,
            capsize=2, lw=1.2, label="Last node keyed")
ax.errorbar(ns, [m for m, _ in ml], yerr=[c for _, c in ml], marker="s", ms=3.5, color=GREY,
            capsize=2, lw=1.2, label="Mean per node")
ax.set_xlabel("Sensor nodes in the room"); ax.set_ylabel("Time after power-on (s)")
ax.set_ylim(0, None); ax.set_xticks(ns); ax.legend(frameon=False)
fig.tight_layout(); fig.savefig("fig2_coldstart.pdf"); fig.savefig("fig2_coldstart.png", dpi=300)

# Fig. 3: data-phase energy per packet vs hops
hs = [1, 2, 3, 4]
fig, ax = plt.subplots(figsize=(3.5, 2.4))
w = 0.38
ax.bar([h - w / 2 for h in hs], [s3[h]["thesis_mJ"] for h in hs], w, color=GREY,
       label="Per-hop EC-ElGamal (thesis design)")
ax.bar([h + w / 2 for h in hs], [s3[h]["proposed_mJ"] for h in hs], w, color=ACC,
       label="Proposed (ECDH key + AES-CCM)")
ax.set_yscale("log"); ax.set_xticks(hs); ax.set_ylim(0.05, 400)
ax.set_xlabel("Hops from sensor to gateway"); ax.set_ylabel("Energy per packet (mJ)")
ax.legend(frameon=False, fontsize=7.5, loc="upper left")
fig.tight_layout(); fig.savefig("fig3_dataphase.pdf"); fig.savefig("fig3_dataphase.png", dpi=300)
print("figures written")
