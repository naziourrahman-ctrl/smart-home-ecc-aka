"""
Discrete-event simulation of the proposed multi-domain smart-home AKA over
IEEE 802.15.4 unslotted CSMA/CA (SimPy).

Model summary (state these in the paper):
- One room = one domain = one 802.15.4 channel; all nodes of a room hear each other
  (single collision domain, no hidden terminals). Rooms use different channels.
- Nodes sit in a collection tree of depth <= D under the room gateway. Relays forward
  frames without cryptographic work.
- Unslotted CSMA/CA with standard constants, immediate ACKs, up to 3 frame retries.
  Two transmissions that overlap in time both fail.
- A handshake whose message is dropped after all retries restarts after a random
  1-2 s back-off with fresh ephemeral keys.
- Energy counts only protocol-attributable work: CPU time for crypto, radio TX time,
  and RX time of frames addressed to the node (incl. ACKs). Idle listening is excluded.
"""
import random, statistics, json, math, sys
import simpy
from params import *


def airtime(payload):
    return (PHY_OVERHEAD + MAC_OVERHEAD + TYPE_BYTE + payload) * BYTE_TIME


ACK_AIR = ACK_BYTES * BYTE_TIME


class Channel:
    def __init__(self, env):
        self.env = env
        self.active = []                       # list of dicts {start, end, bad}

    def busy(self):
        now = self.env.now
        return any(t["start"] <= now < t["end"] for t in self.active)

    def start_tx(self, dur):
        now = self.env.now
        tx = {"start": now, "end": now + dur, "bad": False}
        for t in self.active:
            if t["start"] < tx["end"] and now < t["end"]:
                t["bad"] = True
                tx["bad"] = True
        self.active.append(tx)
        return tx

    def end_tx(self, tx):
        self.active.remove(tx)


class Stats:
    def __init__(self):
        self.energy = {}                       # node -> joules
        self.frames = 0
        self.retries = 0
        self.cca_fail = 0

    def add(self, node, joules):
        self.energy[node] = self.energy.get(node, 0.0) + joules


def link_send(env, ch, st, src, dst, payload, rng):
    """One hop with CSMA/CA, ACK and retries. Returns True on success."""
    dur = airtime(payload)
    for attempt in range(MAX_FRAME_RETRIES + 1):
        if attempt:
            st.retries += 1
        nb, be = 0, MIN_BE
        while True:
            yield env.timeout(rng.randint(0, 2 ** be - 1) * UNIT_BACKOFF)
            yield env.timeout(CCA_TIME)
            if not ch.busy():
                break
            nb += 1
            be = min(be + 1, MAX_BE)
            if nb > MAX_CSMA_BACKOFFS:
                st.cca_fail += 1
                nb = -1
                break
        if nb == -1:
            continue                          # channel-access failure: next attempt
        yield env.timeout(TURNAROUND)
        tx = ch.start_tx(dur)
        st.frames += 1
        st.add(src, dur * I_TX * V)
        yield env.timeout(dur)
        ch.end_tx(tx)
        if tx["bad"]:
            yield env.timeout(ACK_WAIT)
            continue
        st.add(dst, dur * I_RX * V)
        yield env.timeout(TURNAROUND)
        ack = ch.start_tx(ACK_AIR)
        st.add(dst, ACK_AIR * I_TX * V)
        yield env.timeout(ACK_AIR)
        ch.end_tx(ack)
        if ack["bad"]:
            continue
        st.add(src, ACK_AIR * I_RX * V)
        return True
    return False


def path_send(env, ch, st, path, payload, rng):
    for a, b in zip(path, path[1:]):
        ok = yield env.process(link_send(env, ch, st, a, b, payload, rng))
        if not ok:
            return False
    return True


def cpu(env, st, node, seconds):
    st.add(node, seconds * I_CPU * V)
    yield env.timeout(seconds)


def handshake(env, ch, st, gw_cpu, node, path_up, rng, out, t0_jitter):
    yield env.timeout(t0_jitter)
    t_start = env.now
    attempts = 0
    while True:
        attempts += 1
        # SN: R_i = r_i G (fixed base), K1 = r_i X_j, KDF, AE
        yield env.process(cpu(env, st, node, T_PM_FIXED_SN + T_PM_VAR_SN + 2 * T_SYM_SN))
        ok = yield env.process(path_send(env, ch, st, path_up, M1, rng))
        if ok:
            with gw_cpu.request() as req:     # gateway serves one handshake at a time
                yield req
                yield env.timeout(4 * T_PM_GW + 4 * T_SYM_GW)
            ok = yield env.process(path_send(env, ch, st, path_up[::-1], M2, rng))
        if ok:
            # SN: Z1, Z2, KDF, verify V_g, MAC V_i
            yield env.process(cpu(env, st, node, 2 * T_PM_VAR_SN + 3 * T_SYM_SN))
            ok = yield env.process(path_send(env, ch, st, path_up, M3, rng))
        if ok:
            yield env.timeout(T_SYM_GW)        # gateway verifies V_i
            out.append({"node": node, "hops": len(path_up) - 1,
                        "latency": env.now - t_start, "done": env.now, "attempts": attempts})
            return
        yield env.timeout(rng.uniform(1.0, 2.0))


def build_tree(n, depth, rng):
    """Return {node: path to gateway 'GW'} with depths spread evenly over 1..depth."""
    levels = {d: [] for d in range(1, depth + 1)}
    paths = {}
    for i in range(n):
        d = 1 + (i % depth)
        levels[d].append(i)
    for d in range(1, depth + 1):
        for v in levels[d]:
            if d == 1 or not levels[d - 1]:
                paths[v] = [v, "GW"]
            else:
                p = rng.choice(levels[d - 1])
                paths[v] = [v] + paths[p]
    return paths


def run_domain(n, depth, seed, boot_window=0.1):
    rng = random.Random(seed)
    env = simpy.Environment()
    ch, st = Channel(env), Stats()
    gw_cpu = simpy.Resource(env, capacity=1)
    paths = build_tree(n, depth, rng)
    out = []
    for v, p in paths.items():
        env.process(handshake(env, ch, st, gw_cpu, v, p, rng, out, rng.uniform(0, boot_window)))
    env.run()
    assert len(out) == n
    lat = [o["latency"] for o in out]
    sensor_e = [st.energy.get(v, 0.0) for v in paths]
    return {
        "makespan": max(o["done"] for o in out),
        "mean_latency": statistics.mean(lat),
        "restarts": sum(o["attempts"] - 1 for o in out),
        "retries": st.retries, "frames": st.frames, "cca_fail": st.cca_fail,
        "mean_energy_mJ": 1e3 * statistics.mean(sensor_e),
        "max_energy_mJ": 1e3 * max(sensor_e),
        "per_node": out,
    }


def run_single(hops, seed):
    """One node at a given depth, others idle (relay chain only)."""
    rng = random.Random(seed)
    env = simpy.Environment()
    ch, st = Channel(env), Stats()
    gw_cpu = simpy.Resource(env, capacity=1)
    path = ["N"] + [f"R{i}" for i in range(hops - 1)] + ["GW"]
    out = []
    env.process(handshake(env, ch, st, gw_cpu, "N", path, rng, out, 0.0))
    env.run()
    relays = sum(st.energy.get(f"R{i}", 0.0) for i in range(hops - 1))
    return out[0]["latency"], st.energy["N"], relays


def run_cross(hops, seed):
    """Cross-domain key setup (Phase E) between SN_a and SN_b, each `hops` from its gateway."""
    rng = random.Random(seed)
    env = simpy.Environment()
    cha, chb, st = Channel(env), Channel(env), Stats()
    pa = ["A"] + [f"RA{i}" for i in range(hops - 1)] + ["GWj"]
    pb = ["B"] + [f"RB{i}" for i in range(hops - 1)] + ["GWk"]
    res = {}

    def bb():
        return rng.uniform(BACKBONE_MIN, BACKBONE_MAX)

    def proc():
        t0 = env.now
        yield env.process(cpu(env, st, "A", T_PM_FIXED_SN + T_SYM_SN))          # E_a, AE
        yield env.process(path_send(env, cha, st, pa, 1 + 8 + 33 + 8 + 12, rng))  # REQ
        yield env.timeout(2 * T_SYM_GW + bb())                                  # GWj -> GWk
        yield env.timeout(2 * T_SYM_GW)
        yield env.process(path_send(env, chb, st, pb[::-1], 8 + 33 + 8 + 12, rng))
        yield env.process(cpu(env, st, "B", T_PM_FIXED_SN + T_PM_VAR_SN + 4 * T_SYM_SN))
        yield env.process(path_send(env, chb, st, pb, 33 + 16 + 12, rng))        # E_b, MAC
        yield env.timeout(2 * T_SYM_GW + bb() + 2 * T_SYM_GW)
        yield env.process(path_send(env, cha, st, pa[::-1], 33 + 16 + 12, rng))
        yield env.process(cpu(env, st, "A", T_PM_VAR_SN + 4 * T_SYM_SN))
        res["key_at_A"] = env.now - t0
        yield env.process(path_send(env, cha, st, pa, 16 + 12, rng))             # confirm
        yield env.timeout(2 * T_SYM_GW + bb() + 2 * T_SYM_GW)
        yield env.process(path_send(env, chb, st, pb[::-1], 16 + 12, rng))
        yield env.process(cpu(env, st, "B", 2 * T_SYM_SN))
        res["both_confirmed"] = env.now - t0
        res["E_A"], res["E_B"] = st.energy["A"], st.energy["B"]

    env.process(proc())
    env.run()
    return res


def ci95(xs):
    m = statistics.mean(xs)
    if len(xs) < 2:
        return m, 0.0
    return m, 1.96 * statistics.stdev(xs) / math.sqrt(len(xs))


if __name__ == "__main__":
    SEEDS = range(1, 31)
    results = {"params": {k: v for k, v in globals().items()
                          if k.isupper() and isinstance(v, (int, float))}}

    # S1: single handshake vs hop count
    s1 = {}
    for h in (1, 2, 3, 4):
        runs = [run_single(h, s) for s in range(1, 201)]
        lat, en, rel = zip(*runs)
        s1[h] = {"latency_ms": ci95([1e3 * x for x in lat]),
                 "sensor_energy_mJ": ci95([1e3 * x for x in en]),
                 "relay_energy_mJ_total": ci95([1e3 * x for x in rel])}
    results["S1"] = s1

    # S2: cold start of a whole room
    s2 = {}
    for n in (5, 10, 15, 20, 30):
        runs = [run_domain(n, 3, s) for s in SEEDS]
        s2[n] = {k: ci95([r[k] for r in runs]) for k in
                 ("makespan", "mean_latency", "restarts", "retries", "frames",
                  "mean_energy_mJ", "max_energy_mJ")}
    results["S2"] = s2

    # S4: cross-domain
    s4 = {}
    for h in (1, 2, 3):
        runs = [run_cross(h, s) for s in range(1, 201)]
        s4[h] = {"key_at_A_ms": ci95([1e3 * r["key_at_A"] for r in runs]),
                 "both_confirmed_ms": ci95([1e3 * r["both_confirmed"] for r in runs]),
                 "E_A_mJ": ci95([1e3 * r["E_A"] for r in runs]),
                 "E_B_mJ": ci95([1e3 * r["E_B"] for r in runs])}
    results["S4"] = s4

    with open("results.json", "w") as f:
        json.dump(results, f, indent=1, default=str)
    print(json.dumps({k: results[k] for k in ("S1", "S2", "S4")}, indent=1))
