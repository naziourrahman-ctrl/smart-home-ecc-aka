"""
Simulation parameters. Every value is either taken from a cited source or is a
stated modelling assumption. Keep this file in the paper's supplementary material.
"""

# ---------------- Sensor node profile: nRF52840-class (Cortex-M4F @ 64 MHz) -------------
# P-256 timings: p256-m on Cortex-M4 @ 100 MHz (STM32F411): keygen 145 ms, ECDH 144 ms
# (github.com/mpg/p256-m). ASSUMPTION: time scales linearly with clock -> x 100/64.
CLK_SCALE = 100 / 64
T_PM_FIXED_SN = 0.145 * CLK_SCALE        # R = rG (key generation), s
T_PM_VAR_SN = 0.144 * CLK_SCALE          # rP (ECDH shared secret), s
# ASSUMPTION: each SHA-256 KDF/MAC call and each AES-CCM call costs <= 1 ms on the node
# (conservative upper bound; the nRF52840 has an AES-CCM co-processor).
T_SYM_SN = 0.001

# Currents at 3 V, DC/DC (nRF52840 product brief v3.0): TX 0 dBm 6.40 mA, RX 6.26 mA.
# CPU: 52 uA/MHz running CoreMark from flash (nRF52840 PS) -> 3.33 mA at 64 MHz.
V = 3.0
I_TX = 6.40e-3
I_RX = 6.26e-3
I_CPU = 52e-6 * 64

# ---------------- Gateway profile: Raspberry-Pi-class --------------------------------------
# p256-m on Cortex-A7 @ 900 MHz (Raspberry Pi 2B): keygen 11 ms, ECDH 11 ms. A Pi 4 is faster,
# so this is conservative.
T_PM_GW = 0.011
T_SYM_GW = 0.0001                        # ASSUMPTION: 0.1 ms per symmetric op on gateway

# ---------------- IEEE 802.15.4 (2.4 GHz O-QPSK) PHY/MAC ------------------------------------
BYTE_TIME = 32e-6            # 250 kbit/s
UNIT_BACKOFF = 320e-6        # aUnitBackoffPeriod = 20 symbols
CCA_TIME = 128e-6            # 8 symbols
TURNAROUND = 192e-6          # aTurnaroundTime = 12 symbols
MIN_BE, MAX_BE = 3, 5
MAX_CSMA_BACKOFFS = 4
MAX_FRAME_RETRIES = 3
ACK_WAIT = 864e-6            # macAckWaitDuration (54 symbols)
PHY_OVERHEAD = 6             # preamble 4 + SFD 1 + PHR 1
MAC_OVERHEAD = 11            # FCF 2 + seq 1 + PAN 2 + dst 2 + src 2 + FCS 2 (short addresses)
TYPE_BYTE = 1                # ASSUMPTION: 1-byte message-type field in the payload
ACK_BYTES = 6 + 5            # PHY overhead + imm-ACK MPDU

# ---------------- Protocol message payloads (bytes), from reference_impl.py ---------------
M1, M2, M3 = 49, 49, 16

# ---------------- Backbone between gateways (Wi-Fi/Ethernet) -------------------------------
# ASSUMPTION: one-way latency uniform in [1, 5] ms.
BACKBONE_MIN, BACKBONE_MAX = 0.001, 0.005
