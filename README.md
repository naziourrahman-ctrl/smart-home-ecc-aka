# Supplementary material: multi-domain smart-home AKA

- `reference_impl.py`: Python reference implementation of the intra-domain handshake (checks key agreement and rejection of tampered/impersonated messages).
- `intra_domain_aka.pv`: ProVerif model. Run: `proverif intra_domain_aka.pv`
- `params.py`: every simulation parameter, with its source or stated assumption.
- `sim.py`: SimPy discrete-event simulation (802.15.4 CSMA/CA, multi-hop, cold start, cross-domain). Writes `results.json`.
- `analysis.py`: per-packet data-phase comparison, battery budget, host micro-benchmark, figures. Writes `analysis.json`, `fig2_coldstart.*`, `fig3_dataphase.*`.

Reproduce: `pip install simpy matplotlib cryptography && python3 sim.py && python3 analysis.py`
Seeds are fixed, so results are reproducible.
