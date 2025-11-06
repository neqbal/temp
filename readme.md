# PyTunnel — Minimal WireGuard-inspired VPN (Student Project)

**Status:** Design & implementation plan for a semester project. This README collects: project layout, protocol and feature design, TAP/bridge QEMU setup, demo plans (DDoS cookie challenge & replay protection), developer milestones, commands, and a suggested Gemini CLI prompt to generate the program scaffolding.

---

## Project summary

PyTunnel is a lightweight, educational VPN prototype inspired by WireGuard. It runs in userspace, uses a TUN device for capturing IP packets, tunnels them over UDP, and implements a simplified Noise-style handshake with X25519 + HKDF + ChaCha20-Poly1305.

Focus features for the semester project:

* Handshake / authentication (client and server static keys + ephemeral keys)
* Stateless cookie-based DDoS mitigation (server returns cookie challenge)
* Per-session replay protection (sliding-window bitmap)
* Separate client & server implementations (clean repo layout)
* TUN ↔ UDP forwarding and exit-node (NAT) demo

> This prototype is educational. **Do not** use it for production traffic without a security review.

---

## Repository layout

```
pytunnel/
├── README.md
├── pyproject.toml (or requirements.txt)
├── LICENSE
├── docs/
│   └── design.md
├── configs/
│   ├── server.yaml
│   └── client.yaml
├── scripts/
│   ├── genkeys.py
│   ├── run_server.sh
│   └── run_client.sh
├── tools/
│   ├── replay_attack.py
│   └── flood_attack.py
├── tests/
│   ├── test_handshake.py
│   └── test_replay_window.py
└── src/
    └── pytunnel/
        ├── cli/
        │   ├── server_cli.py
        │   └── client_cli.py
        ├── config.py
        ├── logconfig.py
        ├── common/
        │   ├── proto.py
        │   ├── crypto.py
        │   ├── cookie.py
        │   ├── replay.py
        │   └── netio.py
        ├── server/
        │   ├── server.py
        │   ├── session.py
        │   └── dos_metrics.py
        └── client/
            ├── client.py
            └── tun_route.py
```

---

## High-level protocol design

**Messages** (simplified):

* `MSG_INIT` — client ephemeral pubkey || client static pubkey || client nonce
* `MSG_COOKIE_CHALLENGE` — server stateless cookie || timestamp
* `MSG_INIT_WITH_COOKIE` — cookie || init\_payload
* `MSG_RESP` — server ephemeral pubkey || encrypted server static (optional)
* `MSG_DATA` — seq (uint64) || nonce || ciphertext

**Handshake (simplified Noise-like):**

1. Client -> Server: `MSG_INIT` (no cookie)
2. Server -> Client: `MSG_COOKIE_CHALLENGE` (stateless HMAC cookie — *server allocates no state yet*)
3. Client -> Server: `MSG_INIT_WITH_COOKIE` (cookie proves reachability)
4. Server verifies cookie, computes DHs and derives AEAD keys, creates session, replies `MSG_RESP`
5. Client and server now exchange encrypted `MSG_DATA` packets using ChaCha20-Poly1305.

**Key derivation:**

* Compute three X25519 DHs (ephemeral/static combinations) and `IKM = SHA256(DH1||DH2||DH3)`. Use HKDF to derive separate AEAD keys for each direction.

**Cookie mechanics:**

* `cookie = HMAC(cookie_secret, ip||port||ts||init_payload)[:16] || ts(4)`
* TTL e.g. 10–30s. Server verifies cookie by recomputing HMAC and checking timestamp freshness.

**Replay protection:**

* Each session has a monotonic `seq` counter (uint64) in each `MSG_DATA` packet.
* Server maintains a `ReplayWindow` (default 64-bit bitmap).
* `accept(seq)` logic: accepts new larger seq (shifts bitmap), accepts in-window unseen seq, rejects duplicates or too-old seq.

---

## DDoS mitigation strategy

* On `MSG_INIT` from unknown source: **do not** allocate session or perform expensive crypto. Instead reply with a `MSG_COOKIE_CHALLENGE` computed statelessly.
* Only after client returns `MSG_INIT_WITH_COOKIE` with a valid cookie does server do the DHs and create per-peer session state.
* Additional optional mitigations:

  * Per-source rate-limiter (token bucket) to temporarily blacklist aggressive inits.
  * Global thresholding: if handshake flood detected, increase cookie TTL or drop inits.

---

## Replay protection details

* `MSG_DATA` includes a clear or AEAD-associated `seq` number.
* Server's per-session `ReplayWindow` holds `max_seq` and a bitmap for the last `window_size` packets (default 64).
* Accept/reject rules described earlier; implement `ReplayWindow.accept(seq)` and log `replay_drops` for demo.

---

## TAP + Bridge network setup (host)

Both the server and client VMs are connected through a host bridge 
client and server ips are different

## Commands & usage

**Generate keys:**

```bash
python3 scripts/genkeys.py --out-dir ./keys --name server
python3 scripts/genkeys.py --out-dir ./keys --name client
```

**Run server (inside server VM):**

```bash
sudo python3 -m src.pytunnel.cli.server_cli --config configs/server.yaml
```

**Run client (inside client VM):**

```bash
sudo python3 -m src.pytunnel.cli.client_cli --config configs/client.yaml
```

**Attacks / test tools (host or attacker VM):**

* Flood: `python3 tools/flood_attack.py --target 192.168.100.10 --port 51820 --rate 1000`
* Replay: capture a packet with tcpdump, then `python3 tools/replay_attack.py --pcap captured.pcap --send-to 192.168.100.10:51820`

**Useful debug commands:**

* `sudo tcpdump -n -i any udp port 51820 -w server_wg.pcap`
* `sudo tcpdump -n -i eth0` (host) or `-i tun0` (server internal)
* `htop` / `top` for CPU during flood

---

## Security & limitations

* Simplified handshake (does not fully implement Noise transcript and strong state machine used by production WireGuard).
* Cookie secret rotation and other advanced DoS protections not implemented by default.
* No kernel fast-path; userspace performance and security differ from kernel WireGuard.
* AEAD usage and AAD binding must be carefully checked before any real-world use.

---
