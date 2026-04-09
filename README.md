#  Live Polling & Voting System

> **Socket Programming Mini Project**  
> A secure, real-time networked polling application using low-level UDP and TLS/TCP socket programming in Python.

---

##  Problem Statement

Design and implement a real-time polling and voting system where:
- Multiple clients submit votes over UDP with custom packet format
- Results are broadcast periodically to all clients
- An admin controls polls via a secure TLS/SSL TCP channel
- The server provides reliability guarantees: duplicate detection, HMAC integrity, ACK/NACK, and packet loss analysis

---

##  System Architecture

```
┌────────────────────────────────────────────────────────────┐
│                         SERVER                             │
│                                                            │
│  ┌──────────────┐  ┌────────────────┐  ┌───────────────┐   │
│  │  UDP Thread  │  │  TLS Control   │  │  Broadcaster  │   │
│  │  Port 9999   │  │  Thread :9443  │  │  Thread :9997 │   │
│  └──────┬───────┘  └───────┬────────┘  └───────┬───────┘   │
│         │                  │                   │           │
│         └──────────────────┴───────────────────┘           │
│                      Shared State (thread-safe)            │
└────────────────────────────────────────────────────────────┘
         ▲ UDP votes                ▲ TLS cmds        ▼ UDP broadcast
         │                          │                 │
┌────────┴──────┐         ┌─────────┴──────┐  ┌───────┴────────┐
│  CLIENT(s)    │         │  ADMIN CLIENT  │  │  All Clients   │
│  client.py    │         │  admin.py      │  │  (receive)     │
└───────────────┘         └────────────────┘  └────────────────┘
```

### Communication Flow

| Channel       | Protocol | Port | Purpose                        |
|---------------|----------|------|--------------------------------|
| Vote channel  | UDP      | 9999 | Clients → Server (vote packets)|
| Control channel| TCP+TLS | 9443 | Admin → Server (poll control)  |
| Broadcast     | UDP      | 9997 | Server → All clients (results) |

---

##  Security Implementation (SSL/TLS + HMAC)

### 1. TLS/SSL (TCP Port 9998 for Admin Commands)
- All admin commands use secure connection (TLS 1.2+)
- Server authenticates with a certificate
- Client verifies server certificate using `server.crt`

### 2. HMAC-SHA256 on Vote Packets (UDP)
- Each vote packet includes a secure hash (HMAC-SHA256)
- Created using a shared secret key
- Server verifies it using safe comparison.
- Tampered packets are rejected with `NACK:tampered`

### 3. Custom Vote Packet Format

```
 Bytes 0–31    : HMAC-SHA256 (32 bytes)
 Bytes 32–35   : client_id  
 Bytes 36–39   : seq        (duplicate detection)
 Bytes 40–43   : poll_id    
 Byte  44      : vote_option 
 Total: 45 bytes
```

---

##  Setup & Installation

### Prerequisites
- Python 3.8+
- OpenSSL (for cert generation) or git bash

### 1. Clone / Download

```bash
git clone https://github.com/PSaanviBhat/UE24CS252B-mini-project
```

### 2. Generate TLS Certificates

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 \
  -keyout certs/server.key \
  -out certs/server.crt \
  -days 365 -nodes \
  -subj "/CN=localhost/O=VotingSystem/C=IN"
```

### 3. Configure Server IP

Edit `client.py` and `admin.py` — change `SERVER_IP` to your server's IP address.

---

##  Usage

### Start the Server

```bash
python3 server.py
```

### Start Admin Client (on server machine or LAN)

```bash
python3 admin.py [SERVER_IP]
```

Admin commands:
```
create   → Create a new poll (guided prompt)
open     → Open voting
close    → Close voting
results  → Live results with per-option counts
stats    → Packet loss & reliability statistics
reset    → Reset vote counts
exit     → Disconnect
```

### Start Voting Client(s)

```bash
python3 client.py [SERVER_IP]
```

### Run Performance Test

```bash
# Syntax: python3 perf_test.py <num_clients> <votes_per_client>
python3 perf_test.py 10 20
```

---

##  Reliability Guarantees

| Feature | Implementation |
|---|---|
| Duplicate detection | `(client_id, seq)` set on server |
| HMAC integrity | 32-byte HMAC-SHA256 per packet |
| ACK/NACK | Server replies per packet; client retries up to 3× |
| Sequence tracking | Per-client seq gap detection → loss estimate |
| Tamper detection | HMAC mismatch → `NACK:tampered` + log |

---

##  Performance Evaluation

Run `perf_test.py` to simulate concurrent clients. Sample output:

```
  Elapsed time      : 0.842s
  Throughput        : 118.7 votes/sec
  ACKs received     : 98
  Timeouts (lost)   : 2
  Packet loss rate  : 2.00%
  Avg RTT           : 1.24 ms
  Min RTT           : 0.61 ms
  Max RTT           : 8.93 ms
```

---

##  File Structure

```
voting-system/
├── server.py        ← Main server (UDP + TLS + broadcast threads)
├── client.py        ← Interactive voting client
├── admin.py         ← TLS admin control client
├── perf_test.py     ← Concurrent client performance tester
├── certs/
│   ├── server.crt   ← TLS certificate (generated)
│   └── server.key   ← TLS private key (generated)
└── README.md
```

---

##  Design Decisions

1. **UDP for votes** — Lower latency; matches real polling systems; reliability handled at application layer (ACK/retry, duplicate detection)
2. **TLS TCP for control** — Admin operations need reliability and confidentiality; TCP guarantees delivery
3. **HMAC over plain hash** — HMAC-SHA256 is cryptographically stronger than `sha256(data + key)`; resistant to length-extension attacks
4. **Thread per control client** — Allows multiple admins simultaneously with minimal overhead
5. **Broadcast over multicast** — Simpler to set up on LANs without multicast routing; uses `SO_BROADCAST`

---
 
Socket Programming Mini Project — Jackfruit