"""
  Live Polling & Voting System — SERVER
  Socket Programming Mini Project 
  Features:
    - UDP socket for vote reception (custom packet format)
    - TLS/SSL TCP control channel for admin & result queries
    - Duplicate vote detection (client_id + seq)
    - HMAC-SHA256 integrity verification
    - Periodic result broadcasting (UDP multicast-style)
    - Statistical packet loss analysis
    - Multiple concurrent clients (threading)
    - Active poll management (create/close polls)
"""

import socket
import struct
import hashlib
import hmac
import threading
import time
import json
import ssl
import os
import datetime

UDP_IP        = "0.0.0.0"
UDP_PORT      = 9999
TLS_IP        = "0.0.0.0"
TLS_PORT      = 9443
BROADCAST_IP  = "255.255.255.255"
BROADCAST_PORT= 9997
BROADCAST_INTERVAL = 5          # seconds between result broadcasts

SECRET_KEY = b"securekey_voting2025"

CERT_FILE  = "certs/server.crt"
KEY_FILE   = "certs/server.key"

lock       = threading.Lock()
votes      = {}          # option_label -> count
poll_open  = False
poll_title = ""
options    = []          # list of option labels

# Reliability tracking
total_received   = 0     # all packets received (including bad/dup)
valid_votes      = 0     # accepted votes
duplicate_count  = 0
tampered_count   = 0
received_seqs    = set() # (client_id, seq) pairs

# Per-client sequence tracking for loss analysis
client_stats = {}        # client_id -> {"last_seq": int, "expected": int, "lost": int}

# Log
log_lines = []

def log(msg):
    ts  = datetime.datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    with lock:
        log_lines.append(line)


# Packet Format 
# | 32 bytes HMAC-SHA256 | 4B client_id | 4B seq | 4B poll_id | 1B vote_option |
# Total header = 32 + 13 = 45 bytes

HMAC_LEN    = 32
PAYLOAD_FMT = "!IIIB"   # client_id, seq, poll_id, vote_option
PAYLOAD_SIZE = struct.calcsize(PAYLOAD_FMT)   # 13 bytes

def verify_and_parse(packet):
    """Returns (client_id, seq, poll_id, vote_option) or raises ValueError."""
    if len(packet) < HMAC_LEN + PAYLOAD_SIZE:
        raise ValueError("Packet too short")

    recv_hmac = packet[:HMAC_LEN]
    payload   = packet[HMAC_LEN:]

    # HMAC-SHA256 integrity check (stronger than plain hash)
    calc_hmac = hmac.new(SECRET_KEY, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(recv_hmac, calc_hmac):
        raise PermissionError("HMAC mismatch — packet tampered")

    client_id, seq, poll_id, vote_option = struct.unpack(PAYLOAD_FMT, payload)
    return client_id, seq, poll_id, vote_option


# UDP Vote Receiver 
def udp_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((UDP_IP, UDP_PORT))
    log(f"UDP vote receiver listening on port {UDP_PORT}")

    while True:
        try:
            packet, addr = sock.recvfrom(1024)
        except Exception as e:
            log(f"UDP recv error: {e}")
            continue

        response = None
        log_msg   = None

        with lock:
            global total_received, valid_votes, duplicate_count, tampered_count

            total_received += 1

            try:
                client_id, seq, poll_id, vote_option = verify_and_parse(packet)
            except PermissionError as e:
                tampered_count += 1
                log_msg  = f"TAMPERED packet from {addr}: {e}"
                response = b"NACK:tampered"
            except Exception as e:
                log_msg  = f"INVALID packet from {addr}: {e}"
                response = b"NACK:invalid"

            if response is None:
                vote_id = (client_id, seq)
                if vote_id in received_seqs:
                    duplicate_count += 1
                    log_msg  = f"DUPLICATE from client {client_id} seq {seq}"
                    response = b"NACK:duplicate"
                elif not poll_open:
                    log_msg  = f"Vote rejected (poll closed) from {addr}"
                    response = b"NACK:poll_closed"
                elif vote_option < 1 or vote_option > len(options):
                    log_msg  = f"Invalid option {vote_option} from {addr}"
                    response = b"NACK:bad_option"
                else:
                    # Accept vote
                    received_seqs.add(vote_id)
                    chosen = options[vote_option - 1]
                    votes[chosen] = votes.get(chosen, 0) + 1
                    valid_votes += 1

                    if client_id not in client_stats:
                        client_stats[client_id] = {"last_seq": seq, "expected": seq, "lost": 0}
                    else:
                        expected = client_stats[client_id]["last_seq"] + 1
                        if seq > expected:
                            lost = seq - expected
                            client_stats[client_id]["lost"] += lost
                            log(f"Loss detected: client {client_id} seq gap {expected}→{seq}")
                        client_stats[client_id]["last_seq"] = seq

                    log_msg  = f"VOTE from {addr} | client={client_id} seq={seq} → '{chosen}' | Tally: {votes}"
                    response = b"ACK"

        if log_msg:
            log(log_msg)
        if response:
            sock.sendto(response, addr)


def broadcaster():
    """Periodically UDP-broadcast current results to the LAN."""
    bcast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bcast_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    while True:
        time.sleep(BROADCAST_INTERVAL)
        with lock:
            payload = {
                "type"   : "broadcast",
                "title"  : poll_title,
                "open"   : poll_open,
                "votes"  : dict(votes),
                "total"  : valid_votes,
                "dup"    : duplicate_count,
                "tampered": tampered_count,
                "time"   : datetime.datetime.now().strftime("%H:%M:%S"),
            }
        msg = json.dumps(payload).encode()
        try:
            bcast_sock.sendto(msg, (BROADCAST_IP, BROADCAST_PORT))
        except Exception:
            pass    

def handle_control_client(conn, addr):
    """Handles one TLS control connection."""
    global poll_open, poll_title, options, votes, received_seqs
    global valid_votes, duplicate_count, tampered_count, total_received

    log(f"Control client connected: {addr}")
    try:
        conn.sendall(b"WELCOME VotingSystem/1.0\n")

        while True:
            raw = conn.recv(4096)
            if not raw:
                break
            cmd = raw.decode(errors="ignore").strip()
            log(f"CMD from {addr}: {cmd}")

            if cmd.startswith("CREATE "):
                parts = cmd[7:].split("|")
                if len(parts) != 2:
                    conn.sendall(b"ERROR: Usage: CREATE <title>|<opt1>,<opt2>\n")
                    continue
                title_new = parts[0].strip()
                opts_new  = [o.strip() for o in parts[1].split(",") if o.strip()]
                if len(opts_new) < 2:
                    conn.sendall(b"ERROR: Need at least 2 options\n")
                    continue
                with lock:
                    poll_title   = title_new
                    options      = opts_new
                    votes        = {o: 0 for o in opts_new}
                    received_seqs.clear()
                    poll_open    = False
                conn.sendall(f"CREATED '{title_new}' with options {opts_new}\n".encode())

            elif cmd == "OPEN":
                with lock:
                    if not options:
                        conn.sendall(b"ERROR: No poll created yet\n")
                        continue
                    poll_open = True
                log(f"Poll OPENED: {poll_title}")
                conn.sendall(b"POLL OPEN\n")

            elif cmd == "CLOSE":
                with lock:
                    poll_open = False
                log("Poll CLOSED")
                conn.sendall(b"POLL CLOSED\n")

            elif cmd == "RESULTS":
                with lock:
                    payload = {
                        "title"        : poll_title,
                        "open"         : poll_open,
                        "votes"        : dict(votes),
                        "valid_votes"  : valid_votes,
                        "duplicates"   : duplicate_count,
                        "tampered"     : tampered_count,
                        "total_recv"   : total_received,
                        "loss_stats"   : {str(k): v for k, v in client_stats.items()},
                    }
                conn.sendall((json.dumps(payload, indent=2) + "\n").encode())

            elif cmd == "STATS":
                with lock:
                    total_lost = sum(v["lost"] for v in client_stats.values())
                    loss_rate  = (total_lost / (valid_votes + total_lost) * 100) if (valid_votes + total_lost) > 0 else 0.0
                    stat = {
                        "total_packets_received" : total_received,
                        "valid_votes"            : valid_votes,
                        "duplicates_rejected"    : duplicate_count,
                        "tampered_rejected"      : tampered_count,
                        "estimated_packets_lost" : total_lost,
                        "packet_loss_rate_pct"   : round(loss_rate, 2),
                        "active_clients"         : len(client_stats),
                    }
                conn.sendall((json.dumps(stat, indent=2) + "\n").encode())

            elif cmd == "RESET":
                with lock:
                    votes            = {o: 0 for o in options}
                    received_seqs.clear()
                    valid_votes      = 0
                    duplicate_count  = 0
                    tampered_count   = 0
                    total_received   = 0
                    client_stats.clear()
                    poll_open        = False
                conn.sendall(b"RESET OK\n")

            elif cmd in ("HELP", "?"):
                help_text = (
                    "Commands:\n"
                    "  CREATE <title>|<opt1>,<opt2>,...  Create a new poll\n"
                    "  OPEN                              Open voting\n"
                    "  CLOSE                             Close voting\n"
                    "  RESULTS                           Get current results (JSON)\n"
                    "  STATS                             Get packet/loss statistics\n"
                    "  RESET                             Reset vote counts\n"
                    "  QUIT                              Disconnect\n"
                )
                conn.sendall(help_text.encode())

            elif cmd in ("QUIT", "EXIT", "BYE"):
                conn.sendall(b"BYE\n")
                break

            else:
                conn.sendall(b"ERROR: Unknown command. Type HELP.\n")

    except Exception as e:
        log(f"Control client {addr} error: {e}")
    finally:
        conn.close()
        log(f"Control client disconnected: {addr}")


def tls_control_server():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_sock.bind((TLS_IP, TLS_PORT))
    raw_sock.listen(10)
    log(f"TLS control server listening on port {TLS_PORT}")

    with context.wrap_socket(raw_sock, server_side=True) as tls_sock:
        while True:
            try:
                conn, addr = tls_sock.accept()
                t = threading.Thread(target=handle_control_client, args=(conn, addr), daemon=True)
                t.start()
            except Exception as e:
                log(f"TLS accept error: {e}")


if __name__ == "__main__":
    log("=" * 55)
    log("  Live Polling & Voting System — SERVER STARTING")
    log("=" * 55)

    threads = [
        threading.Thread(target=udp_server,       daemon=True, name="UDP-Votes"),
        threading.Thread(target=tls_control_server, daemon=True, name="TLS-Control"),
        threading.Thread(target=broadcaster,       daemon=True, name="Broadcaster"),
    ]
    for t in threads:
        t.start()
        log(f"Thread started: {t.name}")

    log("Server running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log("Server shutting down.")
