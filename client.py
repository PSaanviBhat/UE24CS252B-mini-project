"""
  Live Polling & Voting System — CLIENT
  Socket Programming Mini Project 
  Features:
    - UDP socket for sending votes (custom HMAC-signed packet)
    - TLS/SSL TCP connection for receiving poll info & results
    - ACK/NACK handling with retry on packet loss
    - Sequence numbering per client
    - Background thread for broadcast result updates
    - CLI-based interactive interface
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
import sys

SERVER_IP      = "192.168.1.6"   
UDP_PORT       = 9999
TLS_PORT       = 9443
BROADCAST_PORT = 9997

SECRET_KEY = b"securekey_voting2025"

CERT_FILE  = "certs/server.crt"   

MAX_RETRIES  = 3
RECV_TIMEOUT = 3   # seconds to wait for ACK

#Packet Format 
# | 32 bytes HMAC-SHA256 | 4B client_id | 4B seq | 4B poll_id | 1B vote_option |
HMAC_LEN    = 32
PAYLOAD_FMT = "!IIIB"
PAYLOAD_SIZE = struct.calcsize(PAYLOAD_FMT)

client_id = os.getpid()   # unique per process
seq       = 0
poll_id   = 1             # updated when server announces a new poll

# Current poll info (updated via broadcast)
current_poll   = {"title": "—", "options": [], "open": False, "votes": {}}
poll_lock      = threading.Lock()


def create_vote_packet(cid, sq, pid, vote_option):
    payload   = struct.pack(PAYLOAD_FMT, cid, sq, pid, vote_option)
    mac       = hmac.new(SECRET_KEY, payload, hashlib.sha256).digest()
    return mac + payload


def send_vote(vote_option: int) -> bool:
    global seq
    seq += 1

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.settimeout(RECV_TIMEOUT)

    packet = create_vote_packet(client_id, seq, poll_id, vote_option)

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            udp_sock.sendto(packet, (SERVER_IP, UDP_PORT))
            response, _ = udp_sock.recvfrom(256)
            resp_str = response.decode(errors="ignore")

            if resp_str == "ACK":
                print(f"    Vote accepted (seq={seq})")
                udp_sock.close()
                return True
            elif resp_str.startswith("NACK:"):
                reason = resp_str[5:]
                print(f"    Vote rejected: {reason}")
                udp_sock.close()
                return False
        except socket.timeout:
            print(f"    Timeout on attempt {attempt}/{MAX_RETRIES}, retrying...")

    print("    Vote failed after max retries (possible packet loss)")
    udp_sock.close()
    return False


def broadcast_listener():
    """Listens for server result broadcasts and updates local state."""
    bsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        bsock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        bsock.bind(("", BROADCAST_PORT))
    except OSError as e:
        # Non-fatal: broadcast listen may not work everywhere
        print(f"[Broadcast listener]: {e} — live updates disabled")
        return

    while True:
        try:
            data, _ = bsock.recvfrom(4096)
            payload = json.loads(data.decode())
            if payload.get("type") == "broadcast":
                with poll_lock:
                    current_poll["title"] = payload.get("title", "—")
                    current_poll["open"]  = payload.get("open", False)
                    current_poll["votes"] = payload.get("votes", {})
        except Exception:
            pass


def get_tls_connection():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tls_conn = context.wrap_socket(raw)
    tls_conn.connect((SERVER_IP, TLS_PORT))
    return tls_conn


def tls_command(cmd: str) -> str:
    """Send a single command over TLS and return response."""
    try:
        conn = get_tls_connection()
        conn.recv(256)  # consume WELCOME banner
        conn.sendall((cmd + "\n").encode())
        resp = b""
        conn.settimeout(3)
        while True:
            try:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if resp.endswith(b"\n"):
                    break
            except socket.timeout:
                break
        conn.close()
        return resp.decode(errors="ignore").strip()
    except Exception as e:
        return f"ERROR: {e}"


def print_banner():
    print("\n" + "═" * 55)
    print("     Live Polling & Voting System — CLIENT")
    print("═" * 55)
    print(f"   Client ID : {client_id}")
    print(f"   Server    : {SERVER_IP}:{UDP_PORT} (UDP votes)")
    print(f"             : {SERVER_IP}:{TLS_PORT}  (TLS control)")
    print("═" * 55)


def show_menu():
    with poll_lock:
        title  = current_poll["title"]
        is_open = current_poll["open"]
        v_data = current_poll["votes"]

    status = " OPEN" if is_open else " CLOSED"
    print(f"\n  Poll : {title}  [{status}]")
    if v_data:
        total = sum(v_data.values()) or 1
        print("  Current results (from last broadcast):")
        for opt, cnt in v_data.items():
            bar = "█" * int(cnt / total * 20)
            print(f"    {opt:15s} {bar:20s} {cnt} votes")
    print()
    print("  [1-9] Cast vote for option number")
    print("  [r]   Fetch live results via TLS")
    print("  [s]   Fetch packet/loss statistics")
    print("  [p]   Fetch poll info")
    print("  [q]   Quit")
    print()


def interactive_mode():
    global poll_id

    print_banner()

    # Try to fetch current poll info
    print("  Connecting to server via TLS...")
    resp = tls_command("RESULTS")
    try:
        data = json.loads(resp)
        with poll_lock:
            current_poll["title"] = data.get("title", "—")
            current_poll["open"]  = data.get("open", False)
            current_poll["votes"] = data.get("votes", {})
            opts = list(data.get("votes", {}).keys())
            current_poll["options"] = opts
        print(f"  Connected! Poll: '{current_poll['title']}'")
    except Exception:
        print(f"  Could not fetch poll info: {resp}")

    while True:
        show_menu()
        choice = input("  > ").strip().lower()

        if choice == "q":
            print("  Goodbye!")
            sys.exit(0)

        elif choice == "r":
            print("\n  [TLS] Fetching results...")
            resp = tls_command("RESULTS")
            try:
                d = json.loads(resp)
                print(f"\n  Poll: {d['title']}  ({'OPEN' if d['open'] else 'CLOSED'})")
                print(f"  Valid votes   : {d['valid_votes']}")
                print(f"  Duplicates    : {d['duplicates']}")
                print(f"  Tampered pkts : {d['tampered']}")
                for opt, cnt in d.get("votes", {}).items():
                    print(f"    {opt}: {cnt}")
            except Exception:
                print(f"  {resp}")

        elif choice == "s":
            print("\n  [TLS] Fetching statistics...")
            resp = tls_command("STATS")
            try:
                s = json.loads(resp)
                print(f"\n  Total received : {s['total_packets_received']}")
                print(f"  Valid votes    : {s['valid_votes']}")
                print(f"  Duplicates     : {s['duplicates_rejected']}")
                print(f"  Tampered       : {s['tampered_rejected']}")
                print(f"  Est. lost pkts : {s['estimated_packets_lost']}")
                print(f"  Loss rate      : {s['packet_loss_rate_pct']}%")
                print(f"  Active clients : {s['active_clients']}")
            except Exception:
                print(f"  {resp}")

        elif choice == "p":
            resp = tls_command("RESULTS")
            try:
                d = json.loads(resp)
                with poll_lock:
                    current_poll["title"] = d.get("title", "—")
                    current_poll["open"]  = d.get("open", False)
                    current_poll["votes"] = d.get("votes", {})
                    current_poll["options"] = list(d.get("votes", {}).keys())
                print(f"  Poll refreshed: '{d['title']}'")
            except Exception:
                print(f"  {resp}")

        elif choice.isdigit():
            opt_num = int(choice)
            with poll_lock:
                opts = current_poll["options"] or list(current_poll["votes"].keys())
                is_open = current_poll["open"]

            if not is_open:
                print("    Poll is currently closed.")
                continue
            if opt_num < 1 or opt_num > len(opts):
                print(f"    Invalid option. Choose 1–{len(opts)}.")
                continue

            chosen_label = opts[opt_num - 1]
            print(f"  Sending vote for: '{chosen_label}' (option {opt_num})...")
            send_vote(opt_num)

        else:
            print("  Unknown command.")


if __name__ == "__main__":
    # Override server IP from CLI arg if provided
    if len(sys.argv) > 1:
        SERVER_IP = sys.argv[1]
        print(f"Using server IP: {SERVER_IP}")

    # Start broadcast listener in background
    t = threading.Thread(target=broadcast_listener, daemon=True, name="BroadcastListener")
    t.start()

    interactive_mode()
