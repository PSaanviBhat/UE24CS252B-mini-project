"""
  Live Polling & Voting System — ADMIN CONTROL CLIENT
  Socket Programming Mini Project 
  Admin tool for:
    - Creating polls
    - Opening / closing polls
    - Viewing live results and statistics
    - Resetting data
"""

import socket
import ssl
import sys
import json
import os
import time

SERVER_IP = "192.168.1.6"   
TLS_PORT  = 9443
CERT_FILE = "certs/server.crt"


def get_connection():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tls = ctx.wrap_socket(raw)
    tls.connect((SERVER_IP, TLS_PORT))
    return tls


def send_cmd(conn, cmd):
    conn.sendall((cmd + "\n").encode())
    resp = b""
    conn.settimeout(4)
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
    return resp.decode(errors="ignore").strip()


def print_banner():
    print("\n" + "═" * 55)
    print("   🛠  Voting System — ADMIN CONTROL")
    print("═" * 55)
    print(f"   Server: {SERVER_IP}:{TLS_PORT} (TLS)")
    print("═" * 55 + "\n")


def print_help():
    print("""
Commands:
  create   — Create a new poll (guided)
  open     — Open voting on current poll
  close    — Close voting
  results  — Show live results
  stats    — Show packet/loss statistics
  reset    — Reset all vote counts
  raw      — Send a raw command to server
  help     — Show this help
  exit     — Quit
""")


def guided_create(conn):
    title = input("Poll title: ").strip()
    if not title:
        print("Aborted.")
        return
    opts_raw = input("Options (comma-separated, e.g. 'Option A,Option B'): ").strip()
    if not opts_raw:
        print("Aborted.")
        return
    cmd = f"CREATE {title}|{opts_raw}"
    resp = send_cmd(conn, cmd)
    print(f"Server: {resp}")


def show_results(conn):
    resp = send_cmd(conn, "RESULTS")
    try:
        d = json.loads(resp)
        print(f"\n  Poll : {d['title']}  [{'OPEN' if d['open'] else 'CLOSED'}]")
        print(f"  Valid votes    : {d['valid_votes']}")
        print(f"  Duplicates     : {d['duplicates']}")
        print(f"  Tampered pkts  : {d['tampered']}")
        print(f"  Total received : {d['total_recv']}")
        print("\n  Results:")
        total = sum(d["votes"].values()) or 1
        for opt, cnt in d["votes"].items():
            pct = cnt / total * 100
            bar = "█" * int(pct / 5)
            print(f"    {opt:20s} {bar:20s} {cnt:4d} ({pct:.1f}%)")
        if d.get("loss_stats"):
            print("\n  Per-client loss stats:")
            for cid, s in d["loss_stats"].items():
                print(f"    client {cid}: last_seq={s['last_seq']} lost={s['lost']}")
    except Exception:
        print(f"  {resp}")


def show_stats(conn):
    resp = send_cmd(conn, "STATS")
    try:
        s = json.loads(resp)
        print(f"\n  Total received : {s['total_packets_received']}")
        print(f"  Valid votes    : {s['valid_votes']}")
        print(f"  Duplicates rej : {s['duplicates_rejected']}")
        print(f"  Tampered rej   : {s['tampered_rejected']}")
        print(f"  Est. lost pkts : {s['estimated_packets_lost']}")
        print(f"  Loss rate      : {s['packet_loss_rate_pct']}%")
        print(f"  Active clients : {s['active_clients']}")
    except Exception:
        print(f"  {resp}")


def main():
    global SERVER_IP
    if len(sys.argv) > 1:
        SERVER_IP = sys.argv[1]

    print_banner()

    try:
        conn = get_connection()
        banner = conn.recv(256).decode(errors="ignore").strip()
        print(f"Connected → {banner}\n")
    except Exception as e:
        print(f"Cannot connect to server: {e}")
        sys.exit(1)

    print_help()

    while True:
        try:
            cmd = input("admin> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if cmd in ("exit", "quit", "q"):
            send_cmd(conn, "QUIT")
            break
        elif cmd == "help":
            print_help()
        elif cmd == "create":
            guided_create(conn)
        elif cmd == "open":
            resp = send_cmd(conn, "OPEN")
            print(f"Server: {resp}")
        elif cmd == "close":
            resp = send_cmd(conn, "CLOSE")
            print(f"Server: {resp}")
        elif cmd == "results":
            show_results(conn)
        elif cmd == "stats":
            show_stats(conn)
        elif cmd == "reset":
            confirm = input("Reset all vote data? (yes/no): ").strip().lower()
            if confirm == "yes":
                resp = send_cmd(conn, "RESET")
                print(f"Server: {resp}")
            else:
                print("Aborted.")
        elif cmd == "raw":
            raw_cmd = input("Raw command: ").strip()
            resp = send_cmd(conn, raw_cmd)
            print(f"Server: {resp}")
        else:
            print("Unknown command. Type 'help'.")

    conn.close()


if __name__ == "__main__":
    main()
