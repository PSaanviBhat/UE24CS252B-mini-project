"""
  Live Polling & Voting System — PERFORMANCE TEST
  Socket Programming Mini Project
  Simulates N concurrent clients sending votes simultaneously.
  Measures:
    - Throughput (votes/sec)
    - Average response time (RTT)
    - ACK success rate
    - Packet loss rate
"""

import socket
import struct
import hashlib
import hmac
import threading
import time
import os
import random
import sys

SERVER_IP  = "192.168.1.6"
UDP_PORT   = 9999
SECRET_KEY = b"securekey_voting2025"

PAYLOAD_FMT = "!IIIB"
HMAC_LEN    = 32

NUM_CLIENTS   = int(sys.argv[1]) if len(sys.argv) > 1 else 5
VOTES_EACH    = int(sys.argv[2]) if len(sys.argv) > 2 else 10
MAX_OPTIONS   = 2
RECV_TIMEOUT  = 2


def create_vote_packet(cid, sq, vote_option):
    payload = struct.pack(PAYLOAD_FMT, cid, sq, 1, vote_option)
    mac     = hmac.new(SECRET_KEY, payload, hashlib.sha256).digest()
    return mac + payload


# Shared results
results_lock = threading.Lock()
all_rtts     = []
ack_count    = 0
nack_count   = 0
timeout_count= 0


def client_worker(client_idx):
    global ack_count, nack_count, timeout_count

    cid  = os.getpid() * 1000 + client_idx
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(RECV_TIMEOUT)
    local_rtts = []

    for seq in range(1, VOTES_EACH + 1):
        vote_option = random.randint(1, MAX_OPTIONS)
        pkt = create_vote_packet(cid, seq, vote_option)

        t0 = time.time()
        try:
            sock.sendto(pkt, (SERVER_IP, UDP_PORT))
            resp, _ = sock.recvfrom(256)
            rtt = (time.time() - t0) * 1000  # ms
            local_rtts.append(rtt)
            resp_str = resp.decode(errors="ignore")
            with results_lock:
                if resp_str == "ACK":
                    ack_count += 1
                else:
                    nack_count += 1
        except socket.timeout:
            with results_lock:
                timeout_count += 1

    sock.close()

    with results_lock:
        all_rtts.extend(local_rtts)

    print(f"  Client {client_idx:3d} done | avg RTT={sum(local_rtts)/len(local_rtts):.2f}ms"
          if local_rtts else f"  Client {client_idx:3d} done | no RTT data")


def main():
    print("=" * 55)
    print("  Performance Test: Voting System")
    print("=" * 55)
    print(f"  Concurrent clients : {NUM_CLIENTS}")
    print(f"  Votes per client   : {VOTES_EACH}")
    print(f"  Total vote packets : {NUM_CLIENTS * VOTES_EACH}")
    print("=" * 55)
    print("  Starting threads...\n")

    threads = [threading.Thread(target=client_worker, args=(i,)) for i in range(NUM_CLIENTS)]

    t_start = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.time() - t_start

    total      = NUM_CLIENTS * VOTES_EACH
    throughput = total / elapsed if elapsed > 0 else 0
    avg_rtt    = sum(all_rtts) / len(all_rtts) if all_rtts else 0
    min_rtt    = min(all_rtts) if all_rtts else 0
    max_rtt    = max(all_rtts) if all_rtts else 0
    loss_rate  = timeout_count / total * 100 if total else 0

    print("\n" + "=" * 55)
    print("  RESULTS")
    print("=" * 55)
    print(f"  Elapsed time      : {elapsed:.3f}s")
    print(f"  Throughput        : {throughput:.1f} votes/sec")
    print(f"  ACKs received     : {ack_count}")
    print(f"  NACKs received    : {nack_count}")
    print(f"  Timeouts (lost)   : {timeout_count}")
    print(f"  Packet loss rate  : {loss_rate:.2f}%")
    print(f"  Avg RTT           : {avg_rtt:.2f} ms")
    print(f"  Min RTT           : {min_rtt:.2f} ms")
    print(f"  Max RTT           : {max_rtt:.2f} ms")
    print("=" * 55)


if __name__ == "__main__":
    main()
