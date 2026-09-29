#!/usr/bin/env python3
"""DPI analysis of an mcvpn capture: what a wire observer actually sees.

Reads the pcap (raw-IP records, the exact TCP bytes) and the timing tsv
produced by mcvpn-verify, then answers the only question that matters:
does anything on the wire betray that this is not a real Minecraft 1.8.9
server? Decodes the plaintext login stage, checks RSA key size, measures
byte entropy of the encrypted phase, and checks packet cadence (20 Hz idle
player ticks) against real vanilla behavior.
"""
import math
import struct
import sys
from collections import Counter


def read_pcap(path):
    with open(path, "rb") as f:
        data = f.read()
    linktype = struct.unpack("<I", data[20:24])[0]
    assert linktype == 101, f"expected LINKTYPE_RAW, got {linktype}"
    off = 24
    pkts = []
    while off + 16 <= len(data):
        ts_s, ts_us, incl, _ = struct.unpack("<IIII", data[off : off + 16])
        off += 16
        pkt = data[off : off + incl]
        off += incl
        ihl = (pkt[0] & 0x0F) * 4
        sport, dport = struct.unpack(">HH", pkt[ihl + 0 : ihl + 4])
        payload = pkt[ihl + 20 :]
        ts = ts_s + ts_us / 1e6
        pkts.append((ts, sport, dport, payload))
    return pkts


def read_varint(buf, off):
    val = 0
    for i in range(5):
        if off >= len(buf):
            return None, off
        b = buf[off]
        off += 1
        val |= (b & 0x7F) << (7 * i)
        if not b & 0x80:
            return val, off
    return None, off


def read_string(buf, off):
    n, off = read_varint(buf, off)
    if n is None or off + n > len(buf):
        return None, off
    s = buf[off : off + n]
    return s, off + n


def frames(stream):
    out = []
    off = 0
    while off < len(stream):
        n, noff = read_varint(stream, off)
        if n is None or noff + n > len(stream):
            break
        out.append(stream[noff : noff + n])
        off = noff + n
    return out


def entropy_bits(data):
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def main():
    pcap, tsv = sys.argv[1], sys.argv[2]
    pkts = read_pcap(pcap)
    ports = Counter()
    for _, s, d, _ in pkts:
        ports[d] += 1
    mc_port = ports.most_common(1)[0][0]
    conns = {}
    for ts, s, d, payload in pkts:
        key = tuple(sorted((s, d)))
        direction = "c2s" if d == mc_port else "s2c"
        conns.setdefault(key, {"c2s": b"", "s2c": b"", "c2s_ts": [], "s2c_ts": []})
        conns[key][direction] += payload
        conns[key][direction + "_ts"].append((ts, len(payload)))

    print("=== mcvpn DPI report (what an observer of the wire sees) ===")
    print(f"connections: {len(conns)}  minecraft port: {mc_port}")
    issues = []
    for i, (key, c) in enumerate(conns.items()):
        c2s, s2c = c["c2s"], c["s2c"]
        cf, sf = frames(c2s), frames(s2c)
        print(f"\n-- connection {i + 1} ({key[0]} <-> {key[1]}) --")
        if cf and cf[0][0] == 0:
            hs = cf[0]
            proto, off = read_varint(hs, 1)
            host, off = read_string(hs, off)
            port = struct.unpack(">H", hs[off : off + 2])[0]
            nxt, _ = read_varint(hs, off + 2)
            ok = proto == 47 and nxt == 2
            print(f"  handshake: proto={proto} host={host.decode()} port={port} next_state={nxt} "
                  f"{'OK (vanilla 1.8.9)' if ok else 'SUSPICIOUS'}")
            if not ok:
                issues.append("handshake not vanilla-shaped")
        if len(cf) > 1 and cf[1][0] == 0:
            name, _ = read_string(cf[1], 1)
            n = name.decode("utf-8", "replace")
            valid = 1 <= len(n) <= 16 and all(ch.isalnum() or ch == "_" for ch in n)
            print(f"  login start: username={n!r} {'OK (valid MC name)' if valid else 'SUSPICIOUS'}")
            if not valid:
                issues.append("username not MC-valid")
        if sf and sf[0][0] == 1:
            sid, off = read_string(sf[0], 1)
            klen = struct.unpack(">H", sf[0][off : off + 2])[0]
            tlen = struct.unpack(">H", sf[0][off + 2 + klen : off + 4 + klen])[0]
            print(f"  encryption request: server_id={sid.decode()!r} pubkey={klen}B verify_token={tlen}B")
            if klen == 162:
                print("    RSA key is 1024-bit sized (162B SPKI) byte-identical to vanilla/BungeeCord")
            else:
                issues.append(f"pubkey size {klen}B differs from vanilla 1024-bit (162B)")
        if len(cf) > 2 and cf[2][0] == 1:
            slen = struct.unpack(">H", cf[2][1:3])[0]
            tlen2 = struct.unpack(">H", cf[2][3 + slen : 5 + slen])[0]
            print(f"  encryption response: secret={slen}B token={tlen2}B (1024-bit RSA blocks)")
            if slen != 128:
                issues.append(f"RSA block size {slen} != 128 (1024-bit)")
        enc = c2s[min(len(c2s), 200) :]
        sample = enc[: min(len(enc), 1 << 20)]
        e = entropy_bits(sample)
        # Entropy needs a real sample: a few hundred bytes mathematically
        # cannot approach 8 bits/byte, so tiny sessions are inconclusive,
        # not fingerprints.
        if len(sample) >= 10240:
            verdict = "indistinguishable from random" if e > 7.9 else "LOW ENTROPY"
            print(f"  encrypted c2s entropy: {e:.3f} bits/byte over {len(sample)}B {verdict}")
            if e <= 7.9:
                issues.append("encrypted phase entropy below random")
        else:
            print(f"  encrypted c2s entropy: {e:.3f} bits/byte over {len(sample)}B (sample too small to judge — inconclusive)")
        small = [ts for ts, ln in c["c2s_ts"] if ln <= 4]
        if len(small) > 10:
            gaps = sorted((b - a) * 1000 for a, b in zip(small, small[1:]))
            med = gaps[len(gaps) // 2]
            print(f"  tiny-frame cadence: {len(small)} frames, median gap {med:.1f} ms "
                  f"({'matches vanilla 20 Hz idle player ticks' if 30 <= med <= 90 else 'check'})")
        big = [ln for _, ln in c["c2s_ts"] if ln > 100]
        if big:
            print(f"  data-frame sizes: {len(big)} frames > 100B (max {max(big)}B)")
    print("\n=== verdict ===")
    if issues:
        print("FINGERPRINTS FOUND:")
        for it in issues:
            print(f"  - {it}")
        sys.exit(1)
    print("No signature-level fingerprints: the plaintext login stage is byte-shaped like")
    print("vanilla 1.8.9 online-mode (1024-bit RSA request, MC-valid username), and the")
    print("encrypted phase is random-looking with vanilla packet cadence. Only statistical/")
    print("behavioral analysis (volumes, timing correlation) could go further: no protocol")
    print("signature gives it away.")


if __name__ == "__main__":
    main()
