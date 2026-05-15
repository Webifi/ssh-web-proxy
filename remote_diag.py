#!/usr/bin/env python3
"""ssh-web-proxy remote diagnostic runner.

Invoked as: python3 - <json_config_arg>
Reads its own source from stdin. Runs ping/TCP/SNMP checks in parallel,
prints results as a single-line JSON blob on stdout, exits 0 on
success. Any uncaught exception → traceback to stderr, exit 1.

Pure stdlib. Tested on Python 3.5+ (Ubuntu 16.04 ships 3.5 — works).
"""
import json
import socket
import subprocess
import sys
import threading
import time


# ─── BER / SNMP helpers (copied verbatim from printer_manager) ──────
def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return bytes([0x81, n])
    else:
        return bytes([0x82, (n >> 8) & 0xff, n & 0xff])


def _tlv(tag, value):
    if isinstance(value, str):
        value = value.encode()
    elif isinstance(value, int):
        if value == 0:
            value = b"\x00"
        else:
            length = (value.bit_length() + 8) // 8
            value = value.to_bytes(length, "big")
    return bytes([tag]) + _ber_len(len(value)) + value


def _encode_oid(oid_str):
    parts = list(map(int, oid_str.split(".")))
    out = [40 * parts[0] + parts[1]]
    for p in parts[2:]:
        if p == 0:
            out.append(0)
        else:
            enc = []
            while p:
                enc.append(p & 0x7f)
                p >>= 7
            enc.reverse()
            for i, b in enumerate(enc):
                out.append(b | (0x80 if i < len(enc) - 1 else 0))
    return bytes(out)


def _read_len(data, pos):
    b = data[pos]; pos += 1
    if b < 0x80:
        return b, pos
    nb = b & 0x7f
    n = int.from_bytes(data[pos:pos + nb], "big")
    return n, pos + nb


def _parse_value(tag, data):
    if tag == 0x02:  # INTEGER
        return {"type": "INTEGER", "value": int.from_bytes(data, "big", signed=True)}
    if tag == 0x04:  # OCTET STRING — try text, fall back to hex
        try:
            text = data.decode("utf-8", errors="replace").strip("\x00")
            # Only treat as text if it looks printable
            if all(c == "\t" or c == "\n" or 32 <= ord(c) < 127 for c in text):
                return {"type": "OCTET STRING", "value": text,
                        "hex": data.hex()}
        except (UnicodeDecodeError, AttributeError):
            pass
        return {"type": "OCTET STRING", "value": data.hex(),
                "hex": data.hex(), "binary": True}
    if tag == 0x06:  # OID
        if len(data) < 1:
            return {"type": "OID", "value": ""}
        parts = [str(data[0] // 40), str(data[0] % 40)]
        val = 0
        for b in data[1:]:
            val = (val << 7) | (b & 0x7f)
            if not (b & 0x80):
                parts.append(str(val)); val = 0
        return {"type": "OID", "value": ".".join(parts)}
    if tag == 0x40:  # IpAddress
        return {"type": "IpAddress", "value": ".".join(str(b) for b in data)}
    if tag == 0x41:  # Counter32
        return {"type": "Counter32", "value": int.from_bytes(data, "big")}
    if tag == 0x42:  # Gauge32
        return {"type": "Gauge32", "value": int.from_bytes(data, "big")}
    if tag == 0x43:  # TimeTicks
        ticks = int.from_bytes(data, "big")
        return {"type": "TimeTicks", "value": ticks,
                "seconds": ticks / 100.0}
    if tag == 0x46:  # Counter64
        return {"type": "Counter64", "value": int.from_bytes(data, "big")}
    if tag == 0x80:
        return {"type": "noSuchObject", "value": None}
    if tag == 0x81:
        return {"type": "noSuchInstance", "value": None}
    if tag == 0x82:
        return {"type": "endOfMibView", "value": None}
    return {"type": "UNKNOWN(0x%02x)" % tag, "value": data.hex()}


def _build_snmp_get(community, oid_str, req_id=1, version=0):
    oid_bytes = _encode_oid(oid_str)
    varbind = _tlv(0x30, _tlv(0x06, oid_bytes) + bytes([0x05, 0x00]))
    pdu = _tlv(0xa0,
               _tlv(0x02, req_id)
               + bytes([0x02, 0x01, 0x00, 0x02, 0x01, 0x00])
               + _tlv(0x30, varbind))
    return _tlv(0x30, _tlv(0x02, version) + _tlv(0x04, community) + pdu)


ERR_STATUS_NAMES = {
    0: "noError", 1: "tooBig", 2: "noSuchName",
    3: "badValue", 4: "readOnly", 5: "genErr",
}


def _parse_snmp_response(data):
    """Return parsed varbind value dict, or None if the packet shape
    doesn't match (exotic agents sometimes diverge from RFC 1157)."""
    try:
        pos = 0
        assert data[pos] == 0x30; pos += 1
        _, pos = _read_len(data, pos)
        assert data[pos] == 0x02; pos += 1
        vlen, pos = _read_len(data, pos); pos += vlen
        assert data[pos] == 0x04; pos += 1
        clen, pos = _read_len(data, pos); pos += clen
        assert data[pos] == 0xa2; pos += 1
        _, pos = _read_len(data, pos)
        assert data[pos] == 0x02; pos += 1
        rlen, pos = _read_len(data, pos); pos += rlen
        assert data[pos] == 0x02; pos += 1
        _, pos = _read_len(data, pos)
        err = data[pos]; pos += 1
        if err != 0:
            # v1 PDU-level error. Translate the code so the UI shows
            # "noSuchName" instead of "2".
            return {
                "type": "ErrorStatus",
                "value": ERR_STATUS_NAMES.get(err, "unknown(%d)" % err),
                "error_code": err,
            }
        assert data[pos] == 0x02; pos += 1
        elen, pos = _read_len(data, pos); pos += elen
        assert data[pos] == 0x30; pos += 1
        _, pos = _read_len(data, pos)
        assert data[pos] == 0x30; pos += 1
        _, pos = _read_len(data, pos)
        assert data[pos] == 0x06; pos += 1
        olen, pos = _read_len(data, pos); pos += olen
        vtag = data[pos]; pos += 1
        vlen, pos = _read_len(data, pos)
        return _parse_value(vtag, data[pos:pos + vlen])
    except (AssertionError, IndexError, ValueError):
        return None


def snmp_get(host, oid, community, timeout):
    """Try SNMPv1, then v2c. Returns parsed-value dict or None.
    Order matters: receipt printers tend to speak v1 better than v2c."""
    for version in (0, 1):
        try:
            pkt = _build_snmp_get(community, oid, version=version)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(pkt, (host, 161))
            data, _addr = s.recvfrom(4096)
            s.close()
            result = _parse_snmp_response(data)
            if result is not None:
                result["snmp_version"] = "v1" if version == 0 else "v2c"
                return result
        except (OSError, socket.timeout):
            try: s.close()
            except Exception: pass
            continue
    return None


# ─── OIDs we query (grouped for the results page) ───────────────────
OID_GROUPS = [
    ("identity", [
        ("sysDescr",     "1.3.6.1.2.1.1.1.0"),
        ("sysName",      "1.3.6.1.2.1.1.5.0"),
        ("sysLocation",  "1.3.6.1.2.1.1.6.0"),
        ("sysContact",   "1.3.6.1.2.1.1.4.0"),
        ("sysObjectID",  "1.3.6.1.2.1.1.2.0"),
        ("sysUpTime",    "1.3.6.1.2.1.1.3.0"),
    ]),
    ("interface", [
        ("ifPhysAddress", "1.3.6.1.2.1.2.2.1.6.1"),
        ("ifOperStatus",  "1.3.6.1.2.1.2.2.1.8.1"),
        ("ifSpeed",       "1.3.6.1.2.1.2.2.1.5.1"),
    ]),
    ("device", [
        # hrDeviceType.1 — tells us "is this advertising as a printer
        # or a generic IO device" (i.e. dumb print server adapter).
        ("hrDeviceType",      "1.3.6.1.2.1.25.3.2.1.2.1"),
        ("hrDeviceDescr",     "1.3.6.1.2.1.25.3.2.1.3.1"),
        ("hrDeviceStatus",    "1.3.6.1.2.1.25.3.2.1.5.1"),
    ]),
    ("printer_status", [
        # Cosmetic per fleet experience (NEVER use as a decision signal).
        ("hrPrinterStatus",        "1.3.6.1.2.1.25.3.5.1.1.1"),
        # Raw OCTET STRING bitfield — bit assignments below.
        ("hrPrinterErrorState",    "1.3.6.1.2.1.25.3.5.1.2.1"),
        ("prtCoverStatus",         "1.3.6.1.2.1.43.6.1.1.3.1.1"),
    ]),
    ("printer_identity", [
        ("prtGeneralPrinterName",  "1.3.6.1.2.1.43.5.1.1.16.1"),
        ("prtGeneralSerialNumber", "1.3.6.1.2.1.43.5.1.1.17.1"),
    ]),
    ("supplies_counters", [
        # These are the ones most likely to come back as noSuchObject
        # on receipt printers and on cheap print servers.
        ("prtMarkerLifeCount",     "1.3.6.1.2.1.43.10.2.1.4.1.1"),
        ("prtMarkerSuppliesLevel", "1.3.6.1.2.1.43.11.1.1.9.1.1"),
        ("prtInputCurrentLevel",   "1.3.6.1.2.1.43.8.2.1.10.1.1"),
    ]),
]

ERROR_BITS = [
    "lowPaper", "noPaper", "lowToner", "noToner", "doorOpen",
    "jammed", "offline", "serviceRequested", "inputTrayMissing",
    "outputTrayMissing", "markerSupplyMissing", "outputNearFull",
    "outputFull", "inputTrayEmpty", "overduePreventMaint",
]

VENDOR_OID_PREFIXES = {
    "1.3.6.1.4.1.1248":  "Epson",
    "1.3.6.1.4.1.11":    "HP",
    "1.3.6.1.4.1.2435":  "Brother",
    "1.3.6.1.4.1.367":   "Ricoh",
    "1.3.6.1.4.1.18334": "Star Micronics",
    "1.3.6.1.4.1.3232":  "Bixolon",
    "1.3.6.1.4.1.38446": "Bixolon",
    "1.3.6.1.4.1.17224": "Citizen",
    "1.3.6.1.4.1.1602":  "Canon",
    "1.3.6.1.4.1.253":   "Xerox",
    "1.3.6.1.4.1.641":   "Lexmark",
    "1.3.6.1.4.1.2001":  "OKI",
    "1.3.6.1.4.1.1347":  "Kyocera",
    "1.3.6.1.4.1.2590":  "Zebra",
    "1.3.6.1.4.1.10642": "Zebra",
    "1.3.6.1.4.1.6334":  "SNBC",
    "1.3.6.1.4.1.26513": "HPRT",
    # Print-server adapter chipsets (separate from printer brands —
    # if the OID matches one of these, the responder is a print server,
    # NOT the attached USB printer)
    "1.3.6.1.4.1.20111": "Silex (print server)",
    "1.3.6.1.4.1.244":   "Lantronix (print server)",
    "1.3.6.1.4.1.10888": "Realtek (likely cheap print server)",
    "1.3.6.1.4.1.11863": "TP-Link (print server)",
    "1.3.6.1.4.1.171":   "D-Link (print server)",
    "1.3.6.1.4.1.10056": "Edimax (print server)",
    "1.3.6.1.4.1.4651":  "ATEN (print server)",
}


# ─── Check 1: ping ──────────────────────────────────────────────────
def check_ping(host, timeout_s):
    start = time.monotonic()
    try:
        proc = subprocess.run(
            ["ping", "-c", "1", "-W", str(max(1, int(timeout_s))), host],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout_s + 2,
        )
        elapsed_ms = int((time.monotonic() - start) * 1000)
        stdout = proc.stdout.decode("utf-8", "replace")
        stderr = proc.stderr.decode("utf-8", "replace")
        rtt_ms = None
        for line in stdout.splitlines():
            if "time=" in line:
                try:
                    rtt_ms = float(line.split("time=", 1)[1].split()[0])
                except (IndexError, ValueError):
                    pass
                break
        if proc.returncode == 0:
            return {"ok": True, "rtt_ms": rtt_ms, "elapsed_ms": elapsed_ms,
                    "stdout": stdout.strip()}
        return {"ok": False, "elapsed_ms": elapsed_ms,
                "error": (stderr.strip() or stdout.strip()
                          or "ping returned %d" % proc.returncode),
                "stdout": stdout.strip()}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "ping subprocess timeout",
                "elapsed_ms": int(timeout_s * 1000)}
    except FileNotFoundError:
        return {"ok": False, "error": "ping command not available on remote"}
    except Exception as e:
        return {"ok": False,
                "error": "%s: %s" % (type(e).__name__, e),
                "elapsed_ms": int((time.monotonic() - start) * 1000)}


# ─── Check 2: TCP 9100 ──────────────────────────────────────────────
def check_tcp(host, port, timeout_s):
    start = time.monotonic()
    try:
        sock = socket.create_connection((host, port), timeout=timeout_s)
        elapsed_ms = int((time.monotonic() - start) * 1000)
        sock.close()
        return {"ok": True, "port": port, "elapsed_ms": elapsed_ms}
    except ConnectionRefusedError:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {"ok": False, "port": port,
                "error": "connection refused", "elapsed_ms": elapsed_ms}
    except socket.timeout:
        return {"ok": False, "port": port, "error": "timeout",
                "elapsed_ms": int(timeout_s * 1000)}
    except OSError as e:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {"ok": False, "port": port,
                "error": "%s: %s" % (type(e).__name__, e),
                "elapsed_ms": elapsed_ms}


# ─── Check 3: SNMP ──────────────────────────────────────────────────
def check_snmp(host, community, timeout_s):
    start = time.monotonic()
    per_oid_timeout = max(0.4, timeout_s / 16.0)
    answers = {}      # name -> {oid, group, ...result}
    any_answer = False
    versions_seen = set()

    for group_name, group_oids in OID_GROUPS:
        for name, oid in group_oids:
            if time.monotonic() - start > timeout_s:
                answers[name] = {"oid": oid, "group": group_name,
                                 "value": None, "type": None,
                                 "error": "overall SNMP budget exceeded"}
                continue
            result = snmp_get(host, oid, community, per_oid_timeout)
            entry = {"oid": oid, "group": group_name}
            if result is None:
                entry["value"] = None
                entry["type"] = None
                entry["error"] = "no response"
            else:
                any_answer = True
                entry["value"] = result.get("value")
                entry["type"] = result.get("type")
                entry["snmp_version"] = result.get("snmp_version")
                if result.get("hex"):
                    entry["hex"] = result["hex"]
                if result.get("binary"):
                    entry["binary"] = True
                if result.get("seconds") is not None:
                    entry["seconds"] = result["seconds"]
                if result.get("snmp_version"):
                    versions_seen.add(result["snmp_version"])
            answers[name] = entry

    # Decode hrPrinterErrorState bitfield (if we got bytes back)
    error_bits = []
    err_entry = answers.get("hrPrinterErrorState") or {}
    err_hex = err_entry.get("hex")
    if err_hex:
        try:
            err_bytes = bytes.fromhex(err_hex)
            for bi, byte_ in enumerate(err_bytes):
                for bit in range(8):
                    if byte_ & (0x80 >> bit):
                        idx = bi * 8 + bit
                        if idx < len(ERROR_BITS):
                            error_bits.append(ERROR_BITS[idx])
        except ValueError:
            pass

    # Identify vendor from sysObjectID prefix
    vendor = None
    sysoid_entry = answers.get("sysObjectID") or {}
    sysoid = sysoid_entry.get("value") if sysoid_entry.get("type") == "OID" else None
    if sysoid:
        for prefix, name in VENDOR_OID_PREFIXES.items():
            if sysoid == prefix or sysoid.startswith(prefix + "."):
                vendor = name
                break

    # Classify what kind of agent we're talking to. "Answered" here
    # means we got a USEFUL value back, NOT just an SNMP exception
    # (noSuchObject / noSuchInstance / ErrorStatus).
    EXCEPTION_TYPES = {"ErrorStatus", "noSuchObject", "noSuchInstance",
                       "endOfMibView"}

    def _is_real_answer(entry):
        if not entry: return False
        if entry.get("value") is None: return False
        if entry.get("type") in EXCEPTION_TYPES: return False
        return True

    dev_type_entry = answers.get("hrDeviceType") or {}
    dev_type_oid = (
        dev_type_entry.get("value")
        if dev_type_entry.get("type") == "OID" else None
    )
    has_printer_mib_data = any(
        _is_real_answer(answers.get(k))
        for k in ("prtGeneralPrinterName", "prtMarkerLifeCount",
                  "hrPrinterStatus")
    )
    has_basic_mib = _is_real_answer(answers.get("sysDescr"))

    if dev_type_oid == "1.3.6.1.2.1.25.3.1.5":
        classification = "printer (Printer-MIB aware)"
    elif has_printer_mib_data:
        classification = "printer (partial Printer-MIB)"
    elif has_basic_mib:
        # Could be a basic SNMP agent on a printer's built-in NIC, or
        # a thin Ethernet→USB print-server adapter. SNMP alone can't
        # distinguish — both look the same from this side.
        classification = "responsive (MIB-II only, no Printer-MIB)"
    else:
        classification = "unresponsive"

    # ── Decoded POS-relevant status ────────────────────────────────
    # Translation logic + vocabulary mirror
    # printer_manager.protocols.snmp.snmp_health() so the two stay
    # consistent (operators looking at this diag and at the manager
    # UI see the same labels for the same conditions). Key points
    # reused from the fleet-proven implementation there:
    #
    #   - Paper bits in hrPrinterErrorState are trustworthy when the
    #     OID returns at all. Absence of bits = paper "ok" (RFC 3805).
    #     printer-manager's paper vocab: empty / near_end / ok / None.
    #   - prtCoverStatus is the primary cover source; the doorOpen
    #     bit in hrPrinterErrorState supplements it (some firmwares
    #     only expose one). Either indicating open = open.
    #   - Overall status uses printer-manager's hierarchy:
    #     cover_open → offline → error → online → unknown.
    #     Cover-open is its own state because it's the single most
    #     operator-actionable condition.
    #   - hrPrinterStatus (idle/printing/warmup) is unreliable —
    #     surfaced as `firmware_reports` for display only, NEVER as a
    #     decision signal. See HR_STATUS_COSMETIC docstring in
    #     printer-manager/protocols/snmp.py.
    err_responded = _is_real_answer(answers.get("hrPrinterErrorState"))

    paper = None
    if err_responded:
        if "noPaper" in error_bits:
            paper = "empty"
        elif "lowPaper" in error_bits:
            paper = "near_end"   # printer-manager vocabulary
        else:
            paper = "ok"

    cover = None
    cov_entry = answers.get("prtCoverStatus") or {}
    cov_val = cov_entry.get("value")
    if _is_real_answer(cov_entry) and cov_entry.get("type") == "INTEGER":
        try:
            cv = int(cov_val)
            # RFC 3805 prtCoverStatus: 3=open 4=closed
            #                          5=interlockOpen 6=interlockClosed
            if cv in (3, 5):
                cover = "open"
            elif cv in (4, 6):
                cover = "closed"
        except (ValueError, TypeError):
            pass
    # doorOpen bit in hrPrinterErrorState supplements / overrides.
    if cover is None and err_responded:
        cover = "open" if "doorOpen" in error_bits else "closed"
    elif cover != "open" and "doorOpen" in error_bits:
        cover = "open"

    # hrDeviceStatus 5 = down
    device_down = False
    dev_status_entry = answers.get("hrDeviceStatus") or {}
    if (_is_real_answer(dev_status_entry)
            and dev_status_entry.get("type") == "INTEGER"):
        try:
            if int(dev_status_entry.get("value")) == 5:
                device_down = True
        except (ValueError, TypeError):
            pass

    # Cosmetic hrPrinterStatus mapping — never decision-making.
    # Names match printer-manager's HR_STATUS_COSMETIC verbatim.
    HR_STATUS_COSMETIC = {
        1: "other", 2: "unknown", 3: "idle", 4: "printing",
        5: "warmup", 7: "stopped",
    }
    firmware_reports = None
    status_int = None
    ps_entry = answers.get("hrPrinterStatus") or {}
    if _is_real_answer(ps_entry) and ps_entry.get("type") == "INTEGER":
        try:
            status_int = int(ps_entry.get("value"))
            firmware_reports = HR_STATUS_COSMETIC.get(
                status_int, "code=%d" % status_int,
            )
        except (ValueError, TypeError):
            pass

    # Overall status — printer-manager hierarchy, in this exact order.
    # cover_open is its own state because it's the most actionable.
    if cover == "open":
        status = "cover_open"
    elif device_down or "offline" in error_bits:
        status = "offline"
    elif error_bits:
        # Any other bit set in hrPrinterErrorState = generic error.
        # The raw bit list is surfaced separately so the operator can
        # see exactly which ones.
        status = "error"
    elif err_responded or _is_real_answer(answers.get("hrPrinterStatus")):
        status = "online"
    elif has_basic_mib:
        status = "responsive_no_status"
    else:
        status = "unknown"

    decoded = {
        "status":           status,
        "status_int":       status_int,
        "paper":            paper,
        "cover":            cover,
        "device_down":      device_down,
        # Raw RFC 3805 bit names from hrPrinterErrorState. Same shape
        # as printer-manager's `errors` field. The UI can show these
        # alongside the translated status.
        "errors":           list(error_bits),
        "firmware_reports": firmware_reports,
    }

    return {
        "ok": any_answer,
        "elapsed_ms": int((time.monotonic() - start) * 1000),
        "snmp_versions": sorted(versions_seen) or None,
        "vendor_from_sysoid": vendor,
        "classification": classification,
        "error_bits": error_bits,
        "decoded": decoded,
        "answers": answers,
        "error": (None if any_answer
                  else "no SNMP response on any OID at v1 or v2c"),
    }


# ─── Parallel runner + main ─────────────────────────────────────────
def run_parallel(target, community, ping_to, tcp_to, snmp_to):
    results = {}
    def runner(name, fn, *args):
        try:
            results[name] = fn(*args)
        except Exception as e:
            import traceback as _tb
            results[name] = {
                "ok": False,
                "error": "%s: %s" % (type(e).__name__, e),
                "traceback": _tb.format_exc(),
            }
    threads = [
        threading.Thread(target=runner, args=("ping", check_ping, target, ping_to)),
        threading.Thread(target=runner, args=("tcp9100", check_tcp, target, 9100, tcp_to)),
        threading.Thread(target=runner, args=("snmp", check_snmp, target, community, snmp_to)),
    ]
    overall_start = time.monotonic()
    for t in threads: t.start()
    for t in threads: t.join()
    results["__elapsed_ms"] = int((time.monotonic() - overall_start) * 1000)
    results["__python_version"] = sys.version.split()[0]
    return results


def main():
    try:
        cfg = json.loads(sys.argv[1])
    except (IndexError, ValueError) as e:
        sys.stderr.write("bad config arg: %s\n" % e)
        return 2
    target    = cfg["target"]
    community = cfg.get("community", "public")
    ping_to   = float(cfg.get("ping_timeout", 2))
    tcp_to    = float(cfg.get("tcp_timeout", 5))
    snmp_to   = float(cfg.get("snmp_timeout", 5))
    results = run_parallel(target, community, ping_to, tcp_to, snmp_to)
    sys.stdout.write(json.dumps(results))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)
