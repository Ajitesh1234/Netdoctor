
def interpret(site_results):
    """Turn raw diagnostic results into human-friendly diagnosis."""
    notes = []

    dns = site_results.get("dns", {})
    tcp80 = site_results.get("tcp80", {})
    tcp443 = site_results.get("tcp443", {})
    http = site_results.get("http", {})
    ping = site_results.get("ping", {})
    tls = site_results.get("tls", {})

    if not dns.get("ok"):
        notes.append("❌ DNS resolution failed. Website may be blocked by DNS or domain doesn't exist.")
        return notes

    if not (tcp80.get("ok") or tcp443.get("ok")):
        notes.append("❌ Cannot establish TCP connection. Server may be down or blocked by firewall/ISP.")
        return notes

    if http.get("ok"):
        status = http.get("status", 0)
        if status == 200:
            notes.append("✅ Website is reachable and responding normally.")
        elif status in (403, 451):
            notes.append(f"⚠️ HTTP {status}: Access blocked (geo-restriction, firewall, or ISP filtering).")
        elif status >= 500:
            notes.append(f"⚠️ Server error ({status}): Website is up but experiencing issues.")
        else:
            notes.append(f"ℹ️ HTTP status {status}: unusual response.")
    else:
        notes.append("⚠️ HTTP request failed, but TCP connection works. Server may be overloaded or blocking requests.")

    if ping.get("ok"):
        avg = ping.get("avg_ms", 0)
        jitter = ping.get("jitter_ms", 0)
        if avg > 150:
            notes.append(f"⚠️ High latency detected ({avg:.1f} ms). May cause slow browsing or video buffering.")
        else:
            notes.append(f"✅ Latency looks normal ({avg:.1f} ms).")
        if jitter > 20:
            notes.append(f"⚠️ High jitter ({jitter:.1f} ms). Video calls or gaming may lag.")
    else:
        notes.append("⚠️ Ping failed. ICMP may be blocked by server/ISP, not always a problem.")

    if not tls.get("ok"):
        notes.append("⚠️ TLS handshake failed. Possible SSL misconfiguration or MITM blocking HTTPS.")

    return notes
