import socket, ssl, subprocess, platform, requests, time

def resolve_dns(host):
    try:
        ip = socket.gethostbyname(host)
        return {"ok": True, "ip": ip}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def tcp_check(ip, port, timeout=3):
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.close()
        return {"ok": True, "latency_ms": timeout*100}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def check_tls(host, timeout=3):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return {"ok": True, "cert": cert}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def http_get(host, timeout=5):
    try:
        start = time.time()
        r = requests.get("http://" + host, timeout=timeout)
        return {"ok": True, "status": r.status_code,
                "reason": r.reason,
                "latency_ms": (time.time()-start)*1000}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def ping(host, count=1):
    try:
        param = "-n" if platform.system().lower()=="windows" else "-c"
        cmd = ["ping", param, str(count), host]
        out = subprocess.check_output(cmd, universal_newlines=True)
        return {"ok": True, "output": out}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def traceroute(host, max_hops=20):
    try:
        if platform.system().lower()=="windows":
            cmd = ["tracert", "-h", str(max_hops), host]
        else:
            cmd = ["traceroute", "-m", str(max_hops), host]
        out = subprocess.check_output(cmd, universal_newlines=True)
        return {"ok": True, "output": out}
    except Exception as e:
        return {"ok": False, "error": str(e)}
