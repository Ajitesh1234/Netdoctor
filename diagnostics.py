
import socket, ssl, subprocess, statistics, time

def resolve_dns(host):
    try:
        ip = socket.gethostbyname(host)
        return {"ok": True, "ip": ip}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def tcp_connect(host, port=80, timeout=3):
    try:
        start = time.time()
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return {"ok": True, "latency_ms": (time.time()-start)*1000}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def tls_handshake(host, port=443, timeout=3):
    try:
        ctx = ssl.create_default_context()
        start = time.time()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        return {"ok": True, "latency_ms": (time.time()-start)*1000, "cert": cert}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def http_get(host, use_https=True, timeout=5):
    import http.client
    try:
        start = time.time()
        conn = (http.client.HTTPSConnection(host, timeout=timeout) if use_https 
                else http.client.HTTPConnection(host, timeout=timeout))
        conn.request("GET", "/")
        resp = conn.getresponse()
        data = resp.read()
        return {"ok": True, "status": resp.status, "reason": resp.reason, "latency_ms": (time.time()-start)*1000}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def ping(host, count=4):
    try:
        cmd = ["ping", "-c", str(count), host]
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        times = []
        for line in out.splitlines():
            if "time=" in line:
                ms = float(line.split("time=")[1].split()[0])
                times.append(ms)
        if times:
            return {"ok": True, "avg_ms": statistics.mean(times), "jitter_ms": statistics.pstdev(times), "loss": 0.0}
        return {"ok": False, "error": "no times"}
    except subprocess.CalledProcessError as e:
        return {"ok": False, "error": e.output}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def traceroute(host, max_hops=15):
    try:
        cmd = ["traceroute", "-m", str(max_hops), host]
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return {"ok": True, "trace": out.splitlines()}
    except Exception as e:
        return {"ok": False, "error": str(e)}
