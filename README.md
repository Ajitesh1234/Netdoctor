
# NetDoctor — Smart Network Troubleshooter

NetDoctor helps everyday users diagnose *why* a website feels slow or unreachable.  
It combines **DNS, TCP, TLS, HTTP, ping, and traceroute** checks and produces a **human-readable report**.

## 🚀 Features
- Detects **DNS failures**
- Checks if **server is down**
- Flags **website blocking (403/451, DNS tampering)**
- Measures **latency, jitter, and packet loss**
- Runs **traceroute** for path visibility
- Provides **heuristic diagnosis** (e.g., congestion vs packet loss)

## 🔧 Installation
```bash
git clone https://github.com/your-username/netdoctor.git
cd netdoctor
pip install -e .
```

## ▶️ Usage
Run diagnostics on a few sites:
```bash
python -m netdoctor.main --sites https://example.com https://www.wikipedia.org
```

Output:
- Markdown report → `netdoctor_report.md`
- JSON report → use `--json`

Example:
```bash
python -m netdoctor.main --json --out result.json
```

## 📊 Example Report
```
# NetDoctor Report

## https://www.wikipedia.org
- dns: {'ok': True, 'ip': '208.80.154.224'}
- tcp80: {'ok': True, 'latency_ms': 40.3}
- http: {'ok': True, 'status': 200, 'reason': 'OK', 'latency_ms': 122.1}
- ping: {'ok': True, 'avg_ms': 43.5, 'jitter_ms': 2.3, 'loss': 0.0}
**Diagnosis:** Latency within normal range.
```

## 📜 License
MIT License
