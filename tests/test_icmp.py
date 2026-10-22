from netdoctor.checks.icmp import parse_ping

LINUX = """PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
--- 1.1.1.1 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 4006ms
rtt min/avg/max/mdev = 10.100/12.300/15.500/1.800 ms
"""
MAC = """--- 1.1.1.1 ping statistics ---
5 packets transmitted, 4 packets received, 20.0% packet loss
round-trip min/avg/max/stddev = 9.1/10.2/11.3/0.7 ms
"""
WIN = """Ping statistics for 1.1.1.1:
    Packets: Sent = 4, Received = 3, Lost = 1 (25% loss),
Approximate round trip times in milli-seconds:
    Minimum = 12ms, Maximum = 20ms, Average = 15ms
"""
DEAD = """--- 10.255.255.1 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2050ms
"""


def test_linux():
    r = parse_ping(LINUX)
    assert r.ok and (r.sent, r.received, r.loss_pct) == (5, 5, 0.0)
    assert (r.min_ms, r.avg_ms, r.max_ms, r.jitter_ms) == (10.1, 12.3, 15.5, 1.8)


def test_macos_partial_loss():
    r = parse_ping(MAC)
    assert r.ok and r.loss_pct == 20.0 and r.received == 4 and r.jitter_ms == 0.7


def test_windows():
    r = parse_ping(WIN)
    assert r.ok and r.loss_pct == 25.0 and r.avg_ms == 15.0 and r.jitter_ms is None


def test_total_loss():
    r = parse_ping(DEAD)
    assert not r.ok and r.loss_pct == 100.0 and r.avg_ms is None


def test_garbage():
    r = parse_ping("ping: unknown host")
    assert not r.ok and r.error
