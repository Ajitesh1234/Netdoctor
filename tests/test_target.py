import pytest

from netdoctor.target import TargetError, parse_target


@pytest.mark.parametrize(
    ("raw", "host", "scheme", "port", "path"),
    [
        ("example.com", "example.com", None, None, "/"),
        ("EXAMPLE.com", "example.com", None, None, "/"),
        ("https://example.com/a?b=1", "example.com", "https", None, "/a?b=1"),
        ("example.com:8443/x", "example.com", None, 8443, "/x"),
        ("example.com:80", "example.com", "http", 80, "/"),
        ("http://example.com:8080", "example.com", "http", 8080, "/"),
        ("bücher.example", "xn--bcher-kva.example", None, None, "/"),
        ("example.com.", "example.com", None, None, "/"),
    ],
)
def test_valid(raw, host, scheme, port, path):
    t = parse_target(raw)
    assert (t.host, t.scheme, t.port, t.path) == (host, scheme, port, path)
    assert not t.is_ip


def test_ip_literals():
    assert parse_target("127.0.0.1:8080").is_ip
    t = parse_target("https://[2001:db8::1]:8443/")
    assert t.is_ip and t.host == "2001:db8::1" and t.port == 8443


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "-oProxyCommand=x",
        "--help",
        "ftp://example.com",
        "exa mple.com",
        "a..b",
        "example.com:99999",
        "example.com:abc",
        "user:pw@example.com",
        "http://",
        "ex\nample.com",
        "a" * 64 + ".com",
        "x" * 300 + ".com",
    ],
)
def test_rejected(raw):
    with pytest.raises(TargetError):
        parse_target(raw)


def test_ports_and_tls_port():
    assert parse_target("example.com").tcp_ports == [443, 80]
    assert parse_target("http://example.com").tcp_ports == [80]
    assert parse_target("http://example.com").tls_port is None
    assert parse_target("example.com:8443").tcp_ports == [8443]
    assert parse_target("https://example.com").tls_port == 443
