import app


def test_firewall_line():
    e = app.parse_line("firewall,info DROP-WAN input: in:ether1 out:(unknown 0), connection-state:new "
                       "src-mac 0c:aa:bb:cc:dd:ee, proto TCP (SYN), 45.33.32.156:51000->192.168.88.1:22, "
                       "len 60", "10.0.0.1", 1000.1234)
    assert e["ts"] == 1000.123
    assert e["device"] == "10.0.0.1"
    assert e["topics"] == "firewall,info" and e["level"] == "info"
    assert e["prefix"] == "DROP-WAN" and e["chain"] == "input"
    assert e["in_if"] == "ether1" and e["out_if"] == "(unknown 0)"
    assert e["conn_state"] == "new" and e["src_mac"] == "0C:AA:BB:CC:DD:EE"
    assert e["proto"] == "TCP" and e["proto_info"] == "SYN"
    assert (e["src_ip"], e["src_port"], e["dst_ip"], e["dst_port"]) == ("45.33.32.156", 51000, "192.168.88.1", 22)
    assert e["len"] == 60 and e["scope"] == "entrante"


def test_nat_and_ipv6():
    e = app.parse_line("firewall,info forward: in:bridge out:ether1, proto UDP, "
                       "192.168.88.10:5353->8.8.8.8:53, NAT (192.168.88.10:5353->1.2.3.4:5353)->8.8.8.8:53, len 70",
                       "r", 1)
    assert e["nat"].startswith("(192.168.88.10")
    assert e["scope"] == "saliente" and e["len"] == 70
    e = app.parse_line("firewall,info input: in:ether1 out:(none), proto ICMP, [2001:db8::1]:0->[fe80::1]:0, len 8",
                       "r", 1)
    assert e["src_ip"] == "2001:db8::1" and "out_if" not in e


def test_syslog_headers_and_plain():
    e = app.parse_line("<30>Oct 10 12:00:00 MiRouter system,info user admin logged in", "1.1.1.1", 5)
    assert e["device"] == "MiRouter" and e["topics"] == "system,info" and "chain" not in e
    e = app.parse_line("<30>2026-10-10T12:00:00Z gw dhcp,info lease assigned", "1.1.1.1", 5)
    assert e["device"] == "gw" and e["raw"] == "dhcp,info lease assigned"
    assert app.parse_line("  \x00 ", "x", 1) is None
    assert app.parse_line("<13>", "x", 1) is None
    assert len(app.parse_line("x" * 5000, "x", 1)["raw"]) == app.MAX_RAW


def test_scope():
    assert app._scope("8.8.8.8", "1.1.1.1") == "externo"
    assert app._scope("10.0.0.1", "192.168.1.1") == "interno"
    assert app._scope("nope", "1.1.1.1") is None


def test_sanitize_entry():
    assert app.sanitize_entry({"ts": "12.5", "raw": "x", "src_port": 5, "len": True, "evil": 1, "id": 3}) == \
        {"ts": 12.5, "raw": "x", "src_port": 5, "id": 3}
    assert app.sanitize_entry({"ts": "a", "raw": "x"}) is None
    assert app.sanitize_entry({"ts": 1, "raw": ""}) is None
    assert app.sanitize_entry([1]) is None
