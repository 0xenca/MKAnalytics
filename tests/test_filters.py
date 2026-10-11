import pytest

import app

E = app.parse_line("firewall,info DROP input: in:ether1 out:bridge, connection-state:new src-mac "
                   "aa:bb:cc:dd:ee:01, proto TCP (SYN), 203.0.113.5:51000->192.168.88.1:443, len 60",
                   "10.0.0.1", 1000)


def matches(q):
    preds = app.compile_filter({"q": q})
    return all(p(E) for p in preds)


@pytest.mark.parametrize("q,expected", [
    ("203.0.113", True), ("nothere", False), ("-udp", True), ("-tcp", False),
    ("src:203.0.113.0/24", True), ("src:10.0.0.0/8", False), ("ip:192.168.88.1", True),
    ("dport:443", True), ("dport:22,443", True), ("dport:22", False), ("port:51000", True),
    ("len:>50", True), ("len:<=59", False), ("len:>=60", True),
    ("proto:tcp", True), ("chain=input", True), ("chain=inp", False), ("chain:inp", True),
    ("state!=new", False), ("in=ether1", True), ("if:bridge", True),
    ("/SYN.*443/", True), ("msg:/^firewall/", True), ('"TCP (SYN)"', True),
    ("topic=firewall", True), ("level=info", True), ("mac:aa:bb", True), ("scope=interno", True), ("scope=entrante", False),
])
def test_query_language(q, expected):
    assert matches(q) is expected


@pytest.mark.parametrize("op,value,expected", [
    ("contains", "203.0", True), ("not_contains", "203.0", False), ("eq", "203.0.113.5", True),
    ("ne", "203.0.113.5", False), ("starts", "203.", True), ("ends", ".5", True),
    ("regex", r"^203\.", True), ("not_regex", r"^203\.", False), ("cidr", "203.0.113.0/24", True),
    ("not_cidr", "203.0.113.0/24", False), ("in", "1.1.1.1, 203.0.113.5", True),
    ("not_in", "1.1.1.1", True), ("exists", "", True), ("not_exists", "", False),
])
def test_condition_ops(op, value, expected):
    assert app.compile_cond({"field": "src_ip", "op": op, "value": value})(E) is expected


def test_numeric_ops():
    for op, v, exp in [("gt", "59", True), ("gte", "60", True), ("lt", "60", False), ("lte", "60", True),
                       ("eq", "60.0", True), ("in", "1,60", True)]:
        assert app.compile_cond({"field": "len", "op": op, "value": v})(E) is exp


def test_invalid_filters():
    for c in ({"field": "nope", "value": "x"}, {"field": "len", "op": "gt", "value": "abc"},
              {"field": "raw", "op": "regex", "value": "("}, {"field": "src_ip", "op": "cidr", "value": "x/99"},
              {"field": "raw", "op": "weird", "value": "x"}, {"field": "raw", "op": "eq", "value": ""}):
        with pytest.raises(ValueError):
            app.compile_cond(c)
    with pytest.raises(ValueError):
        app.compile_filter({"q": "src:"})


def test_cond_hint_is_necessary():
    """Si hay pista, toda entrada que cumple la condición contiene la pista en su línea JSON."""
    line = app._dumps(E).lower()
    conds = app.parse_query('203.0.113 dport:443 chain=input proto:tcp "TCP (SYN)" level=info topic=firewall')
    for c in conds:
        assert app.compile_cond(c)(E)
        h = app._cond_hint(c)
        assert h is None or h in line
    # sin pista cuando no es seguro deducirla
    for c in ({"field": "len", "op": "eq", "value": "60.0"}, {"field": "src_ip", "op": "cidr", "value": "1.0.0.0/8"},
              {"field": "raw", "op": "contains", "value": 'a"b'}, {"field": "raw", "op": "contains", "value": "x", "not": True},
              {"field": "ts", "op": "contains", "value": "1"}, {"field": "raw", "op": "regex", "value": "x"}):
        assert app._cond_hint(c) is None


def test_clean_rule():
    r = app.clean_rule({"name": "", "action": "exclude", "conditions": [{"field": "dport", "op": "eq", "value": 22}]})
    assert r["name"] == "Regla sin nombre" and r["mode"] == "drop" and r["match"] == "all"
    assert app.compile_rule(dict(r, conditions=[{"field": "dst_port", "op": "eq", "value": "443"}]))(E)
    any_rule = app.clean_rule({"action": "highlight", "match": "any", "color": "#AABBCC",
                               "conditions": [{"field": "dport", "value": "1"}, {"field": "proto", "value": "tcp"}]})
    assert any_rule["color"] == "#aabbcc" and app.compile_rule(any_rule)(E)
    for bad in ({"action": "x", "conditions": [{"value": "a"}]}, {"action": "highlight", "conditions": []},
                {"action": "highlight", "color": "red", "conditions": [{"value": "a"}]},
                {"action": "exclude", "mode": "x", "conditions": [{"value": "a"}]}):
        with pytest.raises(ValueError):
            app.clean_rule(bad)


def test_clean_settings():
    cur = dict(app.DEFAULT_SETTINGS)
    s = app.clean_settings({"rotate_size_mb": "99999", "rotate_hours": 0, "retention_days": -3,
                            "compress_rotated": 0, "low_disk_action": "pause"}, cur)
    assert s["rotate_size_mb"] == 4096 and s["rotate_hours"] == 0 and s["retention_days"] == 1
    assert s["compress_rotated"] is False and s["low_disk_action"] == "pause"
    for bad in ({"autosave_seconds": "x"}, {"low_disk_action": "explode"}):
        with pytest.raises(ValueError):
            app.clean_settings(bad, cur)


def test_user_regex_is_linear_time():
    """Patrones de backtracking catastrófico (ReDoS) no bloquean: RE2 va en tiempo lineal."""
    import time
    evil = {"field": "raw", "op": "regex", "value": "^(a+)+$"}
    pred = app.compile_cond(evil)
    t = time.monotonic()
    assert not pred({"raw": "a" * 100_000 + "!"})
    assert time.monotonic() - t < 1.0
    assert app.compile_filter({"q": "/(x+x+)+y/"})[0]({"raw": "x" * 50_000}) is False


def test_user_regex_limits():
    assert app.compile_cond({"field": "raw", "op": "regex", "value": "syn.*ACK"})({"raw": "TCP (SYN,ACK)"})
    for bad in (r"(a)\1", r"(?<=a)b", "x" * (app.MAX_REGEX_LEN + 1)):
        with pytest.raises(ValueError):
            app.compile_cond({"field": "raw", "op": "regex", "value": bad})
