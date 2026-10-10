from collections import Counter

import pytest

import app

QUERIES = [{}, {"q": "dport:22"}, {"q": "chain=input -proto:udp"}, {"q": "DROP"},
           {"conditions": [{"field": "src_ip", "op": "cidr", "value": "203.0.113.0/28"}]},
           {"q": "nada-coincide"}]


def reference(store, body, window):
    q = app.make_query(store, body, window)
    return [e for e in store.iter_entries() if q.match(e)]


def page_until_exact(store, q, page, size, desc):
    for _ in range(100):
        total, exact, rows = app.query_page(store, q, page, size, desc, budget=0)
        if exact:
            return total, rows
    raise AssertionError("no converge")


@pytest.mark.parametrize("body", QUERIES)
@pytest.mark.parametrize("window_idx", [None, (700, 2600)])
def test_query_page_matches_reference(store, history, body, window_idx):
    window = (None, None) if window_idx is None else \
        (history[window_idx[0]]["ts"] + 0.5, history[window_idx[1]]["ts"] - 0.5)
    ref = reference(store, body, window)
    q = app.make_query(store, body, window)
    for desc in (True, False):
        order = ref[::-1] if desc else ref
        for page in (1, 2, 7, 30):
            for budget in (0, 10):          # budget 0 obliga a ir por tandas
                if budget:
                    total, exact, rows = app.query_page(store, q, page, 100, desc, budget=budget)
                    assert exact
                else:
                    total, rows = page_until_exact(store, q, page, 100, desc)
                assert total == len(ref)
                assert [e["id"] for e in rows] == [e["id"] for e in order[(page - 1) * 100: page * 100]]


def test_progressive_count_uses_cache(store, history, monkeypatch):
    q = app.make_query(store, {"q": "dport:22"}, (None, None))
    reads = Counter()
    real = store._read_segment

    def spy(seg, keep=None):
        reads[seg.name] += 1
        return real(seg, keep)
    monkeypatch.setattr(store, "_read_segment", spy)
    total, exact, rows = app.query_page(store, q, 1, 100, True, budget=0)
    assert not exact and total <= sum(1 for e in history if e.get("dst_port") == 22)
    steps = 1
    while not exact:
        total, exact, rows = app.query_page(store, q, 1, 100, True, budget=0)
        steps += 1
    assert steps > 2 and total == sum(1 for e in history if e.get("dst_port") == 22)
    reads.clear()
    app.query_page(store, q, 1, 100, True)            # ya contado: solo abre lo necesario
    assert sum(reads.values()) <= 2


def test_trivial_count_without_reading(store, history, monkeypatch):
    monkeypatch.setattr(store, "_read_segment", lambda *a, **k: (_ for _ in ()).throw(AssertionError("leído")))
    q = app.make_query(store, {}, (None, None))
    total, exact, rows = app.query_page(store, q, 1, 20, True)
    assert exact and total == len(history) and len(rows) == 20   # las 20 primeras salen del activo
    assert app.count_matches(store, q) == (len(history), True)


def test_hide_rule_changes_signature(store, history):
    q1 = app.make_query(store, {}, (None, None))
    store.add_rule({"name": "h", "action": "exclude", "mode": "hide",
                    "conditions": [{"field": "dport", "op": "eq", "value": "22"}]})
    q2 = app.make_query(store, {}, (None, None))
    assert q1.sig != q2.sig and not q2.trivial
    n = app.count_matches(store, q2)[0]
    assert n == sum(1 for e in history if e.get("dst_port") != 22)
    assert app.make_query(store, {"show_hidden": True}, (None, None)).trivial


def test_lru():
    c = app.LRU(3)
    c.put("a", 1)
    c.put("b", 2, 2)
    c.get("a")
    c.put("c", 3)
    assert c.get("b") is None and c.get("a") == 1 and c.get("c") == 3 and c.w == 2


def norm_top(items):
    """Los empates (mismo recuento) pueden salir en cualquier orden y, en el último puesto, ser
    cualquiera de los empatados: se comparan los recuentos y las claves sin empate en el corte."""
    ns = [x["n"] for x in items]
    cut = ns[-1] if len(ns) == 15 else -1
    return sorted(ns), sorted(str(x["k"]) for x in items if x["n"] > cut)


def same_stats(a, b):
    ka = {k: v for k, v in a.items() if k != "top"}
    kb = {k: v for k, v in b.items() if k != "top"}
    assert ka == kb
    for k in a["top"]:
        assert norm_top(a["top"][k]) == norm_top(b["top"][k]), k


def stats_until_done(store, body, window, now):
    for _ in range(100):
        d = app.compute_stats(store, body, window, now, budget=0)
        if not d.get("partial"):
            return d
    raise AssertionError("no converge")


@pytest.mark.parametrize("body", QUERIES[:4])
def test_stats_match_reference(store, history, body):
    store.add_rule({"name": "hl", "action": "highlight", "conditions": [{"field": "dport", "op": "eq", "value": "443"}]})
    window = (None, None)
    now = history[-1]["ts"] + 10
    ref = reference(store, body, window)
    first = app.compute_stats(store, body, window, now, budget=0)
    if len(store.segments()) > 1 and ref:
        assert first["partial"]
    d = stats_until_done(store, body, window, now)
    again = app.compute_stats(store, body, window, now)      # caliente: misma respuesta
    same_stats(again, d)
    assert d["total"] == len(ref)
    if not ref:
        return
    assert d["bytes"] == sum(e.get("len", 0) for e in ref)
    assert sum(x["n"] for x in d["timeline"]) == len(ref)
    assert sum(d["hours"]) == len(ref)
    assert d["highlighted"] == sum(1 for e in ref if e.get("dst_port") == 443)
    for f in ("proto", "chain", "prefix", "dst_port", "src_ip", "dst_ip"):
        exp = Counter(str(e[f]) for e in ref if e.get(f) is not None)
        assert norm_top(d["top"][f]) == norm_top([{"k": k, "n": n} for k, n in exp.most_common(15)]), f
    assert d["unique_src"] == len({e["src_ip"] for e in ref})
    assert d["approx"] is False


def test_stats_trimmed_and_estimated(store, monkeypatch, history):
    monkeypatch.setattr(app, "TRIM_K", 5)
    monkeypatch.setattr(app, "SKETCH_K", 16)
    d = stats_until_done(store, {}, (None, None), history[-1]["ts"])
    assert d["approx"] is True and d["total"] == len(history)
    real = len({e["src_ip"] for e in history})
    assert real * 0.4 <= d["unique_src"] <= real * 2.5


def test_prev_total(store, history):
    t0, t1 = history[1500]["ts"], history[2000]["ts"]
    d = stats_until_done(store, {"from": t0, "to": t1}, (t0, t1), t1)
    dur = t1 - t0
    assert d["prev_total"] == sum(1 for e in history if t0 - dur <= e["ts"] <= t0)


def test_rule_counts_cached(store, history, monkeypatch):
    r = store.add_rule({"name": "x", "action": "highlight", "conditions": [{"field": "proto", "value": "tcp"}]})
    monkeypatch.setattr(app.time, "time", lambda: history[-1]["ts"] + 1)
    t0 = history[-1]["ts"] + 1 - 86400
    exp = sum(1 for e in history if e["ts"] >= t0)
    assert store.rule_counts() == {r["id"]: exp}
    assert store.rule_counts() == {r["id"]: exp}
    assert len(app.RULES_CACHE.d) >= 1
