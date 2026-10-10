import gzip
import json
import os
import time

import app
from conftest import make_entries, write_segment

LINE = ("firewall,info DROP input: in:ether1 out:bridge, proto TCP (SYN), "
        "45.33.32.156:1234->192.168.88.1:{port}, len 60")


def ids(entries):
    return [e["id"] for e in entries]


def test_ingest_save_and_reload(store):
    for p in (22, 80, 443):
        store.ingest(LINE.format(port=p), "10.0.0.1")
    store.ingest("   ", "10.0.0.1")
    assert store.counters["stored"] == 3 and store.counters["invalid"] == 1
    assert store.status()["unsaved"] == 3
    assert store.save_logs() and store.status()["unsaved"] == 0
    store._close_fh()
    again = app.Store(store.dir)
    assert [e["dst_port"] for e in again.cur] == [22, 80, 443]
    assert again.next_id == 4
    again._close_fh()


def test_capture_paused_and_drop_rule(store):
    store.update_settings({"capture_enabled": False})
    store.ingest(LINE.format(port=22), "r")
    assert store.counters["paused"] == 1 and not store.cur
    store.update_settings({"capture_enabled": True})
    store.add_rule({"name": "ssh", "action": "exclude", "mode": "drop",
                    "conditions": [{"field": "dport", "op": "eq", "value": "22"}]})
    store.ingest(LINE.format(port=22), "r")
    store.ingest(LINE.format(port=80), "r")
    assert store.counters["dropped_rule"] == 1 and len(store.cur) == 1
    assert store.cfg["rules"][0]["hits"] == 1


def test_rules_crud_and_hidden(store, client):
    r = store.add_rule({"name": "hide80", "action": "exclude", "mode": "hide",
                        "conditions": [{"field": "dport", "op": "eq", "value": "80"}]})
    h = store.add_rule({"name": "hl", "action": "highlight", "color": "#ff0000",
                        "conditions": [{"field": "dport", "op": "eq", "value": "443"}]})
    for p in (80, 443, 22):
        store.ingest(LINE.format(port=p), "r")
    from conftest import H
    d = client.post("/api/logs", json={}, headers=H).get_json()
    assert [e["dst_port"] for e in d["entries"]] == [22, 443]     # más reciente primero
    assert d["entries"][1]["hl"] == {"color": "#ff0000", "names": ["hl"]}
    assert client.post("/api/logs", json={"show_hidden": True}, headers=H).get_json()["total"] == 3
    assert client.post("/api/logs", json={"only_highlighted": True}, headers=H).get_json()["total"] == 1
    store.move_rule(h["id"], "up")
    assert store.cfg["rules"][0]["id"] == h["id"]
    store.update_rule(r["id"], dict(r, enabled=False))
    assert client.post("/api/logs", json={}, headers=H).get_json()["total"] == 3
    store.delete_rule(r["id"])
    assert len(store.cfg["rules"]) == 1
    assert store.rule_counts() == {h["id"]: 1}


def test_rotation_by_size_and_age(store):
    store.cfg["settings"]["rotate_size_mb"] = 1
    big = "x" * 1500
    for _ in range(800):
        store.ingest("system,info " + big, "r")
    segs = store.segments()
    assert len(segs) == 1 and store.counters["rotations"] == 1
    assert segs[0].count + len(store.cur) == 800
    store.cfg["settings"]["rotate_hours"] = 1
    store.cur[0]["ts"] -= 7200
    store._rotate_if_old()
    assert len(store.segments()) == 2 and not store.cur
    assert store.rotate_now() is None          # vacío: no rota


def test_compress_pending(store):
    write_segment(store, make_entries(20, 1000), gz=False)
    store._compress_pending()
    segs = store.segments()
    assert len(segs) == 1 and segs[0].gz
    assert ids(store.iter_entries()) == list(range(1, 21))
    store.cfg["settings"]["compress_rotated"] = False
    write_segment(store, make_entries(5, 5000, start_id=21), gz=False)
    store._compress_pending()
    assert sum(1 for s in store.segments() if not s.gz) == 1


def test_corrupt_current_and_tmp_cleanup(tmp_path):
    d = tmp_path / "d" / "logs"
    d.mkdir(parents=True)
    good = make_entries(3, 100)
    (d / "current.ndjson").write_text("\n".join(app._dumps(e) for e in good) + '\n{"ts": 1, "id"', encoding="utf-8")
    (d / "seg-x.ndjson.tmp").write_text("basura")
    s = app.Store(str(tmp_path / "d"))
    assert ids(s.cur) == [1, 2, 3] and "ilegibles" in s.warning
    assert not (d / "seg-x.ndjson.tmp").exists()
    s.ingest(LINE.format(port=1), "r")
    assert s.cur[-1]["id"] == 4
    s._close_fh()


def test_corrupt_config_is_moved(tmp_path):
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "config.json").write_text("{nope")
    s = app.Store(str(tmp_path / "d"))
    assert "ilegible" in s.warning and s.cfg["settings"] == app.DEFAULT_SETTINGS
    assert any(n.startswith("config.json.corrupt-") for n in os.listdir(tmp_path / "d"))
    s._close_fh()


def test_legacy_migration(tmp_path):
    (tmp_path / "d").mkdir()
    legacy = {"entries": [{"ts": 10, "raw": "a"}, {"ts": 5, "raw": "b"}], "next_id": 3}
    with gzip.open(tmp_path / "d" / "logs.json", "wt") as f:
        json.dump(legacy, f)
    s = app.Store(str(tmp_path / "d"))
    assert [e["raw"] for e in s.iter_entries()] == ["b", "a"]
    assert (tmp_path / "d" / "logs.json.migrated").exists() and s.next_id == 3
    s._close_fh()


def test_iter_entries_window_and_overlap(store, history):
    assert ids(store.iter_entries()) == ids(sorted(history, key=lambda e: e["ts"]))
    t0, t1 = history[700]["ts"], history[1800]["ts"]
    got = [e for e in store.iter_entries(t0, t1) if t0 <= e["ts"] <= t1]
    assert ids(got) == ids(history[700:1801])
    # una importación que se solapa con segmentos existentes se mezcla por fecha
    res = store.import_entries([{"ts": history[10]["ts"] + 1, "raw": "importado"}, dict(history[11])])
    assert res == {"added": 1, "skipped": 1}
    tss = [e["ts"] for e in store.iter_entries()]
    assert tss == sorted(tss) and len(tss) == len(history) + 1


def test_import_replace(store, history):
    res = store.import_entries([{"ts": 5, "raw": "solo"}], mode="replace")
    assert res["added"] == 1 and [e["raw"] for e in store.iter_entries()] == ["solo"]


def test_purge_filter_older_clear(store, history):
    q = app.make_query(store, {"q": "dport:22", "show_hidden": True}, (None, None))
    n22 = sum(1 for e in history if e.get("dst_port") == 22)
    assert store.purge(pred=q.match) == n22
    assert not any(e.get("dst_port") == 22 for e in store.iter_entries())
    cutoff = history[1600]["ts"]
    left = [e for e in history if e.get("dst_port") != 22]
    assert store.delete_older_than(cutoff) == sum(1 for e in left if e["ts"] < cutoff)
    assert min(e["ts"] for e in store.iter_entries()) >= cutoff
    total = sum(1 for _ in store.iter_entries())
    assert store.clear() == total
    assert list(store.iter_entries()) == [] and store.segments() == []


def test_delete_segment(store, history):
    seg = store.segments()[0]
    assert store.delete_segment(seg.name) == 500
    assert len(store.segments()) == 5
    for bad in ("../config.json", "nope"):
        try:
            store.delete_segment(bad)
            raise AssertionError
        except (ValueError, FileNotFoundError):
            pass


def test_retention(store, history):
    store.cfg["settings"]["retention_days"] = 1
    assert store.enforce_retention() == 3000   # todos los rotados son de 2023
    assert store.segments() == [] and len(store.cur) == 50
    store.cfg["settings"]["retention_days"] = 0
    assert store.enforce_retention() == 0


def test_disk_guard(store, history, monkeypatch):
    free = {"pct": 5.0}
    monkeypatch.setattr(store, "disk_info", lambda: {"total": 100, "used": 100 - free["pct"],
                                                    "free": free["pct"], "free_pct": free["pct"]})
    store.cfg["settings"].update(min_free_percent=10, low_disk_action="pause")
    store.check_disk()
    assert store.low_disk
    store.ingest(LINE.format(port=1), "r")
    assert store.counters["paused_disk"] == 1
    free["pct"] = 10.5                    # histéresis: hace falta mínimo + 1
    store.check_disk()
    assert store.low_disk
    free["pct"] = 12
    store.check_disk()
    assert not store.low_disk
    # delete_oldest: borra rotados (simulamos que cada borrado libera 2 %)
    real_remove = store._remove_seg_files

    def remove(seg):
        real_remove(seg)
        free["pct"] += 2
    monkeypatch.setattr(store, "_remove_seg_files", remove)
    free["pct"] = 6
    store.cfg["settings"]["low_disk_action"] = "delete_oldest"
    store.check_disk()
    assert len(store.segments()) == 3 and not store.low_disk and "borrados 3" in store.guard_note


def test_status(store, history):
    st = store.status()
    assert st["entries"] == len(history) and st["storage"]["segments"] == 6
    assert st["first_ts"] == history[0]["ts"] and st["last_ts"] == history[-1]["ts"]
    assert st["compact"] is None and "disk" in st


def test_maintenance_thread_stops(store):
    import threading
    stop = threading.Event()
    t = threading.Thread(target=store.maintenance, args=(stop,))
    t.start()
    store.ingest(LINE.format(port=1), "r")
    time.sleep(1.3)
    stop.set()
    t.join(3)
    assert not t.is_alive()
