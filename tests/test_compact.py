import json
import os
import time

import app
from conftest import make_entries, write_segment


def wait(store):
    for _ in range(200):
        if not store.compact_state["running"]:
            return store.compact_state
        time.sleep(0.05)
    raise AssertionError("la compactación no termina")


def all_lines(store):
    return [app._dumps(e) for e in store.iter_entries()]


def small_segments(store, k=12, n=40, gap=600, gz=True):
    """k segmentos pequeños consecutivos, cada uno de n logs separados 10 s, cada `gap` s."""
    nid = 1
    for i in range(k):
        write_segment(store, make_entries(n, 1_700_000_000 + i * gap, start_id=nid, seed=i), gz=gz and i % 3 != 0)
        nid += n


def test_compact_merges_preserving_content(store):
    small_segments(store)
    before = all_lines(store)
    store.cfg["settings"].update(rotate_size_mb=32, rotate_hours=1)    # 1 h => 6 segmentos por lote
    assert [len(b) for b in store.compact_plan()] == [6, 6]
    st = store.start_compaction()
    assert st["total"] == 2 and st["segments_in"] == 12
    st = wait(store)
    assert st["error"] is None and st["segments_out"] == 2 and st["done"] == 2
    segs = store.segments()
    assert len(segs) == 2 and all(s.gz for s in segs)
    assert all(s.last - s.first <= 3600 + store.COMPACT_SLACK for s in segs)
    assert all_lines(store) == before
    assert sum(s.count for s in segs) == len(before)
    assert store.compact_plan() == []
    assert sorted(os.listdir(store.logs_dir)) == sorted([s.name for s in segs] + ["current.ndjson"])


def test_compact_by_size_and_no_compression(store):
    small_segments(store, k=8)
    plain = [s for s in store.segments() if not s.gz][0]
    assert store._plain_size(plain) == plain.size
    gz = [s for s in store.segments() if s.gz][0]
    assert store._plain_size(gz) == sum(len(app._dumps(e)) + 1 for e in store._read_segment(gz))
    store.cfg["settings"].update(rotate_size_mb=1, rotate_hours=0, compress_rotated=False)
    plan = store.compact_plan()
    assert sum(len(b) for b in plan) == 8 and all(sum(store._plain_size(s) for s in b) <= 1048576 for b in plan)
    before = all_lines(store)
    store.start_compaction()
    wait(store)
    assert len(store.segments()) == 1 and not store.segments()[0].gz
    assert all_lines(store) == before


def test_compact_nothing_to_do_and_busy(store, client):
    from conftest import H
    write_segment(store, make_entries(10, 1000))
    r = client.post("/api/segments/compact", headers=H).get_json()
    assert r["total"] == 0 and not r["running"]
    small_segments(store, k=4)
    store.compact_state = {"running": True}
    assert client.post("/api/segments/compact", headers=H).status_code == 400


def test_compact_overlapping_import(store):
    small_segments(store, k=3)
    store.import_entries([{"ts": 1_700_000_005.5, "raw": "importado"}])
    before = all_lines(store)
    store.start_compaction()
    wait(store)
    assert len(store.segments()) == 1
    lines = all_lines(store)
    assert sorted(lines) == sorted(before)
    tss = [e["ts"] for e in store.iter_entries()]
    assert tss == sorted(tss)


def test_compact_stops_on_low_disk(store, monkeypatch):
    small_segments(store)
    store.cfg["settings"].update(rotate_hours=1, min_free_percent=10)
    monkeypatch.setattr(store, "disk_info", lambda: {"total": 100, "used": 99, "free": 1, "free_pct": 1.0})
    store.start_compaction()
    st = wait(store)
    assert "espacio" in st["error"] and len(store.segments()) == 12


def test_compact_skips_batch_changed_meanwhile(store):
    small_segments(store, k=4)
    batch = store.compact_plan()[0]
    store.delete_segment(batch[0].name)            # alguien lo borra entre el plan y el lote
    store.compact_state = dict(running=True, total=1, done=0, segments_in=4, segments_out=0, error=None)
    store._compact_run([batch])
    assert store.compact_state["segments_out"] == 3 and store.compact_state["error"] is None
    assert len(store.segments()) == 3


def test_journal_recovery_after_crash(store):
    small_segments(store, k=4)
    segs = store.segments()
    saved = {s.name: open(s.path, "rb").read() for s in segs}
    total = sum(s.count for s in segs)
    with store.seg_lock:
        final = store._merge_segments(segs)
    for n, b in saved.items():                     # "corte" antes de borrar los originales
        with open(os.path.join(store.logs_dir, n), "wb") as f:
            f.write(b)
    with open(os.path.join(store.logs_dir, "compact.journal"), "w") as f:
        json.dump({"final": final, "members": list(saved)}, f)
    s2 = app.Store(store.dir)
    assert [s.name for s in s2.segments()] == [final]
    assert sum(1 for _ in s2.iter_entries()) == total
    assert not os.path.exists(os.path.join(store.logs_dir, "compact.journal"))
    s2._close_fh()


def test_journal_without_final_keeps_members(store):
    small_segments(store, k=3)
    names = [s.name for s in store.segments()]
    with open(os.path.join(store.logs_dir, "compact.journal"), "w") as f:
        json.dump({"final": "seg-1-2-3-4.ndjson.gz", "members": names}, f)
    open(os.path.join(store.logs_dir, "compact-abc.tmp"), "w").close()
    s2 = app.Store(store.dir)
    assert [s.name for s in s2.segments()] == names
    assert sorted(os.listdir(store.logs_dir)) == sorted(names + ["current.ndjson"])
    s2._close_fh()
