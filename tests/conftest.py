import gzip
import os
import random
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app  # noqa: E402

H = {"X-Requested-With": "fetch"}

FW = ("firewall,info {pfx} {chain}: in:ether1 out:bridge, connection-state:new "
      "src-mac aa:bb:cc:dd:ee:{m:02x}, proto TCP (SYN), {s}:{sp}->{d}:{dp}, len {ln}")


def fw_line(rnd, i):
    return FW.format(pfx=rnd.choice(["DROP", "ACCEPT", "WAN"]), chain=rnd.choice(["input", "forward"]),
                     m=i % 7, s="203.0.113.%d" % rnd.randint(1, 40), sp=rnd.randint(1024, 65535),
                     d="192.168.88.%d" % rnd.randint(1, 20), dp=rnd.choice([22, 53, 80, 443, 8291]),
                     ln=rnd.randint(40, 1500))


def make_entries(n, t0, step=10.0, start_id=1, seed=0):
    rnd = random.Random(seed)
    out = []
    for i in range(n):
        e = app.parse_line(fw_line(rnd, i), "10.0.0.1", t0 + i * step)
        e["id"] = start_id + i
        out.append(e)
    return out


def write_segment(store, entries, gz=True):
    """Escribe `entries` como segmento rotado (igual que lo haría la rotación + compresión)."""
    name = app._seg_filename(entries[0]["ts"], entries[-1]["ts"], max(e["id"] for e in entries),
                             len(entries), gz)
    path = os.path.join(store.logs_dir, name)
    data = "".join(app._dumps(e) + "\n" for e in entries).encode()
    with (gzip.open(path, "wb") if gz else open(path, "wb")) as f:
        f.write(data)
    store._invalidate()
    return name


@pytest.fixture(autouse=True)
def _clear_caches():
    for c in (app.COUNT_CACHE, app.AGG_CACHE, app.RULES_CACHE):
        c.d.clear()
        c.w = 0
    yield


@pytest.fixture
def store(tmp_path):
    s = app.Store(str(tmp_path / "data"))
    yield s
    s._close_fh()


@pytest.fixture
def client(store):
    return app.create_app(store).test_client()


@pytest.fixture
def history(store):
    """Histórico con 6 segmentos rotados (500 logs cada uno, 10 s entre logs) + segmento activo."""
    t0 = 1_700_000_000.0
    all_entries = []
    nid = 1
    for k in range(6):
        es = make_entries(500, t0 + k * 5000, start_id=nid, seed=k)
        write_segment(store, es, gz=k % 2 == 0)
        all_entries += es
        nid += 500
    cur = make_entries(50, t0 + 6 * 5000, start_id=nid, seed=99)
    with store.lock:
        store.cur = list(cur)
        store.next_id = nid + 50
        store._rewrite_current_locked()
    all_entries += cur
    return all_entries
