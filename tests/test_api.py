import gzip
import io
import json

import app
from conftest import H


def test_index_and_static(client):
    assert client.get("/").status_code == 200
    assert client.get("/static/app.js").status_code == 200


def test_csrf_header_required(client):
    assert client.post("/api/logs", json={}).status_code == 403
    assert client.get("/api/status").status_code == 200


def test_basic_auth(store):
    c = app.create_app(store, auth=("u", "p")).test_client()
    assert c.get("/api/status").status_code == 401
    import base64
    tok = base64.b64encode(b"u:p").decode()
    assert c.get("/api/status", headers={"Authorization": "Basic " + tok}).status_code == 200
    bad = base64.b64encode(b"u:x").decode()
    assert c.get("/api/status", headers={"Authorization": "Basic " + bad}).status_code == 401


def test_logs_endpoint(client, history):
    d = client.post("/api/logs", json={"size": 100, "page": 1}, headers=H).get_json()
    assert d["exact"] and d["total"] == len(history) and d["pages"] == 31
    assert [e["id"] for e in d["entries"]] == [e["id"] for e in history[::-1][:100]]
    d = client.post("/api/logs", json={"size": 100, "page": 999}, headers=H).get_json()
    assert d["page"] == 31 and len(d["entries"]) == len(history) % 100
    d = client.post("/api/logs", json={"size": 10, "sort": "len", "dir": "asc"}, headers=H).get_json()
    assert [e["len"] for e in d["entries"]] == sorted(e["len"] for e in history)[:10]
    d = client.post("/api/logs", json={"sort": "src_ip", "dir": "desc", "size": 10}, headers=H).get_json()
    assert d["total"] == len(history)
    r = client.post("/api/logs", json={"q": "len:>abc"}, headers=H)
    assert r.status_code == 400 and "inválido" in r.get_json()["error"]
    assert client.post("/api/logs", json={"sort": "nope"}, headers=H).status_code == 400


def test_stats_endpoint(client, history):
    d = client.post("/api/stats", json={}, headers=H).get_json()
    while d.get("partial"):
        d = client.post("/api/stats", json={}, headers=H).get_json()
    assert d["total"] == len(history) and d["top"]["proto"][0] == {"k": "TCP", "n": len(history)}
    assert client.post("/api/stats", json={"q": "zzz"}, headers=H).get_json()["total"] == 0


def test_export_import_roundtrip(client, store, history):
    r = client.post("/api/export", json={"format": "json", "all": True}, headers=H)
    data = json.loads(r.data)
    assert len(data["entries"]) == len(history)
    r = client.post("/api/export", json={"format": "csv", "q": "dport:22"}, headers=H)
    lines = r.data.decode().strip().splitlines()
    assert lines[0].startswith("ts_iso,ts,device") and len(lines) - 1 == sum(1 for e in history if e.get("dst_port") == 22)
    assert client.post("/api/export", json={"format": "xml"}, headers=H).status_code == 400
    # importar sobre lo mismo: todo duplicado
    up = {"file": (io.BytesIO(gzip.compress(json.dumps(data).encode())), "x.json.gz"), "mode": "merge"}
    d = client.post("/api/import", data=up, headers=H, content_type="multipart/form-data").get_json()
    assert d == {"added": 0, "skipped": len(history)}
    up = {"file": (io.BytesIO(b'[{"ts": 1, "raw": "nuevo"}]'), "x.json"), "mode": "replace"}
    assert client.post("/api/import", data=up, headers=H, content_type="multipart/form-data").get_json()["added"] == 1
    assert store.status()["entries"] == 1
    for bad in (b"no json", b'{"entries": []}'):
        up = {"file": (io.BytesIO(bad), "x.json")}
        assert client.post("/api/import", data=up, headers=H, content_type="multipart/form-data").status_code == 400


def test_purge_endpoint(client, history):
    assert client.post("/api/purge", json={"mode": "older", "days": 0}, headers=H).status_code == 400
    n22 = sum(1 for e in history if e.get("dst_port") == 22)
    d = client.post("/api/purge", json={"mode": "filter", "filter": {"q": "dport:22"}}, headers=H).get_json()
    assert d["deleted"] == n22
    d = client.post("/api/purge", json={"mode": "older", "days": 1}, headers=H).get_json()
    assert d["deleted"] == len(history) - n22          # todo el histórico es antiguo
    assert client.post("/api/purge", json={"mode": "x"}, headers=H).status_code == 400


def test_segments_endpoints(client, store, history):
    segs = client.get("/api/segments").get_json()
    assert len(segs) == 6 and segs[0]["first"] > segs[-1]["first"]
    r = client.get("/api/segments/" + segs[0]["name"])
    assert r.status_code == 200 and r.headers["Content-Disposition"].startswith("attachment")
    assert client.get("/api/segments/seg-1-2-3-4.ndjson").status_code == 404
    assert client.get("/api/segments/evil.txt").status_code == 400
    d = client.delete("/api/segments/" + segs[0]["name"], headers=H).get_json()
    assert d["deleted"] == 500 and len(client.get("/api/segments").get_json()) == 5


def test_save_rotate_config(client, store):
    assert client.post("/api/rotate", headers=H).status_code == 400
    store.ingest("system,info hola", "r")
    assert client.post("/api/save", headers=H).get_json()["ok"]
    assert client.post("/api/rotate", headers=H).get_json()["name"].startswith("seg-")
    d = client.put("/api/config", json={"rotate_hours": 6}, headers=H).get_json()
    assert d["settings"]["rotate_hours"] == 6
    assert client.get("/api/config").get_json()["settings"]["rotate_hours"] == 6
    assert client.put("/api/config", json={"low_disk_action": "x"}, headers=H).status_code == 400


def test_rules_and_searches_endpoints(client, history):
    r = client.post("/api/rules", json={"name": "ssh", "action": "highlight",
                                        "conditions": [{"field": "dport", "op": "eq", "value": "22"}]}, headers=H)
    assert r.status_code == 201
    rid = r.get_json()["id"]
    t = client.post("/api/rules/test", json=r.get_json(), headers=H).get_json()
    assert t["window_hours"] == 24 and "count" in t
    assert client.get("/api/rules?counts=1").get_json()[0]["matches"] is not None
    assert client.post(f"/api/rules/{rid}/move", json={"dir": "x"}, headers=H).status_code == 400
    assert client.put(f"/api/rules/{rid}", json={"action": "highlight", "conditions": [{"value": "a"}]},
                      headers=H).status_code == 200
    assert client.delete(f"/api/rules/{rid}", headers=H).get_json()["ok"]
    assert client.delete("/api/rules/nope", headers=H).status_code == 404
    s = client.post("/api/searches", json={"name": "s1", "q": "dport:22"}, headers=H)
    assert s.status_code == 201
    assert client.post("/api/searches", json={"name": ""}, headers=H).status_code == 400
    assert len(client.get("/api/config").get_json()["searches"]) == 1
    client.delete("/api/searches/" + s.get_json()["id"], headers=H)
    assert client.get("/api/config").get_json()["searches"] == []
