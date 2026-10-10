#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MikroTik Log Viewer
===================
Receptor syslog UDP (por defecto :4501) + interfaz web (Flask) para ver, filtrar,
analizar y guardar logs de MikroTik. Guardado en segmentos NDJSON con rotación
(sin backups y sin tope de logs; el límite real es el espacio libre en disco).

Uso:
    python app.py                       # syslog UDP 4501, web 8080
    python app.py --syslog-port 514 --web-port 8000 --data-dir /var/lib/mtlogs

Variables de entorno opcionales:
    LOGVIEW_USER / LOGVIEW_PASS   -> activa autenticación HTTP Basic
    SYSLOG_PORT, WEB_PORT, WEB_HOST, SYSLOG_HOST, DATA_DIR
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import heapq
import hmac
import ipaddress
import json
import logging
import math
import operator
import os
import re
import shlex
import shutil
import signal
import socket
import statistics
import struct
import sys
import threading
import time
import uuid
from collections import Counter, OrderedDict, deque
from datetime import datetime
from functools import lru_cache

try:                       # opcional: decodifica JSON varias veces más rápido
    from orjson import loads as _loads
except ImportError:
    _loads = json.loads

from flask import Flask, Response, jsonify, request, send_file, send_from_directory
from werkzeug.exceptions import HTTPException

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
log = logging.getLogger("mtlogs")

MAX_RAW = 2000
LEVELS = {"debug", "info", "warning", "error", "critical"}

STR_FIELDS = ("device", "topics", "level", "prefix", "chain", "in_if", "out_if", "proto",
              "proto_info", "src_ip", "dst_ip", "src_mac", "conn_state", "conn_mark",
              "conn_nat_state", "nat", "scope", "raw")
INT_FIELDS = ("src_port", "dst_port", "len")
FIELD_SET = set(STR_FIELDS) | set(INT_FIELDS) | {"ts", "id"}
NUM_FIELDS = {"src_port", "dst_port", "len", "ts", "id"}
IP_FIELDS = {"src_ip", "dst_ip"}

GROUPS = {
    "ip": ("src_ip", "dst_ip"),
    "port": ("src_port", "dst_port"),
    "if": ("in_if", "out_if"),
    "any": ("raw",),
}
ALIASES = {
    "src": "src_ip", "dst": "dst_ip", "sport": "src_port", "dport": "dst_port",
    "mac": "src_mac", "state": "conn_state", "mark": "conn_mark", "in": "in_if",
    "out": "out_if", "iface": "if", "interface": "if", "host": "device",
    "router": "device", "length": "len", "flags": "proto_info", "tcpflags": "proto_info",
    "msg": "raw", "message": "raw", "text": "raw", "topic": "topics",
}
KNOWN_NAMES = FIELD_SET | set(GROUPS) | set(ALIASES)

SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp",
    80: "http", 110: "pop3", 123: "ntp", 137: "netbios", 139: "netbios", 143: "imap",
    161: "snmp", 443: "https", 445: "smb", 465: "smtps", 500: "ike", 587: "submission",
    853: "dns-tls", 993: "imaps", 995: "pop3s", 1194: "openvpn", 1723: "pptp",
    1900: "ssdp", 3306: "mysql", 3389: "rdp", 4500: "ipsec-nat-t", 5060: "sip",
    5353: "mdns", 5432: "postgres", 8080: "http-alt", 8291: "winbox",
    8728: "mikrotik-api", 8729: "mikrotik-api-ssl", 51820: "wireguard",
}

DEFAULT_SETTINGS = {
    "capture_enabled": True,
    "autosave_seconds": 5,          # cada cuánto se vuelca el búfer a disco (flush + fsync)
    "rotate_size_mb": 32,           # rotar el segmento activo al llegar a este tamaño
    "rotate_hours": 24,             # ...o al cumplir esta antigüedad (0 = solo por tamaño)
    "compress_rotated": True,       # comprimir (gzip) los segmentos rotados
    "retention_days": 0,            # 0 = sin límite por antigüedad
    "min_free_percent": 10,         # guard de disco: % libre mínimo (0 = desactivado)
    "low_disk_action": "delete_oldest",   # o "pause"
}

COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
DEFAULT_HL_COLOR = "#ffeb3b"


# ----------------------------------------------------------------------------
# Parser de líneas MikroTik
# ----------------------------------------------------------------------------
RE_PRI = re.compile(r"^<\d{1,3}>")
RE_BSD = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d\s+(\S+)\s+")
RE_ISO = re.compile(r"^\d{4}-\d\d-\d\d[T ]\S+\s+(\S+)\s+")
RE_TOPICS = re.compile(r"^([A-Za-z0-9_\-]+(?:,[A-Za-z0-9_\-]+)+)\s+(.*)$", re.S)
RE_FW = re.compile(
    r"^(?:(?P<prefix>.*?)\s+)?(?P<chain>[\w\-.]+):\s+in:(?P<in>\([^)]*\)|[^\s,]*)"
    r"\s+out:(?P<out>\([^)]*\)|[^\s,]*)(?P<rest>.*)$", re.S)
RE_CMARK = re.compile(r"connection-mark:(\S+?)(?:,\s|\s|$)")
RE_CSTATE = re.compile(r"connection-state:(\S+?)(?:,\s|\s|$)")
RE_CNAT = re.compile(r"connection-nat-state:(\S+?)(?:,\s|\s|$)")
RE_MAC = re.compile(r"src-mac\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")
RE_PROTO = re.compile(r"proto\s+([\w\-]+)(?:\s+\(([^)]*)\))?")
RE_ADDR = re.compile(r"([^\s,]+)->([^\s,]+)")
RE_LEN = re.compile(r"\blen\s+(\d+)")


def _split_addr(a: str):
    if a.startswith("["):
        host, _, port = a[1:].partition("]")
        port = port[1:] if port.startswith(":") else ""
        return host, int(port) if port.isdigit() else None
    if a.count(":") == 1:
        host, port = a.split(":")
        return host, int(port) if port.isdigit() else None
    return a, None


@lru_cache(maxsize=16384)
def _is_global(ip: str):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return None


def _scope(src, dst):
    a, b = _is_global(src), _is_global(dst)
    if a is None or b is None:
        return None
    if a and not b:
        return "entrante"
    if not a and b:
        return "saliente"
    if not a and not b:
        return "interno"
    return "externo"


def _parse_fw(body: str, e: dict) -> bool:
    m = RE_FW.match(body)
    if not m:
        return False
    if m.group("prefix"):
        e["prefix"] = m.group("prefix").strip()
    e["chain"] = m.group("chain")
    for key, grp in (("in_if", "in"), ("out_if", "out")):
        v = m.group(grp)
        if v and v != "(none)":
            e[key] = v
    rest = m.group("rest") or ""
    main = rest
    k = rest.find(", NAT ")
    if k != -1:
        after = rest[k + 6:]
        j = after.find(", len ")
        e["nat"] = (after[:j] if j != -1 else after).strip()
        main = rest[:k] + (after[j:] if j != -1 else "")
    for key, rx in (("conn_mark", RE_CMARK), ("conn_state", RE_CSTATE), ("conn_nat_state", RE_CNAT)):
        mm = rx.search(main)
        if mm:
            e[key] = mm.group(1)
    mm = RE_MAC.search(main)
    if mm:
        e["src_mac"] = mm.group(1).upper()
    mm = RE_PROTO.search(main)
    if mm:
        e["proto"] = mm.group(1).upper()
        if mm.group(2):
            e["proto_info"] = mm.group(2).strip()
    mm = RE_ADDR.search(main)
    if mm:
        sip, sport = _split_addr(mm.group(1))
        dip, dport = _split_addr(mm.group(2))
        e["src_ip"], e["dst_ip"] = sip, dip
        if sport is not None:
            e["src_port"] = sport
        if dport is not None:
            e["dst_port"] = dport
        sc = _scope(sip, dip)
        if sc:
            e["scope"] = sc
    mm = RE_LEN.search(main)
    if mm:
        e["len"] = int(mm.group(1))
    return True


def parse_line(line: str, device_ip: str, ts: float):
    text = line.strip("\x00\r\n \t")
    if not text:
        return None
    device = device_ip
    m = RE_PRI.match(text)
    if m:
        text = text[m.end():]
    m = RE_BSD.match(text) or RE_ISO.match(text)
    if m:
        device = m.group(1)
        text = text[m.end():]
    text = text.strip()
    if not text:
        return None
    e = {"ts": round(ts, 3), "device": device, "raw": text[:MAX_RAW]}
    body = text
    m = RE_TOPICS.match(text)
    if m:
        topics = m.group(1).lower()
        body = m.group(2)
        e["topics"] = topics
        for t in topics.split(","):
            if t in LEVELS:
                e["level"] = t
                break
    if " in:" in body:
        _parse_fw(body, e)
    return e


def sanitize_entry(d):
    """Valida una entrada procedente de disco / importación (lista blanca de campos)."""
    if not isinstance(d, dict):
        return None
    try:
        ts = float(d.get("ts"))
    except (TypeError, ValueError):
        return None
    raw = d.get("raw")
    if not isinstance(raw, str) or not raw:
        return None
    e = {"ts": round(ts, 3)}
    for k in STR_FIELDS:
        v = d.get(k)
        if isinstance(v, str) and v:
            e[k] = v[:MAX_RAW]
    for k in INT_FIELDS:
        v = d.get(k)
        if isinstance(v, int) and not isinstance(v, bool):
            e[k] = v
    if isinstance(d.get("id"), int) and not isinstance(d.get("id"), bool):
        e["id"] = d["id"]
    return e


# ----------------------------------------------------------------------------
# Motor de filtros (condiciones, lenguaje de búsqueda, reglas)
# ----------------------------------------------------------------------------
def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


@lru_cache(maxsize=16384)
def _ip_obj(v):
    try:
        return ipaddress.ip_address(v)
    except ValueError:
        return None


def _ftype(field):
    if field in NUM_FIELDS:
        return "num"
    if field in IP_FIELDS:
        return "ip"
    return "txt"


def _make_test(op, val, fields):
    ftype = _ftype(fields[0])
    sval = str(val).strip()
    low = sval.lower()

    if op == "exists":
        return lambda v: v not in (None, "")
    if sval == "":
        raise ValueError("Condición sin valor")

    if ftype == "ip" and "/" in sval and op in ("eq", "contains"):
        op = "cidr"

    if op == "contains":
        return lambda v: v is not None and low in str(v).lower()
    if op == "eq":
        if ftype == "num":
            n = _num(sval)
            if n is None:
                raise ValueError(f"Valor numérico inválido: {sval}")
            return lambda v: v is not None and _num(v) == n
        if fields[0] == "topics":
            return lambda v: v is not None and low in v.split(",")
        return lambda v: v is not None and str(v).lower() == low
    if op == "starts":
        return lambda v: v is not None and str(v).lower().startswith(low)
    if op == "ends":
        return lambda v: v is not None and str(v).lower().endswith(low)
    if op == "regex":
        try:
            rx = re.compile(sval, re.I)
        except re.error as ex:
            raise ValueError(f"Regex inválida: {ex}")
        return lambda v: v is not None and rx.search(str(v)) is not None
    if op in ("cidr", "in"):
        items = [x.strip() for x in re.split(r"[,\n;]+", sval) if x.strip()]
        if not items:
            raise ValueError("Lista vacía")
        nets, exact = [], set()
        for it in items:
            if ftype == "ip" and ("/" in it or op == "cidr"):
                try:
                    nets.append(ipaddress.ip_network(it, strict=False))
                except ValueError:
                    raise ValueError(f"Red/IP inválida: {it}")
            elif ftype == "num":
                n = _num(it)
                if n is None:
                    raise ValueError(f"Valor numérico inválido: {it}")
                exact.add(n)
            else:
                exact.add(it.lower())
        if ftype == "num":
            return lambda v: v is not None and _num(v) in exact

        def t(v):
            if v is None:
                return False
            if str(v).lower() in exact:
                return True
            if nets:
                ip = _ip_obj(v)
                return ip is not None and any(ip in n for n in nets)
            return False
        return t
    if op in ("gt", "gte", "lt", "lte"):
        n = _num(sval)
        if n is None:
            raise ValueError(f"Valor numérico inválido: {sval}")
        cmp = {"gt": lambda a: a > n, "gte": lambda a: a >= n,
               "lt": lambda a: a < n, "lte": lambda a: a <= n}[op]
        return lambda v: (lambda a: a is not None and cmp(a))(_num(v))
    raise ValueError(f"Operador desconocido: {op}")


def compile_cond(c):
    field = str(c.get("field") or "any").strip().lower()
    op = str(c.get("op") or "contains").strip().lower()
    neg = bool(c.get("not"))
    field = ALIASES.get(field, field)
    fields = GROUPS.get(field) or ((field,) if field in FIELD_SET else None)
    if not fields:
        raise ValueError(f"Campo desconocido: {field}")
    if op == "ne":
        op, neg = "eq", not neg
    elif op.startswith("not_"):
        op, neg = op[4:], not neg
    test = _make_test(op, c.get("value", ""), fields)

    def pred(e):
        hit = False
        for f in fields:
            if test(e.get(f)):
                hit = True
                break
        return (not hit) if neg else hit
    return pred


RE_TOKEN = re.compile(r"^([A-Za-z_]+)(!=|:|=|~)(.*)$")


def token_to_cond(tok):
    neg = False
    if len(tok) > 1 and tok[0] == "-":
        neg, tok = True, tok[1:]
    m = RE_TOKEN.match(tok)
    if m and m.group(1).lower() in KNOWN_NAMES:
        f, sep, v = m.group(1).lower(), m.group(2), m.group(3)
        fld = ALIASES.get(f, f)
        real = GROUPS[fld][0] if fld in GROUPS else fld
        ft = _ftype(real)
        if v == "":
            raise ValueError(f"Falta el valor en «{tok}»")
        op = "contains"
        if sep == "!=":
            neg, sep = (not neg), "="
        if sep == "=":
            op = "eq"
        elif sep == ":" and ft in ("num", "ip"):
            op = "eq"
        if v[:2] in (">=", "<="):
            op, v = ("gte" if v[:2] == ">=" else "lte"), v[2:]
        elif v[:1] in (">", "<"):
            op, v = ("gt" if v[0] == ">" else "lt"), v[1:]
        elif len(v) > 2 and v[0] == "/" and v[-1] == "/":
            op, v = "regex", v[1:-1]
        elif ft == "ip" and "/" in v:
            op = "cidr"
        elif op == "eq" and "," in v:
            op = "in"
        return {"field": f, "op": op, "value": v, "not": neg}
    if len(tok) > 2 and tok[0] == "/" and tok[-1] == "/":
        return {"field": "any", "op": "regex", "value": tok[1:-1], "not": neg}
    return {"field": "any", "op": "contains", "value": tok, "not": neg}


def parse_query(q):
    try:
        lex = shlex.shlex(q, posix=True)
        lex.whitespace_split = True
        lex.commenters = ""
        lex.escape = ""
        tokens = list(lex)
    except ValueError:
        tokens = q.split()
    return [token_to_cond(t) for t in tokens if t]


def compile_filter(body):
    conds = list(body.get("conditions") or [])
    q = (body.get("q") or "").strip()
    if q:
        conds.extend(parse_query(q))
    return [compile_cond(c) for c in conds]


def compile_rule(rule):
    preds = [compile_cond(c) for c in rule["conditions"]]
    if rule.get("match") == "any":
        return lambda e: any(p(e) for p in preds)
    return lambda e: all(p(e) for p in preds)


def clean_rule(b):
    name = str(b.get("name") or "").strip()[:80] or "Regla sin nombre"
    action = b.get("action")
    if action not in ("highlight", "exclude"):
        raise ValueError("Acción inválida (highlight | exclude)")
    mode = None
    if action == "exclude":
        mode = b.get("mode") or "drop"
        if mode not in ("drop", "hide"):
            raise ValueError("Modo inválido (drop | hide)")
    color = b.get("color") or DEFAULT_HL_COLOR
    if not COLOR_RE.match(str(color)):
        raise ValueError("Color inválido (usa #rrggbb)")
    conds = []
    for c in b.get("conditions") or []:
        cc = {"field": str(c.get("field") or "any")[:32],
              "op": str(c.get("op") or "contains")[:16],
              "value": str(c.get("value") if c.get("value") is not None else "")[:500]}
        if c.get("not"):
            cc["not"] = True
        compile_cond(cc)  # valida
        conds.append(cc)
    if not conds:
        raise ValueError("La regla necesita al menos una condición")
    return {"name": name, "action": action, "mode": mode, "color": str(color).lower(),
            "match": "any" if b.get("match") == "any" else "all",
            "enabled": bool(b.get("enabled", True)), "conditions": conds}


def clean_settings(b, cur):
    out = dict(cur)

    def ival(k, lo, hi, zero_ok=False):
        if k in b:
            try:
                v = int(b[k])
            except (TypeError, ValueError):
                raise ValueError(f"Valor inválido en {k}")
            out[k] = 0 if (zero_ok and v == 0) else max(lo, min(hi, v))

    ival("autosave_seconds", 1, 300)
    ival("rotate_size_mb", 1, 4096)
    ival("rotate_hours", 1, 8760, zero_ok=True)
    ival("retention_days", 1, 36500, zero_ok=True)
    ival("min_free_percent", 1, 50, zero_ok=True)
    if "low_disk_action" in b:
        if b["low_disk_action"] not in ("delete_oldest", "pause"):
            raise ValueError("low_disk_action debe ser delete_oldest o pause")
        out["low_disk_action"] = b["low_disk_action"]
    for k in ("capture_enabled", "compress_rotated"):
        if k in b:
            out[k] = bool(b[k])
    return out


# ----------------------------------------------------------------------------
# Almacén: segmentos NDJSON con rotación (sin backups)
#
#   data/logs/current.ndjson                       segmento activo (append; también en RAM)
#   data/logs/seg-<ini>-<fin>-<lastid>-<n>.ndjson[.gz]   segmentos rotados
#
# El nombre de cada segmento lleva su rango de fechas y nº de entradas, así que
# se puede filtrar por fecha y contar sin abrirlo. No hay tope de logs: lo único
# que acota el crecimiento es el espacio libre en disco (guard configurable).
# ----------------------------------------------------------------------------
SEG_RE = re.compile(r"^seg-(\d+)-(\d+)-(\d+)-(\d+)\.ndjson(\.gz)?$")
_ts_key = operator.itemgetter("ts")


class Segment:
    __slots__ = ("path", "name", "first", "last", "last_id", "count", "gz", "size")

    def __init__(self, path, first, last, last_id, count, gz, size):
        self.path, self.name = path, os.path.basename(path)
        self.first, self.last, self.last_id = first, last, last_id
        self.count, self.gz, self.size = count, gz, size


def _seg_filename(first_ts, last_ts, last_id, count, gz=False):
    # first = suelo, last = techo (exclusivo): el filtrado por fecha nunca pierde entradas
    return "seg-%d-%d-%d-%d.ndjson%s" % (int(first_ts), int(last_ts) + 1, last_id, count,
                                         ".gz" if gz else "")


def _dumps(e):
    return json.dumps(e, ensure_ascii=False, separators=(",", ":"))


class Store:
    def __init__(self, data_dir):
        self.dir = os.path.abspath(data_dir)
        self.logs_dir = os.path.join(self.dir, "logs")
        self.cur_path = os.path.join(self.logs_dir, "current.ndjson")
        self.cfg_path = os.path.join(self.dir, "config.json")
        os.makedirs(self.logs_dir, exist_ok=True)

        # Orden de bloqueo: seg_lock -> lock (nunca al revés).
        self.lock = threading.RLock()      # estado en RAM + escritura del segmento activo
        self.seg_lock = threading.RLock()  # cambios en segmentos rotados (comprimir/borrar/reescribir)
        self.cur = []                      # entradas del segmento activo
        self.cur_bytes = 0
        self._fh = None
        self.next_id = 1
        self.dirty = False
        self.unsaved_count = 0             # entradas escritas desde el último fsync
        self.cfg_dirty = False
        self.last_saved = None
        self.last_save_error = None
        self.warning = None
        self.write_error = None            # fallo de escritura (p. ej. disco lleno)
        self.low_disk = False              # el guard de espacio pausó la captura
        self.guard_note = None             # última acción del guard
        self.guard_freed = 0
        self._seg_cache = None
        self._compress_evt = threading.Event()
        self.compact_state = None          # progreso de la última compactación (o None)
        self.counters = dict(received=0, stored=0, dropped_rule=0, invalid=0, paused=0,
                             paused_disk=0, rotations=0, since=time.time())
        self.listener = dict(host=None, port=None, running=False, error=None)
        self._sec, self._sec_n, self._hist = int(time.time()), 0, deque(maxlen=30)
        self._drop, self._hide, self._hl = [], [], []

        self.cfg = self._load_cfg()
        self._compile_rules()
        self._recover_compaction()
        for n in os.listdir(self.logs_dir):          # restos de operaciones interrumpidas
            if n.endswith(".tmp"):
                try:
                    os.remove(os.path.join(self.logs_dir, n))
                except OSError:
                    pass
        self._migrate_legacy()
        self._load_current()

    # -- configuración ------------------------------------------------------
    def _load_cfg(self):
        cfg = {"v": 2, "settings": dict(DEFAULT_SETTINGS), "rules": [], "searches": []}
        if not os.path.exists(self.cfg_path):
            return cfg
        try:
            with open(self.cfg_path, "r", encoding="utf-8") as f:
                d = json.load(f)
            cfg["settings"].update({k: v for k, v in (d.get("settings") or {}).items()
                                    if k in DEFAULT_SETTINGS})
            if d.get("v") != 2:
                # versiones anteriores tenían tope de logs y retención de 30 días: ahora no hay límite
                cfg["settings"]["retention_days"] = 0
                self.cfg_dirty = True
            for r in d.get("rules") or []:
                try:
                    c = clean_rule(r)
                except (ValueError, AttributeError):
                    continue
                c["id"] = str(r.get("id") or uuid.uuid4().hex[:8])
                c["hits"] = int(r.get("hits") or 0)
                cfg["rules"].append(c)
            for s in d.get("searches") or []:
                if isinstance(s, dict) and s.get("name"):
                    s["id"] = str(s.get("id") or uuid.uuid4().hex[:8])
                    cfg["searches"].append(s)
        except Exception as ex:  # config corrupta
            bad = self.cfg_path + f".corrupt-{int(time.time())}"
            try:
                os.replace(self.cfg_path, bad)
            except OSError:
                pass
            self.warning = f"config.json ilegible ({ex}); se movió a {os.path.basename(bad)}"
            log.error(self.warning)
        return cfg

    def save_cfg(self):
        with self.lock:
            data = json.dumps(self.cfg, ensure_ascii=False, indent=1)
            self.cfg_dirty = False
        tmp = self.cfg_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.cfg_path)

    def _compile_rules(self):
        drop, hide, hl = [], [], []
        for r in self.cfg["rules"]:
            if not r.get("enabled", True):
                continue
            pred = compile_rule(r)
            if r["action"] == "highlight":
                hl.append((r, pred))
            elif r.get("mode") == "hide":
                hide.append((r, pred))
            else:
                drop.append((r, pred))
        self._drop, self._hide, self._hl = drop, hide, hl

    def hide_preds(self):
        with self.lock:
            return [p for _, p in self._hide]

    def hide_rules(self):
        with self.lock:
            return list(self._hide)

    def hl_rules(self):
        with self.lock:
            return list(self._hl)

    def update_settings(self, body):
        with self.lock:
            self.cfg["settings"] = clean_settings(body, self.cfg["settings"])
        self._compress_evt.set()
        self.save_cfg()
        return self.cfg["settings"]

    def add_rule(self, body):
        r = clean_rule(body)
        r["id"] = uuid.uuid4().hex[:8]
        r["hits"] = 0
        with self.lock:
            self.cfg["rules"].append(r)
            self._compile_rules()
        self.save_cfg()
        return r

    def update_rule(self, rid, body):
        r = clean_rule(body)
        with self.lock:
            for i, old in enumerate(self.cfg["rules"]):
                if old["id"] == rid:
                    r["id"], r["hits"] = rid, old.get("hits", 0)
                    self.cfg["rules"][i] = r
                    self._compile_rules()
                    break
            else:
                raise KeyError(rid)
        self.save_cfg()
        return r

    def delete_rule(self, rid):
        with self.lock:
            n = len(self.cfg["rules"])
            self.cfg["rules"] = [r for r in self.cfg["rules"] if r["id"] != rid]
            if len(self.cfg["rules"]) == n:
                raise KeyError(rid)
            self._compile_rules()
        self.save_cfg()

    def move_rule(self, rid, direction):
        with self.lock:
            rules = self.cfg["rules"]
            i = next((k for k, r in enumerate(rules) if r["id"] == rid), None)
            if i is None:
                raise KeyError(rid)
            j = i - 1 if direction == "up" else i + 1
            if 0 <= j < len(rules):
                rules[i], rules[j] = rules[j], rules[i]
                self._compile_rules()
        self.save_cfg()

    def rule_counts(self, hours=24):
        """Coincidencias por regla en las últimas `hours` horas (no en todo el histórico).
        Los segmentos rotados que caen enteros en la ventana se cuentan una vez (caché)."""
        with self.lock:
            rules = list(self.cfg["rules"])
        preds = [(r["id"], compile_rule(r)) for r in rules]
        sig = json.dumps([(r["id"], r.get("match"), r["conditions"]) for r in rules],
                         sort_keys=True, default=str)
        out = {rid: 0 for rid, _ in preds}
        t0 = time.time() - hours * 3600

        def count(entries):
            c = dict.fromkeys(out, 0)
            for e in entries:
                if e["ts"] < t0:
                    continue
                for rid, p in preds:
                    if p(e):
                        c[rid] += 1
            return c

        for group in self.snapshot(t0):
            for first, last, src in group:
                if isinstance(src, list) or first < t0:
                    c = count(self.read_source(src))
                else:
                    key = (_seg_key(src), sig)
                    c = RULES_CACHE.get(key)
                    if c is None:
                        c = count(self._read_segment(src))
                        RULES_CACHE.put(key, c, len(c) + 1)
                for rid, v in c.items():
                    out[rid] += v
        return out

    # -- segmentos -----------------------------------------------------------
    def segments(self):
        """Segmentos rotados, del más antiguo al más reciente."""
        found = {}
        try:
            names = os.listdir(self.logs_dir)
        except FileNotFoundError:
            return []
        for n in names:
            m = SEG_RE.match(n)
            if not m:
                continue
            gz = bool(m.group(5))
            base = n[:-3] if gz else n
            old = found.get(base)
            if old is not None and not (old.gz and not gz):
                continue  # si existen .ndjson y .ndjson.gz del mismo segmento, vale el completo
            p = os.path.join(self.logs_dir, n)
            try:
                size = os.path.getsize(p)
            except OSError:
                continue
            found[base] = Segment(p, int(m.group(1)), int(m.group(2)), int(m.group(3)),
                                  int(m.group(4)), gz, size)
        return sorted(found.values(), key=lambda s: (s.first, s.last_id))

    def _invalidate(self):
        self._seg_cache = None

    def _seg_info(self, max_age=10.0):
        now = time.time()
        c = self._seg_cache
        if c and now - c[0] < max_age:
            return c[1]
        segs = self.segments()
        info = dict(count=sum(s.count for s in segs), bytes=sum(s.size for s in segs),
                    segments=len(segs), plain=sum(1 for s in segs if not s.gz),
                    first_ts=min((s.first for s in segs), default=None),
                    last_ts=max((s.last for s in segs), default=None))
        self._seg_cache = (now, info)
        return info

    def list_segments(self):
        out = [{"name": s.name, "size": s.size, "first": s.first, "last": s.last,
                "count": s.count, "gz": s.gz} for s in self.segments()]
        out.reverse()
        return out

    def segment_path(self, name):
        if not SEG_RE.match(name or ""):
            raise ValueError("Nombre de segmento inválido")
        p = os.path.join(self.logs_dir, name)
        if not os.path.isfile(p):
            raise FileNotFoundError(name)
        return p

    def delete_segment(self, name):
        """Borra un único segmento rotado (nunca el activo). Irreversible: no hay backup."""
        if not SEG_RE.match(name or ""):
            raise ValueError("Nombre de segmento inválido")
        with self.seg_lock:
            seg = next((s for s in self.segments() if s.name == name), None)
            if seg is None:
                raise FileNotFoundError(name)
            self._remove_seg_files(seg)
            self._invalidate()
        return seg.count

    @staticmethod
    def _read_segment(seg, keep=None):
        """Entradas del segmento en orden de archivo. `keep(línea)` es un prefiltro barato sobre
        el texto: las líneas que descarta no se llegan a decodificar."""
        opener = gzip.open if seg.gz else open
        try:
            with opener(seg.path, "rt", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if len(line) < 3 or (keep is not None and not keep(line)):
                        continue
                    try:
                        e = _loads(line)
                    except ValueError:
                        continue
                    if isinstance(e, dict) and "ts" in e:
                        yield e
        except FileNotFoundError:
            return  # rotado/borrado mientras se leía
        except (OSError, EOFError) as ex:
            log.warning("Segmento ilegible o truncado %s: %s", seg.path, ex)

    def read_source(self, src, keep=None):
        """Una fuente es un Segment rotado o la lista (foto) del segmento activo."""
        return iter(src) if isinstance(src, list) else self._read_segment(src, keep)

    def snapshot(self, t0=None, t1=None):
        """Fuentes que tocan [t0, t1] agrupadas en orden cronológico: [[(first, last, src), ...]].
        Dentro de un grupo las fuentes se solapan en fechas (importaciones) y hay que mezclarlas;
        grupos distintos no se solapan, así que se pueden recorrer uno a uno en cualquier sentido."""
        with self.lock:                      # foto consistente aunque rote a la vez
            cur = list(self.cur)
            segs = self.segments()
        items = []
        for s in segs:
            if (t0 is not None and s.last < t0) or (t1 is not None and s.first > t1):
                continue
            items.append((s.first, s.last, s))
        if cur:
            cf, cl = int(cur[0]["ts"]), int(cur[-1]["ts"]) + 1
            if not ((t0 is not None and cl < t0) or (t1 is not None and cf > t1)):
                items.append((cf, cl, cur))
        items.sort(key=lambda x: x[0])
        groups, gmax = [], None
        for it in items:
            if groups and it[0] < gmax:
                groups[-1].append(it)
                gmax = max(gmax, it[1])
            else:
                groups.append([it])
                gmax = it[1]
        return groups

    def iter_group(self, group, keep=None, match=None):
        """Entradas de un grupo en orden cronológico (mezcla por fecha si hay varias fuentes)."""
        its = []
        for _, _, src in group:
            it = self.read_source(src, keep)
            its.append(it if match is None else filter(match, it))
        return its[0] if len(its) == 1 else heapq.merge(*its, key=_ts_key)

    def iter_entries(self, t0=None, t1=None):
        """Entradas en orden cronológico, leyendo del disco solo los segmentos del rango.
        Memoria constante: nunca carga el histórico entero."""
        for group in self.snapshot(t0, t1):
            yield from self.iter_group(group)

    def bounds(self):
        info = self._seg_info()
        with self.lock:
            first = info["first_ts"] if info["first_ts"] is not None else \
                (self.cur[0]["ts"] if self.cur else None)
            last = self.cur[-1]["ts"] if self.cur else info["last_ts"]
        return first, last

    # -- segmento activo -----------------------------------------------------
    def _open_fh(self):
        need_nl = False
        try:
            if os.path.getsize(self.cur_path) > 0:
                with open(self.cur_path, "rb") as f:
                    f.seek(-1, os.SEEK_END)
                    need_nl = f.read(1) != b"\n"
        except OSError:
            pass
        self._fh = open(self.cur_path, "a", encoding="utf-8", buffering=1 << 20)
        if need_nl:  # última línea cortada por un apagón: que la siguiente no se pegue a ella
            self._fh.write("\n")

    def _close_fh(self):
        fh, self._fh = self._fh, None
        if fh:
            try:
                fh.flush()
                fh.close()
            except Exception:
                pass

    def _rewrite_current_locked(self):
        """Reescribe el segmento activo desde RAM. Requiere self.lock."""
        self._close_fh()
        tmp = self.cur_path + ".tmp"
        size = 0
        with open(tmp, "w", encoding="utf-8") as f:
            for e in self.cur:
                line = _dumps(e)
                f.write(line)
                f.write("\n")
                size += len(line) + 1
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.cur_path)
        self.cur_bytes = size
        self.dirty = False
        self.unsaved_count = 0
        self._open_fh()

    def _load_current(self):
        entries, bad = [], 0
        try:
            with open(self.cur_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        d = json.loads(line)
                        if not isinstance(d, dict) or "ts" not in d or "id" not in d:
                            raise ValueError
                    except ValueError:
                        bad += 1
                        continue
                    entries.append(d)
        except FileNotFoundError:
            pass
        self.cur = entries
        top = max([e["id"] for e in entries] + [s.last_id for s in self.segments()] + [0])
        self.next_id = top + 1
        if bad:
            self.warning = (f"{bad} línea(s) ilegibles en current.ndjson (¿corte de energía?); "
                            "se omitieron.")
            log.warning(self.warning)
            with self.lock:
                self._rewrite_current_locked()
        else:
            try:
                self.cur_bytes = os.path.getsize(self.cur_path)
            except OSError:
                self.cur_bytes = 0
            self._open_fh()

    def _migrate_legacy(self):
        """Versión anterior: un único logs.json. Se convierte a segmento y se renombra."""
        p = os.path.join(self.dir, "logs.json")
        if not os.path.exists(p):
            return
        try:
            with open(p, "rb") as fb:
                magic = fb.read(2)
            opener = gzip.open if magic == b"\x1f\x8b" else open
            with opener(p, "rt", encoding="utf-8") as f:
                entries, _ = self.parse_payload(json.load(f))
            entries.sort(key=lambda e: e["ts"])
            nxt = max([s.last_id for s in self.segments()] + [0]) + 1
            for e in entries:                      # ids nuevos: nunca chocan con los existentes
                e["id"], nxt = nxt, nxt + 1
            if entries:
                self._write_segment(entries)
            os.replace(p, p + ".migrated")
            log.info("logs.json migrado a segmentos (%d entradas). Los backups antiguos ya no "
                     "se usan: puedes borrar %s", len(entries), os.path.join(self.dir, "backups"))
        except Exception as ex:
            self.warning = f"No se pudo migrar logs.json ({ex}); se deja sin tocar."
            log.error(self.warning)

    def _write_segment(self, entries):
        """Escribe `entries` (ordenadas por fecha) como un segmento rotado nuevo."""
        first, last = entries[0]["ts"], entries[-1]["ts"]
        name = _seg_filename(first, last, max(e["id"] for e in entries), len(entries))
        tmp = os.path.join(self.logs_dir, name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            for e in entries:
                f.write(_dumps(e))
                f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, os.path.join(self.logs_dir, name))
        self._invalidate()
        self._compress_evt.set()

    def _rotate_locked(self):
        """Cierra el segmento activo y abre uno nuevo. Requiere self.lock."""
        if not self.cur:
            return None
        try:
            self._fh.flush()
            os.fsync(self._fh.fileno())
        except Exception as ex:
            self._set_write_error(ex)
            return None
        self._close_fh()
        ts = [e["ts"] for e in self.cur]
        name = _seg_filename(min(ts), max(ts), self.cur[-1]["id"], len(self.cur))
        os.replace(self.cur_path, os.path.join(self.logs_dir, name))
        self.cur, self.cur_bytes = [], 0
        self._open_fh()
        self.counters["rotations"] += 1
        self.dirty = False
        self.unsaved_count = 0
        self._invalidate()
        self._compress_evt.set()
        log.info("Rotado segmento %s", name)
        return name

    def rotate_now(self):
        with self.lock:
            return self._rotate_locked()

    def _rotate_if_old(self):
        hours = self.cfg["settings"]["rotate_hours"]
        if not hours:
            return
        with self.lock:
            if self.cur and time.time() - self.cur[0]["ts"] >= hours * 3600:
                self._rotate_locked()

    def _set_write_error(self, ex):
        if not self.write_error:
            log.error("Error escribiendo en disco: %s (captura pausada hasta recuperar)", ex)
        self.write_error = str(ex)
        self.last_save_error = str(ex)

    # -- compresión de segmentos rotados -------------------------------------
    def compress_worker(self, stop):
        self._compress_evt.set()  # al arrancar, comprime lo que quedara pendiente
        while not stop.is_set():
            if self._compress_evt.wait(1.0):
                self._compress_evt.clear()
                try:
                    self._compress_pending()
                except Exception as ex:
                    log.error("Error comprimiendo segmentos: %s", ex)

    def _compress_pending(self):
        if not self.cfg["settings"]["compress_rotated"]:
            return
        with self.seg_lock:
            for seg in self.segments():
                if seg.gz:
                    continue
                gz_path = seg.path + ".gz"
                tmp = gz_path + ".tmp"
                try:
                    with open(seg.path, "rb") as fi, gzip.open(tmp, "wb", compresslevel=6) as fo:
                        shutil.copyfileobj(fi, fo, 1 << 20)
                    os.replace(tmp, gz_path)
                    os.remove(seg.path)
                    self._invalidate()
                except FileNotFoundError:
                    continue
                except OSError as ex:  # p. ej. sin espacio para el temporal
                    log.error("No se pudo comprimir %s: %s", seg.name, ex)
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass
                    break

    @staticmethod
    def _remove_seg_files(seg):
        for p in (seg.path, seg.path[:-3] if seg.gz else seg.path + ".gz"):
            try:
                os.remove(p)
            except OSError:
                pass

    # -- compactación de segmentos rotados -----------------------------------
    # Tras borrados por filtro, cambios de ajustes o rotaciones manuales quedan segmentos
    # diminutos. Compactar fusiona los consecutivos hasta el tamaño/antigüedad de rotación.
    # Cada lote se escribe a un temporal y se publica con un diario (compact.journal) para que
    # un corte a mitad no deje duplicados: al arrancar se termina de borrar lo que faltara.
    COMPACT_SLACK = 60   # s de tolerancia en la duración (la rotación por horas se comprueba cada 10 s)

    def _journal_path(self):
        return os.path.join(self.logs_dir, "compact.journal")

    def _remove_names(self, names, keep):
        for n in names:
            for p in (n, n[:-3] if n.endswith(".gz") else n + ".gz"):
                if p == keep:
                    continue
                try:
                    os.remove(os.path.join(self.logs_dir, p))
                except OSError:
                    pass

    def _recover_compaction(self):
        jp = self._journal_path()
        if not os.path.exists(jp):
            return
        try:
            with open(jp, "r", encoding="utf-8") as f:
                d = json.load(f)
            if os.path.exists(os.path.join(self.logs_dir, d["final"])):
                self._remove_names(d["members"], d["final"])
                log.warning("Compactación interrumpida completada al arrancar (%s)", d["final"])
        except Exception as ex:
            log.error("Diario de compactación ilegible: %s", ex)
        try:
            os.remove(jp)
        except OSError:
            pass

    @staticmethod
    def _plain_size(seg):
        """Tamaño descomprimido (gzip lo guarda en sus 4 últimos bytes, módulo 4 GiB)."""
        if not seg.gz:
            return seg.size
        try:
            with open(seg.path, "rb") as f:
                f.seek(-4, os.SEEK_END)
                return max(struct.unpack("<I", f.read(4))[0], seg.size)
        except (OSError, struct.error):
            return seg.size * 10

    def compact_plan(self):
        """Lotes de segmentos consecutivos que caben juntos en un segmento estándar."""
        st = self.cfg["settings"]
        limit = st["rotate_size_mb"] * 1048576
        span = st["rotate_hours"] * 3600
        batches, cur = [], []
        size = lo = hi = 0
        for seg in self.segments():
            ps = self._plain_size(seg)
            if cur and size + ps <= limit and \
                    (not span or max(hi, seg.last) - min(lo, seg.first) <= span + self.COMPACT_SLACK):
                cur.append(seg)
                size, lo, hi = size + ps, min(lo, seg.first), max(hi, seg.last)
                continue
            if len(cur) > 1:
                batches.append(cur)
            cur, size, lo, hi = [seg], ps, seg.first, seg.last
        if len(cur) > 1:
            batches.append(cur)
        return batches

    def _merge_segments(self, batch):
        """Fusiona `batch` en un único segmento. Requiere seg_lock. Devuelve el nombre nuevo."""
        gz = self.cfg["settings"]["compress_rotated"]
        tmp = os.path.join(self.logs_dir, "compact-%s.tmp" % uuid.uuid4().hex[:8])
        n = last_id = 0
        lo = hi = None
        try:
            with open(tmp, "wb") as raw:
                fo = gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=6) if gz else raw
                buf = []
                for e in heapq.merge(*(self._read_segment(s) for s in batch), key=_ts_key):
                    buf.append(_dumps(e))
                    n += 1
                    ts = e["ts"]
                    lo = ts if lo is None or ts < lo else lo
                    hi = ts if hi is None or ts > hi else hi
                    i = e.get("id")
                    if isinstance(i, int) and i > last_id:
                        last_id = i
                    if len(buf) >= 4096:
                        fo.write(("\n".join(buf) + "\n").encode("utf-8"))
                        buf = []
                if buf:
                    fo.write(("\n".join(buf) + "\n").encode("utf-8"))
                if gz:
                    fo.close()
                raw.flush()
                os.fsync(raw.fileno())
        except BaseException:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise
        members = [s.name for s in batch]
        if n == 0:
            os.remove(tmp)
            self._remove_names(members, None)
            return None
        name = _seg_filename(lo, hi, last_id, n, gz)
        jp = self._journal_path()
        with open(jp, "w", encoding="utf-8") as f:
            json.dump({"final": name, "members": members}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, os.path.join(self.logs_dir, name))
        self._remove_names(members, name)
        os.remove(jp)
        return name

    def start_compaction(self):
        with self.seg_lock:
            if self.compact_state and self.compact_state.get("running"):
                raise ValueError("Ya hay una compactación en curso")
            batches = self.compact_plan()
            n_in = sum(len(b) for b in batches)
            self.compact_state = dict(running=bool(batches), total=len(batches), done=0,
                                      segments_in=n_in, segments_out=0, error=None,
                                      started=time.time(), finished=None if batches else time.time())
        if batches:
            threading.Thread(target=self._compact_run, args=(batches,), daemon=True,
                             name="compact").start()
        return dict(self.compact_state)

    def _compact_run(self, batches):
        st = self.compact_state
        try:
            for batch in batches:
                pct = self.cfg["settings"]["min_free_percent"]
                d = self.disk_info()
                if pct and d and d["free_pct"] < pct:
                    st["error"] = "Detenida: poco espacio libre en disco"
                    break
                with self.seg_lock:
                    live = {x.name for x in self.segments()}
                    if all(x.name in live for x in batch):  # nadie los ha borrado/reescrito
                        if self._merge_segments(batch):
                            st["segments_out"] += 1
                        self._invalidate()
                    else:
                        st["segments_out"] += sum(1 for x in batch if x.name in live)
                st["done"] += 1
            log.info("Compactación: %d segmentos -> %d", st["segments_in"], st["segments_out"])
        except Exception as ex:
            st["error"] = str(ex)
            log.error("Error compactando segmentos: %s", ex)
        finally:
            self._invalidate()
            self._compress_evt.set()
            st["running"] = False
            st["finished"] = time.time()

    # -- espacio en disco ----------------------------------------------------
    def disk_info(self):
        try:
            u = shutil.disk_usage(self.dir)
        except OSError:
            return None
        return {"total": u.total, "used": u.used, "free": u.free,
                "free_pct": round(100.0 * u.free / u.total, 2) if u.total else 100.0}

    def _free_space(self, target_pct):
        """Borra los segmentos rotados más antiguos hasta llegar a target_pct de espacio libre.
        Nunca toca el segmento activo."""
        n = freed = 0
        with self.seg_lock:
            for seg in self.segments():
                d = self.disk_info()
                if d is None or d["free_pct"] >= target_pct:
                    break
                self._remove_seg_files(seg)
                n += 1
                freed += seg.size
            if n:
                self._invalidate()
        if n:
            self.guard_freed += freed
            self.guard_note = (f"{datetime.now():%Y-%m-%d %H:%M} · borrados {n} segmento(s) "
                               f"antiguo(s), {freed / 1048576:.0f} MB, por poco espacio libre")
            log.warning(self.guard_note)
        return n

    def check_disk(self):
        s = self.cfg["settings"]
        pct = s["min_free_percent"]
        d = self.disk_info()
        if d is None:
            return
        if not pct:
            if self.low_disk:
                self.guard_note = (f"{datetime.now():%Y-%m-%d %H:%M} · guard de disco desactivado; "
                                   "captura reanudada")
            self.low_disk = False
        elif d["free_pct"] < pct:
            if s["low_disk_action"] == "delete_oldest":
                self._free_space(pct + 1.0)
                d = self.disk_info() or d
            low = d["free_pct"] < pct
            if low and not self.low_disk:
                self.guard_note = (f"{datetime.now():%Y-%m-%d %H:%M} · captura PAUSADA: "
                                   f"queda {d['free_pct']}% libre (mínimo {pct}%)")
                log.error(self.guard_note)
            self.low_disk = low
        elif self.low_disk and d["free_pct"] >= pct + 1.0:  # histéresis
            self.low_disk = False
            self.guard_note = f"{datetime.now():%Y-%m-%d %H:%M} · captura reanudada (espacio recuperado)"
            log.info(self.guard_note)
        if self.write_error and not self.low_disk:
            try:
                with self.lock:
                    self._rewrite_current_locked()  # vuelve a persistir lo que quedó solo en RAM
                self.write_error = None
                self.last_save_error = None
                log.info("Escritura en disco recuperada")
            except OSError:
                pass

    def enforce_retention(self):
        """Retención opcional (0 = sin límite). Borra segmentos rotados enteros más viejos que N días."""
        days = self.cfg["settings"]["retention_days"]
        if not days:
            return 0
        cutoff = time.time() - days * 86400
        n = 0
        with self.seg_lock:
            for seg in self.segments():
                if seg.last < cutoff:
                    self._remove_seg_files(seg)
                    n += seg.count
            if n:
                self._invalidate()
        return n

    # -- logs ----------------------------------------------------------------
    def _tick(self, now):
        s = int(now)
        if s != self._sec:
            self._hist.append((self._sec, self._sec_n))
            self._sec, self._sec_n = s, 0
        self._sec_n += 1

    def ingest(self, line, addr):
        now = time.time()
        with self.lock:
            self.counters["received"] += 1
            self._tick(now)
            if not self.cfg["settings"]["capture_enabled"]:
                self.counters["paused"] += 1
                return
            if self.low_disk or self.write_error:
                self.counters["paused_disk"] += 1
                return
        e = parse_line(line, addr, now)
        if e is None:
            with self.lock:
                self.counters["invalid"] += 1
            return
        with self.lock:
            for rule, pred in self._drop:
                if pred(e):
                    rule["hits"] = rule.get("hits", 0) + 1
                    self.cfg_dirty = True
                    self.counters["dropped_rule"] += 1
                    return
            e["id"] = self.next_id
            self.next_id += 1
            self.cur.append(e)
            self.counters["stored"] += 1
            try:
                line = _dumps(e)
                self._fh.write(line)
                self._fh.write("\n")
                self.cur_bytes += len(line) + 1
                self.dirty = True
                self.unsaved_count += 1
            except (OSError, ValueError, AttributeError) as ex:
                self._set_write_error(ex)
                return
            if self.cur_bytes >= self.cfg["settings"]["rotate_size_mb"] * 1048576:
                self._rotate_locked()

    def save_logs(self, force=False):
        """Vuelca el búfer a disco (flush + fsync)."""
        with self.lock:
            if not (self.dirty or force):
                return True
            try:
                self._fh.flush()
                os.fsync(self._fh.fileno())
                self.dirty = False
                self.unsaved_count = 0
                self.last_saved = time.time()
                if not self.write_error:
                    self.last_save_error = None
                return True
            except Exception as ex:
                self._set_write_error(ex)
                return False

    # -- borrado -------------------------------------------------------------
    def _rewrite_segment(self, seg, pred):
        """Reescribe un segmento sin las entradas que cumplen pred. Devuelve nº borradas."""
        kept = deleted = 0
        ts_lo = ts_hi = None
        last_id = 0
        tmp = seg.path + ".rw.tmp"
        opener = (lambda p: gzip.open(p, "wt", encoding="utf-8", compresslevel=6)) if seg.gz \
            else (lambda p: open(p, "w", encoding="utf-8"))
        with opener(tmp) as fo:
            for e in self._read_segment(seg):
                if pred(e):
                    deleted += 1
                    continue
                fo.write(_dumps(e))
                fo.write("\n")
                kept += 1
                ts = e["ts"]
                ts_lo = ts if ts_lo is None else min(ts_lo, ts)
                ts_hi = ts if ts_hi is None else max(ts_hi, ts)
                last_id = max(last_id, e.get("id", 0))
        if deleted == 0:
            os.remove(tmp)
            return 0
        if kept == 0:
            os.remove(tmp)
            self._remove_seg_files(seg)
        else:
            new = os.path.join(self.logs_dir, _seg_filename(ts_lo, ts_hi, last_id, kept, seg.gz))
            os.replace(tmp, new)
            if new != seg.path:
                os.remove(seg.path)
        return deleted

    def purge(self, pred=None, older_than=None, t0=None, t1=None):
        """Borra entradas. `older_than`: todo lo anterior a esa fecha. `pred`: función sobre la
        entrada (t0/t1 acotan qué segmentos hace falta abrir). Irreversible: no hay backups."""
        if older_than is not None:
            pred = lambda e: e["ts"] < older_than  # noqa: E731
            t1 = older_than
        deleted = 0
        with self.seg_lock:
            for seg in self.segments():
                if (t0 is not None and seg.last < t0) or (t1 is not None and seg.first > t1):
                    continue
                if older_than is not None and seg.last <= older_than:
                    self._remove_seg_files(seg)
                    deleted += seg.count
                else:
                    deleted += self._rewrite_segment(seg, pred)
            self._invalidate()
            with self.lock:
                keep = [e for e in self.cur if not pred(e)]
                n = len(self.cur) - len(keep)
                if n:
                    self.cur = keep
                    self._rewrite_current_locked()
                    deleted += n
        return deleted

    def delete_older_than(self, ts):
        return self.purge(older_than=ts)

    def clear(self):
        n = 0
        with self.seg_lock:
            for name in os.listdir(self.logs_dir):
                m = SEG_RE.match(name)
                if m:
                    if not name.endswith(".gz"):
                        n += int(m.group(4))
                    elif not os.path.exists(os.path.join(self.logs_dir, name[:-3])):
                        n += int(m.group(4))
                    try:
                        os.remove(os.path.join(self.logs_dir, name))
                    except OSError:
                        pass
            with self.lock:
                n += len(self.cur)
                self.cur = []
                self._rewrite_current_locked()
            self._invalidate()
        return n

    # -- importación ---------------------------------------------------------
    @staticmethod
    def parse_payload(d):
        if isinstance(d, dict):
            entries, next_id = d.get("entries"), d.get("next_id")
        elif isinstance(d, list):
            entries, next_id = d, None
        else:
            raise ValueError("Formato no reconocido")
        if not isinstance(entries, list):
            raise ValueError("El JSON no contiene una lista «entries»")
        out = [e for e in (sanitize_entry(x) for x in entries) if e]
        return out, next_id

    def import_entries(self, entries, mode="merge"):
        """Las entradas importadas se escriben como segmento propio. `replace` borra todo antes
        (irreversible). En `merge` se omiten duplicados (misma fecha y texto) del mismo rango."""
        if mode == "replace":
            self.clear()
        entries = sorted(entries, key=lambda e: e["ts"])
        seen = set()
        if mode != "replace" and entries:
            seen = {(e["ts"], e["raw"]) for e in self.iter_entries(entries[0]["ts"], entries[-1]["ts"])}
        fresh = []
        for e in entries:
            k = (e["ts"], e["raw"])
            if k in seen:
                continue
            seen.add(k)
            fresh.append(dict(e))
        if fresh:
            with self.lock:
                for e in fresh:
                    e["id"] = self.next_id
                    self.next_id += 1
            self._write_segment(fresh)
        return {"added": len(fresh), "skipped": len(entries) - len(fresh)}

    # -- estado --------------------------------------------------------------
    def status(self):
        now = time.time()
        info = self._seg_info()
        disk = self.disk_info()
        s = self.cfg["settings"]
        with self.lock:
            n_cur = len(self.cur)
            n = info["count"] + n_cur
            last_ts = self.cur[-1]["ts"] if n_cur else info["last_ts"]
            first_ts = info["first_ts"] if info["first_ts"] is not None else \
                (self.cur[0]["ts"] if n_cur else None)
            rate = sum(c for sec, c in self._hist if sec >= now - 10) / 10.0
            logs_bytes = info["bytes"] + self.cur_bytes
            st = {
                "entries": n, "last_id": self.next_id - 1,
                "last_ts": last_ts, "first_ts": first_ts,
                "rate": round(rate, 1), "counters": dict(self.counters),
                "dirty": self.dirty, "unsaved": self.unsaved_count, "last_saved": self.last_saved,
                "last_save_error": self.last_save_error,
                "capture_enabled": s["capture_enabled"],
                "listener": dict(self.listener), "warning": self.warning,
                "server_time": now, "data_dir": self.dir, "logs_dir": self.logs_dir,
                "storage": {
                    "segments": info["segments"], "uncompressed": info["plain"],
                    "rotated_bytes": info["bytes"], "cur_bytes": self.cur_bytes,
                    "cur_entries": n_cur, "logs_bytes": logs_bytes,
                    "rotate_bytes": s["rotate_size_mb"] * 1048576,
                },
                "guard": {"low_disk": self.low_disk, "write_error": self.write_error,
                          "note": self.guard_note, "freed_bytes": self.guard_freed},
                "compact": dict(self.compact_state) if self.compact_state else None,
            }
        if disk:
            st["disk"] = disk
            span = (last_ts - first_ts) if (first_ts and last_ts) else 0
            if span >= 6 * 3600 and logs_bytes > 0:   # con menos de 6 h la estimación no vale
                per_day = logs_bytes / (span / 86400.0)
                room = disk["free"] - disk["total"] * s["min_free_percent"] / 100.0
                st["storage"]["growth_per_day"] = int(per_day)
                st["storage"]["days_left"] = round(max(room, 0) / per_day, 1) if per_day else None
        return st

    def maintenance(self, stop):
        tick = 0
        while not stop.wait(1.0):
            tick += 1
            try:
                s = self.cfg["settings"]
                if self.dirty and time.time() - (self.last_saved or 0) >= s["autosave_seconds"]:
                    self.save_logs()
                if self.cfg_dirty and tick % 15 == 0:
                    self.save_cfg()
                if tick % 10 == 0:
                    self._rotate_if_old()
                    self.check_disk()
                if tick % 60 == 0:
                    self.enforce_retention()
            except Exception as ex:  # nunca matar el hilo
                log.error("Error en mantenimiento: %s", ex)


# ----------------------------------------------------------------------------
# Receptor syslog UDP
# ----------------------------------------------------------------------------
def syslog_loop(store, host, port, stop):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        except OSError:
            pass
        sock.bind((host, port))
    except OSError as ex:
        store.listener.update(host=host, port=port, running=False, error=str(ex))
        log.error("No se pudo abrir UDP %s:%s -> %s", host, port, ex)
        return
    store.listener.update(host=host, port=port, running=True, error=None)
    log.info("Escuchando syslog UDP en %s:%s", host, port)
    sock.settimeout(1.0)
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            text = data.decode("utf-8", "replace")
            for line in text.splitlines():
                if line.strip():
                    store.ingest(line, addr[0])
        except Exception as ex:
            log.error("Error procesando datagrama de %s: %s", addr[0], ex)
    sock.close()
    store.listener["running"] = False


# ----------------------------------------------------------------------------
# Consultas y analítica
# ----------------------------------------------------------------------------
def time_window(body, now=None):
    now = now or time.time()
    t0 = t1 = None
    rs = body.get("range_seconds")
    if rs:
        t0 = now - float(rs)
    else:
        if body.get("from") not in (None, ""):
            t0 = float(body["from"])
        if body.get("to") not in (None, ""):
            t1 = float(body["to"])
    return t0, t1


class LRU:
    """Caché LRU con peso (nº de claves que ocupa cada valor) y acceso concurrente."""

    def __init__(self, max_weight):
        self.d, self.w, self.max = OrderedDict(), 0, max_weight
        self.lock = threading.Lock()

    def get(self, k):
        with self.lock:
            v = self.d.get(k)
            if v is None:
                return None
            self.d.move_to_end(k)
            return v[0]

    def put(self, k, v, w=1):
        with self.lock:
            old = self.d.pop(k, None)
            if old is not None:
                self.w -= old[1]
            self.d[k] = (v, w)
            self.w += w
            while self.w > self.max and len(self.d) > 1:
                _, (_, ow) = self.d.popitem(last=False)
                self.w -= ow


# Los segmentos rotados no cambian: si cambian (borrado por filtro, compactación) cambia su nombre.
# Así que lo que se calcula sobre un segmento entero se puede reutilizar mientras exista.
COUNT_CACHE = LRU(500_000)       # (segmento, firma del filtro) -> nº de coincidencias
AGG_CACHE = LRU(1_500_000)       # (segmento, firma, ...) -> agregados recortados (peso ≈ claves)
RULES_CACHE = LRU(200_000)       # (segmento, firma de reglas) -> coincidencias por regla

LOGS_BUDGET = 3.0     # s por petición de la tabla: luego se devuelve lo que haya y se sigue después
STATS_BUDGET = 4.0    # s por petición de analítica


def _seg_key(seg):
    return seg.name[:-3] if seg.gz else seg.name   # comprimir no cambia el contenido


def _rules_sig(pairs):
    return [(r.get("name"), r.get("match"), r.get("conditions")) for r, _ in pairs]


def _cond_hint(c):
    """Texto (en minúsculas) que tiene que aparecer en la línea JSON para que la condición
    pueda cumplirse, o None si no se puede deducir. Permite descartar líneas sin decodificarlas."""
    if c.get("not"):
        return None
    op = str(c.get("op") or "contains").strip().lower()
    if op not in ("contains", "eq", "starts", "ends"):
        return None
    field = str(c.get("field") or "any").strip().lower()
    field = ALIASES.get(field, field)
    fields = GROUPS.get(field) or ((field,) if field in FIELD_SET else None)
    if not fields:
        return None
    v = str(c.get("value", "")).strip().lower()
    if not v or not v.isascii() or '"' in v or "\\" in v or any(ord(ch) < 32 for ch in v):
        return None
    ft = _ftype(fields[0])
    if ft == "num" and (fields[0] in ("ts", "id") or
                        (op == "eq" and not re.fullmatch(r"0|[1-9]\d*", v))):
        return None
    if ft == "ip" and "/" in v:      # CIDR
        return None
    return v


class Query:
    """Filtro compilado: match(e), ventana [t0, t1] y una firma estable (sin la ventana) para
    reutilizar resultados por segmento entre peticiones."""
    __slots__ = ("match", "t0", "t1", "sig", "trivial", "keep")


def make_query(store, body, window=None):
    conds = list(body.get("conditions") or [])
    qtext = (body.get("q") or "").strip()
    if qtext:
        conds.extend(parse_query(qtext))
    preds = [compile_cond(c) for c in conds]
    t0, t1 = window if window else time_window(body)
    hide_pairs = [] if body.get("show_hidden") else store.hide_rules()
    hide = [p for _, p in hide_pairs]
    only_hl = bool(body.get("only_highlighted"))
    hl_pairs = store.hl_rules() if only_hl else []
    hl = [p for _, p in hl_pairs]

    def match(e):
        ts = e["ts"]
        if t0 is not None and ts < t0:
            return False
        if t1 is not None and ts > t1:
            return False
        if hide and any(h(e) for h in hide):
            return False
        for p in preds:
            if not p(e):
                return False
        if only_hl and not any(h(e) for h in hl):
            return False
        return True

    q = Query()
    q.match, q.t0, q.t1 = match, t0, t1
    q.trivial = not preds and not hide and not only_hl
    q.sig = json.dumps([conds, _rules_sig(hide_pairs), only_hl, _rules_sig(hl_pairs)],
                       sort_keys=True, default=str)
    needles = [h for h in (_cond_hint(c) for c in conds) if h]
    if needles:
        def keep(line):
            low = line.lower()
            for n in needles:
                if n not in low:
                    return False
            return True
        q.keep = keep
    else:
        q.keep = None
    return q


def make_matcher(store, body, window=None):
    """Devuelve (match, t0, t1). match(e) aplica ventana temporal, reglas de ocultado y filtros."""
    q = make_query(store, body, window)
    return q.match, q.t0, q.t1


def iter_select(store, body, window=None):
    q = make_query(store, body, window)
    for group in store.snapshot(q.t0, q.t1):
        yield from store.iter_group(group, q.keep, q.match)


def _covered(q, first, last):
    """¿La fuente cae entera dentro de la ventana? (solo entonces su resultado es reutilizable)"""
    return (q.t0 is None or first >= q.t0) and (q.t1 is None or last <= q.t1)


def _known_count(q, item):
    first, last, src = item
    if isinstance(src, list) or not _covered(q, first, last):
        return None
    if q.trivial:
        return src.count
    return COUNT_CACHE.get((_seg_key(src), q.sig))


def _count_source(store, q, item):
    first, last, src = item
    n = _known_count(q, item)
    if n is None:
        n = sum(1 for e in store.read_source(src, q.keep) if q.match(e))
        if not isinstance(src, list) and _covered(q, first, last):
            COUNT_CACHE.put((_seg_key(src), q.sig), n)
    return n


def count_matches(store, q, deadline=None):
    """(nº de coincidencias, exacto). Con `deadline`, deja sin contar lo que no dé tiempo."""
    total, exact, scanned = 0, True, 0
    for group in store.snapshot(q.t0, q.t1):
        for item in group:
            n = _known_count(q, item)
            if n is None:
                if deadline is not None and scanned and time.monotonic() > deadline:
                    exact = False
                    continue
                n = _count_source(store, q, item)
                scanned += 1
            total += n
    return total, exact


def query_page(store, q, page, size, desc, budget=LOGS_BUDGET):
    """Página `page` de las coincidencias ordenadas por fecha, sin recorrer el histórico entero:
    los segmentos cuyo nº de coincidencias ya se conoce (metadatos o caché) se saltan sin abrirlos.
    Si se agota el presupuesto de tiempo devuelve lo que tenga con exact=False; la siguiente
    petición reaprovecha lo ya contado y avanza."""
    deadline = time.monotonic() + budget
    groups = store.snapshot(q.t0, q.t1)
    if desc:
        groups.reverse()
    lo, hi = (page - 1) * size, page * size
    offset, rows, exact, scanned = 0, [], True, 0
    for group in groups:
        counts = [_known_count(q, it) for it in group]
        n = None if None in counts else sum(counts)
        if n is not None and not (offset < hi and offset + n > lo):
            offset += n                       # ni se abre: solo suma
            continue
        if scanned and time.monotonic() > deadline:
            exact = False
            break
        scanned += 1
        if n is None:
            n = sum(_count_source(store, q, it) for it in group)
        if offset < hi and offset + n > lo:
            a, b = max(lo, offset) - offset, min(hi, offset + n) - offset
            if desc:
                a, b = n - b, n - a
            part = []
            for i, e in enumerate(store.iter_group(group, q.keep, q.match)):
                if i >= b:
                    break
                if i >= a:
                    part.append(e)
            if desc:
                part.reverse()
            rows.extend(part)
        offset += n
    return offset, exact, rows


# Tope de filas que se materializan en RAM para ordenar por una columna que no sea la fecha.
SORT_CAP = 200_000


def select_sorted(store, body, key, direction):
    """Materializa las filas que coinciden (con tope) y las ordena por una columna."""
    rows = []
    for e in iter_select(store, body):
        rows.append(e)
        if len(rows) > SORT_CAP:
            raise ValueError(f"Más de {SORT_CAP:,} resultados: para ordenar por «{key}» acota el "
                             "rango o el filtro (ordenar por fecha no tiene este límite)")
    return sort_entries(rows, key, direction)


@lru_cache(maxsize=16384)
def _ipkey(v):
    ip = _ip_obj(v)
    return (0, ip.version, int(ip)) if ip else (1, 0, 0)


def sort_entries(rows, key, direction):
    rev = direction != "asc"
    if key in (None, "", "ts", "id"):
        return rows[::-1] if rev else rows
    if key in NUM_FIELDS:
        kf = lambda e: (e.get(key) is None, e.get(key) or 0)
    elif key in IP_FIELDS:
        kf = lambda e: _ipkey(e.get(key)) if e.get(key) else (2, 0, 0)
    elif key in FIELD_SET:
        kf = lambda e: (e.get(key) is None, str(e.get(key) or "").lower())
    else:
        raise ValueError(f"No se puede ordenar por {key}")
    return sorted(rows, key=kf, reverse=rev)


BUCKETS = [1, 5, 10, 30, 60, 300, 600, 1800, 3600, 7200, 21600, 43200, 86400]


def _top(counter, n=15, bytes_counter=None, label=None):
    out = []
    for k, c in counter.most_common(n):
        d = {"k": k, "n": c}
        if bytes_counter is not None:
            d["b"] = bytes_counter.get(k, 0)
        if label:
            d["label"] = label(k)
        out.append(d)
    return out


TOP_CAP = 500_000   # tope de claves distintas por contador (protege la RAM en rangos enormes)


def _bump(c, k):
    if k in c:
        c[k] += 1
        return True
    if len(c) < TOP_CAP:
        c[k] = 1
        return True
    return False


_HIGH = ("src_ip", "dst_ip", "src_mac")   # alta cardinalidad: con tope
_LOW = ("proto", "prefix", "chain", "in_if", "out_if", "conn_state", "scope", "device")
_CNT_KEYS = _HIGH + _LOW + ("topics", "dst_port", "flags", "flows")


_UNIQ = ("src_ip", "dst_ip", "src_mac")
TRIM_K = 500        # claves por contador que se guardan de cada segmento en caché (sobra para top-15)
SKETCH_K = 1024     # tamaño del bosquejo KMV para estimar nº de distintos (error típico ~3 %)


def _agg_new():
    return {"n": 0, "first": None, "last": None, "bytes": 0, "tl": {}, "hl": 0,
            "rule_hits": Counter(), "hours": [0] * 24, "capped": False, "approx": False,
            "cnt": {k: Counter() for k in _CNT_KEYS}, "b_src": Counter(), "b_dst": Counter(),
            "sk": {k: [] for k in _UNIQ}}


def _h64(v):
    return int.from_bytes(hashlib.blake2b(str(v).encode(), digest_size=8).digest(), "big")


def _agg_trim(a):
    """Reduce un agregado para guardarlo en caché: se queda con el top-K de cada contador y, para
    los distintos de IP/MAC, con un bosquejo KMV (los K hashes más pequeños). Así la caché aguanta
    cientos de segmentos aunque cada uno tenga decenas de miles de IPs distintas."""
    cnt = a["cnt"]
    for k in _CNT_KEYS:
        c = cnt[k]
        if len(c) <= TRIM_K:
            continue
        if k in _UNIQ:
            a["sk"][k].append((tuple(heapq.nsmallest(SKETCH_K, map(_h64, c))), len(c) <= SKETCH_K))
        cnt[k] = Counter(dict(c.most_common(TRIM_K)))
        a["approx"] = True
    for kb, kc in (("b_src", "src_ip"), ("b_dst", "dst_ip")):
        keys = cnt[kc]
        a[kb] = Counter({ip: v for ip, v in a[kb].items() if ip in keys})
    return a


def _distinct(total, k):
    """Nº de valores distintos: exacto si ningún trozo se recortó; si no, estimación KMV."""
    parts = total["sk"][k]
    if not parts:
        return len(total["cnt"][k])
    hs = set(map(_h64, total["cnt"][k]))
    for h, _ in parts:
        hs.update(h)
    if all(ex for _, ex in parts) or len(hs) < SKETCH_K:
        return len(hs)
    kth = heapq.nsmallest(SKETCH_K, hs)[-1]
    return int((SKETCH_K - 1) * (2 ** 64) / (kth + 1))


def _agg_weight(a):
    return len(a["tl"]) + len(a["b_src"]) + len(a["b_dst"]) + \
        sum(len(c) for c in a["cnt"].values()) + sum(len(h) for p in a["sk"].values() for h, _ in p) // 8


def _agg_entries(entries, fine, hl_rules):
    """Agregados de analítica de un flujo de entradas (ya filtradas). Bucle caliente: todo en
    variables locales y sin llamadas evitables."""
    a = _agg_new()
    tl, cnt, hours, rule_hits = a["tl"], a["cnt"], a["hours"], a["rule_hits"]
    b_src, b_dst = a["b_src"], a["b_dst"]
    c_src, c_dst, c_mac, c_flows = cnt["src_ip"], cnt["dst_ip"], cnt["src_mac"], cnt["flows"]
    c_topics, c_dport, c_flags = cnt["topics"], cnt["dst_port"], cnt["flags"]
    low = [(f, cnt[f]) for f in _LOW]
    n = tot_bytes = hl_total = 0
    first = last = None
    capped = False
    hour_of = {}          # franja de 15 min -> hora local (todas las zonas horarias son múltiplo)
    localtime = time.localtime
    for e in entries:
        ts = e["ts"]
        n += 1
        if first is None or ts < first:
            first = ts
        if last is None or ts > last:
            last = ts
        get = e.get
        ln = get("len") or 0
        tot_bytes += ln
        k = int(ts // fine)
        cell = tl.get(k)
        if cell is None:
            cell = tl[k] = [0, 0, 0]
        cell[0] += 1
        cell[1] += ln
        if hl_rules:
            hit = False
            for r, p in hl_rules:
                if p(e):
                    rule_hits[r["name"]] += 1
                    hit = True
            if hit:
                hl_total += 1
                cell[2] += 1
        q = int(ts // 900)
        h = hour_of.get(q)
        if h is None:
            h = hour_of[q] = localtime(q * 900).tm_hour
        hours[h] += 1
        sip, dip = get("src_ip"), get("dst_ip")
        for v, c in ((sip, c_src), (dip, c_dst), (get("src_mac"), c_mac)):
            if v:
                if v in c:
                    c[v] += 1
                elif len(c) < TOP_CAP:
                    c[v] = 1
                else:
                    capped = True
        for f, c in low:
            v = get(f)
            if v:
                c[v] += 1
        v = get("topics")
        if v:
            for t in v.split(","):
                c_topics[t] += 1
        dport = get("dst_port")
        if dport is not None:
            c_dport[str(dport)] += 1
        if get("proto") == "TCP":
            v = get("proto_info")
            if v:
                c_flags[v] += 1
        if sip and dip:
            fk = (sip, dip, dport)
            if fk in c_flows:
                c_flows[fk] += 1
            elif len(c_flows) < TOP_CAP:
                c_flows[fk] = 1
            else:
                capped = True
            if sip in c_src:
                b_src[sip] += ln
            if dip in c_dst:
                b_dst[dip] += ln
    a.update(n=n, first=first, last=last, bytes=tot_bytes, hl=hl_total, capped=capped)
    return a


def _merge_capped(dst, src):
    if len(dst) + len(src) <= TOP_CAP:
        dst.update(src)
        return False
    capped = False
    for k, v in src.items():
        if k in dst:
            dst[k] += v
        elif len(dst) < TOP_CAP:
            dst[k] = v
        else:
            capped = True
    return capped


def _agg_merge(a, b):
    """Suma b en a (b no se modifica: puede venir de la caché)."""
    if not b["n"]:
        return
    a["n"] += b["n"]
    a["bytes"] += b["bytes"]
    a["hl"] += b["hl"]
    a["first"] = b["first"] if a["first"] is None else min(a["first"], b["first"])
    a["last"] = b["last"] if a["last"] is None else max(a["last"], b["last"])
    tl = a["tl"]
    for k, v in b["tl"].items():
        cell = tl.get(k)
        if cell is None:
            tl[k] = list(v)
        else:
            cell[0] += v[0]
            cell[1] += v[1]
            cell[2] += v[2]
    a["rule_hits"].update(b["rule_hits"])
    a["hours"] = [x + y for x, y in zip(a["hours"], b["hours"])]
    a["capped"] = a["capped"] or b["capped"]
    a["approx"] = a["approx"] or b["approx"]
    for k in _UNIQ:
        a["sk"][k].extend(b["sk"][k])
    for k in _CNT_KEYS:
        if k in _HIGH or k == "flows":
            if _merge_capped(a["cnt"][k], b["cnt"][k]):
                a["capped"] = True
        else:
            a["cnt"][k].update(b["cnt"][k])
    for kb, kc in (("b_src", "src_ip"), ("b_dst", "dst_ip")):
        keys = a["cnt"][kc]
        dst = a[kb]
        for ip, v in b[kb].items():
            if ip in keys:
                dst[ip] += v


def compute_stats(store, body, window, now, budget=STATS_BUDGET):
    """Analítica en streaming. Los segmentos rotados que caen enteros en la ventana se agregan una
    vez y se reutilizan (caché); si no da tiempo a todos, se devuelve un resultado parcial
    (`partial`) y la siguiente petición continúa donde lo dejó."""
    deadline = time.monotonic() + budget
    t0, t1 = window
    q = make_query(store, body, window)
    b_first, b_last = store.bounds()
    gstart = t0 if t0 is not None else (b_first if b_first is not None else now)
    gend = t1 if t1 is not None else (now if body.get("range_seconds") else
                                      (b_last if b_last is not None else now))
    gspan = max(gend - gstart, 1.0)
    fine = next((b for b in BUCKETS if gspan / b <= 20000), BUCKETS[-1])
    hl_rules = store.hl_rules()
    agg_sig = (q.sig, json.dumps(_rules_sig(hl_rules), sort_keys=True, default=str), fine)

    total = _agg_new()
    todo, n_cov = [], 0
    for group in store.snapshot(t0, t1):
        for first, last, src in group:
            if isinstance(src, list) or not _covered(q, first, last):   # activo / bordes: en vivo
                _agg_merge(total, _agg_entries(
                    (e for e in store.read_source(src, q.keep) if q.match(e)), fine, hl_rules))
                continue
            n_cov += 1
            key = (_seg_key(src),) + agg_sig
            cached = AGG_CACHE.get(key)
            if cached is not None:
                _agg_merge(total, cached)
            else:
                todo.append((key, src))
    pending = 0
    for i, (key, src) in enumerate(reversed(todo)):     # primero lo más reciente
        if i and time.monotonic() > deadline:
            pending = len(todo) - i
            break
        a = _agg_entries((e for e in store._read_segment(src, q.keep) if q.match(e)),
                         fine, hl_rules)
        COUNT_CACHE.put((key[0], q.sig), a["n"])
        _agg_trim(a)
        AGG_CACHE.put(key, a, _agg_weight(a) + 1)
        _agg_merge(total, a)

    n, first, last = total["n"], total["first"], total["last"]
    tot_bytes, hl_total, rule_hits = total["bytes"], total["hl"], total["rule_hits"]
    hours, cnt, capped = total["hours"], total["cnt"], total["capped"]
    b_src, b_dst, tl = total["b_src"], total["b_dst"], total["tl"]

    if n == 0:
        return {"total": 0, "partial": {"pending": pending, "of": n_cov} if pending else None}

    start = t0 if t0 is not None else first
    end = t1 if t1 is not None else (now if body.get("range_seconds") else last)
    span = max(end - start, 1.0)
    bsize = max(fine, next((b for b in BUCKETS if span / b <= 90), BUCKETS[-1]))
    base = math.floor(start / bsize) * bsize
    nb = max(min(int((end - base) // bsize) + 1, 400), 1)
    tl_n, tl_b, tl_h = [0] * nb, [0] * nb, [0] * nb
    for k, (c, bt, h) in tl.items():          # los cubos finos dividen exactamente a los finales
        i = min(max(int((k * fine - base) // bsize), 0), nb - 1)
        tl_n[i] += c
        tl_b[i] += bt
        tl_h[i] += h

    spikes = []
    if len(tl_n) >= 8:
        mean, sd = statistics.mean(tl_n), statistics.pstdev(tl_n)
        thr = max(mean + 3 * sd, 10)
        spikes = sorted(({"t": base + i * bsize, "n": c} for i, c in enumerate(tl_n) if c > thr),
                        key=lambda x: -x["n"])[:10]

    def svc(k):
        try:
            name = SERVICES.get(int(k))
        except ValueError:
            name = None
        return f"{k} ({name})" if name else k

    flows = [{"k": "%s|%s|%s" % (s, d, "" if p is None else p),
              "label": f"{s} → {d}" + (f":{p}" if p is not None else ""), "n": c}
             for (s, d, p), c in cnt["flows"].most_common(15)]

    prev_total = None
    if t0 is not None and end > t0 and not pending:
        dur = end - t0
        pn, exact = count_matches(store, make_query(store, body, (t0 - dur, t0)), deadline)
        prev_total = pn if exact else None

    return {
        "total": n, "first_ts": first, "last_ts": last, "span": span,
        "bytes": tot_bytes, "avg_len": round(tot_bytes / n, 1) if n else 0,
        "unique_src": _distinct(total, "src_ip"), "unique_dst": _distinct(total, "dst_ip"),
        "unique_macs": _distinct(total, "src_mac"), "capped": capped, "approx": total["approx"],
        "rate_per_min": round(n / (span / 60.0), 2),
        "peak": {"n": max(tl_n), "bucket": bsize,
                 "t": base + tl_n.index(max(tl_n)) * bsize},
        "highlighted": hl_total, "prev_total": prev_total,
        "bucket": bsize,
        "timeline": [{"t": base + i * bsize, "n": tl_n[i], "b": tl_b[i], "h": tl_h[i]}
                     for i in range(nb)],
        "hours": hours,
        "top": {
            "src_ip": _top(cnt["src_ip"], bytes_counter=b_src),
            "dst_ip": _top(cnt["dst_ip"], bytes_counter=b_dst),
            "dst_port": _top(cnt["dst_port"], label=svc),
            "proto": _top(cnt["proto"]), "flags": _top(cnt["flags"]),
            "prefix": _top(cnt["prefix"]), "chain": _top(cnt["chain"]),
            "in_if": _top(cnt["in_if"]), "out_if": _top(cnt["out_if"]),
            "conn_state": _top(cnt["conn_state"]), "src_mac": _top(cnt["src_mac"]),
            "scope": _top(cnt["scope"]), "device": _top(cnt["device"]),
            "topics": _top(cnt["topics"]), "flows": flows,
            "rules": _top(rule_hits),
        },
        "spikes": spikes,
        "partial": {"pending": pending, "of": n_cov} if pending else None,
    }


# ----------------------------------------------------------------------------
# Aplicación Flask
# ----------------------------------------------------------------------------
CSV_COLUMNS = ("ts_iso", "ts", "device", "topics", "level", "prefix", "chain", "in_if", "out_if",
               "proto", "proto_info", "src_ip", "src_port", "dst_ip", "dst_port", "src_mac",
               "conn_state", "conn_mark", "conn_nat_state", "nat", "len", "scope", "raw")


def _csv_safe(v):
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


def _csv_chunk(rows):
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    for e in rows:
        row = [datetime.fromtimestamp(e["ts"]).isoformat(sep=" ", timespec="seconds")]
        row += [_csv_safe(e.get(c, "")) for c in CSV_COLUMNS[1:]]
        w.writerow(row)
    return buf.getvalue()


def create_app(store, auth=None):
    app = Flask(__name__, static_folder=os.path.join(BASE_DIR, "static"), static_url_path="/static")
    app.config["MAX_CONTENT_LENGTH"] = 300 * 1024 * 1024
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

    @app.before_request
    def guard():
        if auth:
            a = request.authorization
            ok = a and hmac.compare_digest((a.username or "").encode(), auth[0].encode()) \
                and hmac.compare_digest((a.password or "").encode(), auth[1].encode())
            if not ok:
                return Response("Autenticación requerida", 401,
                                {"WWW-Authenticate": 'Basic realm="MikroTik Logs"'})
        if request.method not in ("GET", "HEAD", "OPTIONS") \
                and request.headers.get("X-Requested-With") != "fetch":
            return jsonify(error="Falta la cabecera X-Requested-With"), 403

    @app.errorhandler(ValueError)
    def on_value_error(ex):
        return jsonify(error=str(ex)), 400

    @app.errorhandler(KeyError)
    def on_key_error(ex):
        return jsonify(error="No encontrado"), 404

    @app.errorhandler(FileNotFoundError)
    def on_nf(ex):
        return jsonify(error="Archivo no encontrado"), 404

    @app.errorhandler(HTTPException)
    def on_http(ex):
        return jsonify(error=ex.description), ex.code

    @app.errorhandler(Exception)
    def on_error(ex):
        log.exception("Error no controlado")
        return jsonify(error=f"Error interno: {ex}"), 500

    @app.get("/")
    def index():
        return send_from_directory(app.static_folder, "index.html")

    @app.get("/api/status")
    def api_status():
        return jsonify(store.status())

    # ---- logs ----
    @app.post("/api/logs")
    def api_logs():
        b = request.get_json()
        size = max(10, min(1000, int(b.get("size") or 100)))
        want = max(1, int(b.get("page") or 1))
        key, direction = b.get("sort", "ts"), b.get("dir", "desc")
        exact = True
        if key in (None, "", "ts", "id"):
            q = make_query(store, b)
            desc = direction != "asc"
            total, exact, chunk = query_page(store, q, want, size, desc)
            page = want
            if exact:
                pages = max(1, (total + size - 1) // size)
                if want > pages:   # la página pedida ya no existe: la última (conteos ya en caché)
                    page = pages
                    total, exact, chunk = query_page(store, q, page, size, desc)
            pages = max(1, (total + size - 1) // size) if exact else None
        else:
            rows = select_sorted(store, b, key, direction)
            total = len(rows)
            pages = max(1, (total + size - 1) // size)
            page = min(want, pages)
            chunk = rows[(page - 1) * size: page * size]
        hl = store.hl_rules()
        out = []
        for e in chunk:
            d = dict(e)
            names, color = [], None
            for r, p in hl:
                if p(e):
                    names.append(r["name"])
                    color = color or r["color"]
            if names:
                d["hl"] = {"color": color, "names": names}
            out.append(d)
        return jsonify(total=total, exact=exact, page=page, pages=pages, size=size, entries=out)

    @app.post("/api/stats")
    def api_stats():
        b = request.get_json()
        now = time.time()
        return jsonify(compute_stats(store, b, time_window(b, now), now))

    @app.post("/api/export")
    def api_export():
        b = request.get_json()
        fmt = b.get("format", "json")
        if fmt not in ("json", "csv"):
            raise ValueError("Formato no soportado")
        match, t0, t1 = make_matcher(store, b)
        if b.get("all"):
            rows = store.iter_entries()
        else:
            rows = (e for e in store.iter_entries(t0, t1) if match(e))   # en streaming
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        if fmt == "csv":
            import csv
            import io

            def gen():
                buf = io.StringIO()
                w = csv.writer(buf)
                w.writerow(CSV_COLUMNS)
                yield buf.getvalue()
                batch = []
                for e in rows:
                    batch.append(e)
                    if len(batch) >= 1000:
                        yield _csv_chunk(batch)
                        batch = []
                if batch:
                    yield _csv_chunk(batch)
            return Response(gen(), mimetype="text/csv; charset=utf-8", headers={
                "Content-Disposition": f'attachment; filename="mikrotik-logs-{stamp}.csv"'})

        def gen_json():
            yield '{"version":2,"exported_at":%d,"entries":[\n' % int(time.time())
            first = True
            for e in rows:
                yield ("" if first else ",\n") + json.dumps(e, ensure_ascii=False, separators=(",", ":"))
                first = False
            yield "\n]}\n"
        return Response(gen_json(), mimetype="application/json", headers={
            "Content-Disposition": f'attachment; filename="mikrotik-logs-{stamp}.json"'})

    @app.post("/api/import")
    def api_import():
        f = request.files.get("file")
        if not f:
            raise ValueError("Falta el archivo")
        mode = request.form.get("mode", "merge")
        if mode not in ("merge", "replace"):
            raise ValueError("Modo inválido")
        raw = f.read()
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        try:
            d = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as ex:
            raise ValueError(f"JSON inválido: {ex}")
        entries, _ = Store.parse_payload(d)
        if not entries:
            raise ValueError("El archivo no contiene entradas válidas")
        res = store.import_entries(entries, mode)
        store.save_logs(force=True)
        return jsonify(res)

    @app.post("/api/purge")
    def api_purge():
        b = request.get_json()
        mode = b.get("mode")
        if mode not in ("older", "filter", "all"):
            raise ValueError("Modo inválido")
        if mode == "older":
            days = float(b.get("days") or 0)
            if days <= 0:
                raise ValueError("Indica un número de días > 0")
            n = store.delete_older_than(time.time() - days * 86400)
        elif mode == "filter":
            fb = dict(b.get("filter") or {})
            fb["show_hidden"] = True
            match, t0, t1 = make_matcher(store, fb)
            n = store.purge(pred=match, t0=t0, t1=t1)
        else:
            n = store.clear()
        store.save_logs(force=True)
        return jsonify(deleted=n)

    # ---- guardado / segmentos ----
    @app.post("/api/save")
    def api_save():
        ok = store.save_logs(force=True)
        return jsonify(ok=ok, error=store.last_save_error, status=store.status())

    @app.post("/api/rotate")
    def api_rotate():
        name = store.rotate_now()
        if not name:
            raise ValueError("No hay logs en el segmento activo")
        return jsonify(name=name)

    @app.get("/api/segments")
    def api_segments():
        return jsonify(store.list_segments())

    @app.get("/api/segments/<name>")
    def api_segment_get(name):
        return send_file(store.segment_path(name), as_attachment=True, download_name=name)

    @app.post("/api/segments/compact")
    def api_segments_compact():
        return jsonify(store.start_compaction())

    @app.delete("/api/segments/<name>")
    def api_segment_delete(name):
        n = store.delete_segment(name)
        return jsonify(deleted=n, name=name)

    # ---- configuración, reglas, búsquedas ----
    @app.get("/api/config")
    def api_config():
        return jsonify(settings=store.cfg["settings"], searches=store.cfg["searches"])

    @app.put("/api/config")
    def api_config_put():
        return jsonify(settings=store.update_settings(request.get_json()))

    @app.get("/api/rules")
    def api_rules():
        counts = store.rule_counts() if request.args.get("counts") else {}
        with store.lock:
            rules = [dict(r, matches=counts.get(r["id"])) for r in store.cfg["rules"]]
        return jsonify(rules)

    @app.post("/api/rules")
    def api_rules_add():
        return jsonify(store.add_rule(request.get_json())), 201

    @app.put("/api/rules/<rid>")
    def api_rules_put(rid):
        return jsonify(store.update_rule(rid, request.get_json()))

    @app.delete("/api/rules/<rid>")
    def api_rules_del(rid):
        store.delete_rule(rid)
        return jsonify(ok=True)

    @app.post("/api/rules/<rid>/move")
    def api_rules_move(rid):
        d = (request.get_json() or {}).get("dir")
        if d not in ("up", "down"):
            raise ValueError("dir debe ser up o down")
        store.move_rule(rid, d)
        return jsonify(ok=True)

    @app.post("/api/rules/test")
    def api_rules_test():
        r = clean_rule(request.get_json())
        pred = compile_rule(r)
        t0 = time.time() - 86400
        total = count = 0
        sample = deque(maxlen=5)
        for e in store.iter_entries(t0):
            if e["ts"] < t0:
                continue
            total += 1
            if pred(e):
                count += 1
                sample.append(e)
        return jsonify(count=count, of=total, sample=list(sample)[::-1], window_hours=24)

    @app.post("/api/searches")
    def api_searches_add():
        b = request.get_json()
        name = str(b.get("name") or "").strip()[:80]
        if not name:
            raise ValueError("Falta el nombre")
        s = {"id": uuid.uuid4().hex[:8], "name": name, "q": str(b.get("q") or "")[:1000],
             "conditions": b.get("conditions") or [], "range": b.get("range") or {},
             "show_hidden": bool(b.get("show_hidden")),
             "only_highlighted": bool(b.get("only_highlighted"))}
        compile_filter(s)  # valida
        with store.lock:
            store.cfg["searches"].append(s)
        store.save_cfg()
        return jsonify(s), 201

    @app.delete("/api/searches/<sid>")
    def api_searches_del(sid):
        with store.lock:
            store.cfg["searches"] = [s for s in store.cfg["searches"] if s["id"] != sid]
        store.save_cfg()
        return jsonify(ok=True)

    return app


# ----------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(description="MikroTik Log Viewer")
    p.add_argument("--syslog-host", default=os.environ.get("SYSLOG_HOST", "0.0.0.0"))
    p.add_argument("--syslog-port", type=int, default=int(os.environ.get("SYSLOG_PORT", 4501)))
    p.add_argument("--web-host", default=os.environ.get("WEB_HOST", "0.0.0.0"))
    p.add_argument("--web-port", type=int, default=int(os.environ.get("WEB_PORT", 8080)))
    p.add_argument("--data-dir", default=os.environ.get("DATA_DIR", os.path.join(BASE_DIR, "data")))
    args = p.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    store = Store(args.data_dir)
    log.info("Datos en %s (%d entradas en el segmento activo)", store.logs_dir, len(store.cur))

    stop = threading.Event()
    threading.Thread(target=syslog_loop, args=(store, args.syslog_host, args.syslog_port, stop),
                     daemon=True, name="syslog").start()
    threading.Thread(target=store.maintenance, args=(stop,), daemon=True, name="maint").start()
    threading.Thread(target=store.compress_worker, args=(stop,), daemon=True, name="compress").start()

    def shutdown(*_):
        stop.set()
        store.save_logs(force=True)
        if store.cfg_dirty:
            store.save_cfg()
        log.info("Guardado final completado")
        os._exit(0)

    signal.signal(signal.SIGTERM, shutdown)

    user, pw = os.environ.get("LOGVIEW_USER"), os.environ.get("LOGVIEW_PASS")
    auth = (user, pw) if user and pw else None
    if not auth and args.web_host not in ("127.0.0.1", "localhost", "::1"):
        log.warning("La web escucha en %s SIN autenticación. Define LOGVIEW_USER y LOGVIEW_PASS "
                    "o usa --web-host 127.0.0.1 detrás de un proxy.", args.web_host)

    app = create_app(store, auth)
    log.info("Web en http://%s:%s", args.web_host, args.web_port)
    try:
        try:
            from waitress import serve
            serve(app, host=args.web_host, port=args.web_port, threads=8, ident="mtlogs")
        except ImportError:
            app.run(host=args.web_host, port=args.web_port, threaded=True, use_reloader=False)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        store.save_logs(force=True)
        if store.cfg_dirty:
            store.save_cfg()


if __name__ == "__main__":
    main()
