"""Prueba de extremo a extremo: arranca app.py de verdad (UDP + web) y la usa con Chromium.
Se salta si Playwright no está instalado (pip install playwright && playwright install chromium)."""
import os
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

from conftest import make_entries, write_segment

sync_api = pytest.importorskip("playwright.sync_api")

import app  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def server(tmp_path):
    data = tmp_path / "data"
    st = app.Store(str(data))
    now = time.time()
    nid = 1
    for k in range(12):                       # 12 segmentos pequeños de las últimas horas
        write_segment(st, make_entries(200, now - 40000 + k * 3000, step=10, start_id=nid, seed=k))
        nid += 200
    st._close_fh()
    web, udp = free_port(socket.SOCK_STREAM), free_port(socket.SOCK_DGRAM)
    p = subprocess.Popen([sys.executable, os.path.join(ROOT, "app.py"), "--data-dir", str(data),
                          "--web-host", "127.0.0.1", "--web-port", str(web),
                          "--syslog-host", "127.0.0.1", "--syslog-port", str(udp)],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    url = f"http://127.0.0.1:{web}/"
    for _ in range(100):
        try:
            urllib.request.urlopen(url + "api/status", timeout=1)
            break
        except OSError:
            time.sleep(0.1)
    else:
        p.kill()
        raise AssertionError(p.stdout.read().decode())
    yield url, udp
    p.terminate()
    p.wait(10)


@pytest.fixture
def page():
    exe = os.environ.get("CHROMIUM_PATH") or ("/opt/pw-browsers/chromium" if os.path.exists("/opt/pw-browsers/chromium") else None)
    with sync_api.sync_playwright() as pw:
        b = pw.chromium.launch(executable_path=exe) if exe else pw.chromium.launch()
        pg = b.new_page(viewport={"width": 1400, "height": 900})
        errors = []
        pg.on("pageerror", lambda e: errors.append(str(e)))
        pg.errors = errors
        yield pg
        b.close()


def test_ui_end_to_end(server, page):
    url, udp = server
    page.goto(url)
    page.click('#f-ranges button[data-s="0"]')                     # rango «Todo»
    page.wait_for_function("/^2\\.?400 coincidencias/.test(document.querySelector('#logs-summary').textContent)")
    assert page.text_content("#pager-top span").strip() == "1 / 24"

    # llega un log por UDP y aparece en la tabla
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(b"system,info marcador-e2e", ("127.0.0.1", udp))
    page.fill("#f-q", "marcador-e2e")
    page.press("#f-q", "Enter")
    page.wait_for_function("/^1 coincidencias/.test(document.querySelector('#logs-summary').textContent)", timeout=15000)
    assert "marcador-e2e" in page.text_content("#logbody")

    # filtro sobre el histórico
    page.fill("#f-q", "dport:22")
    page.press("#f-q", "Enter")
    page.wait_for_function("/^[\\d.]+ coincidencias/.test(document.querySelector('#logs-summary').textContent)"
                           " && !/^1 coinc/.test(document.querySelector('#logs-summary').textContent)", timeout=30000)

    # analítica
    page.fill("#f-q", "")
    page.press("#f-q", "Enter")
    page.click('.tabs button[data-tab="analytics"]')
    page.wait_for_function("/^2\\.?401 logs ·/.test(document.querySelector('#an-summary').textContent)"
                           " && !/analizando/.test(document.querySelector('#an-summary').textContent)", timeout=60000)
    assert page.locator("#ch-tl rect.bar").count() > 0

    # ajustes: compactar los 12 segmentos
    page.click('.tabs button[data-tab="storage"]')
    page.wait_for_selector('button[data-act="compact"]')
    page.on("dialog", lambda d: d.accept())
    page.click('button[data-act="compact"]')
    page.wait_for_function("/Última compactación: 12 segmentos → 1/.test(document.querySelector('#compact-state')?.textContent || '')",
                           timeout=30000)
    page.wait_for_function("document.querySelectorAll('button[data-act=\"seg-del\"]').length === 1", timeout=10000)
    assert page.errors == []
