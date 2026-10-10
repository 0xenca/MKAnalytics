import socket
import threading
import time

import app


def test_udp_receiver(store):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    stop = threading.Event()
    t = threading.Thread(target=app.syslog_loop, args=(store, "127.0.0.1", port, stop), daemon=True)
    t.start()
    for _ in range(50):
        if store.listener["running"]:
            break
        time.sleep(0.02)
    assert store.listener["running"] and store.listener["port"] == port
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(b"<30>Oct 10 12:00:00 gw system,info hola\nfirewall,info input: in:e1 out:(none), "
                 b"proto UDP, 1.2.3.4:5->10.0.0.1:53, len 9", ("127.0.0.1", port))
    for _ in range(100):
        if len(store.cur) == 2:
            break
        time.sleep(0.02)
    stop.set()
    t.join(3)
    assert [e.get("device") for e in store.cur] == ["gw", "127.0.0.1"]
    assert store.cur[1]["dst_port"] == 53
    assert not store.listener["running"]


def test_udp_bind_error(store):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as busy:
        busy.bind(("127.0.0.1", 0))
        app.syslog_loop(store, "127.0.0.1", busy.getsockname()[1], threading.Event())
    assert store.listener["running"] is False and store.listener["error"]
