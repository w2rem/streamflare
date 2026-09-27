"""Streamflare — Cloudflare Tunnel, supervised from a Streamlit app.

Streamlit Cloud gives no shell and no systemd, so a tunnel has to be started
from inside the script and kept alive by a background thread. This is the
same shape the Go worker uses for tailscaled: download a client, run it with
the token, read its log back.

Everything renders in the page: status, public URL, and a live log tail. The
token is never printed — only its length.

Run it as a Streamlit app:

    streamlit run app.py

Env:
    TUNNEL_TOKEN     the run token from Zero Trust → Networks → Tunnels
    LOCAL_PORT       local port to expose (default 8080)
    ORIGIN_URL       explicit origin (default http://127.0.0.1:$LOCAL_PORT)
    BINDIR           where cloudflared is cached (default /tmp/bin)
    AUTOSTART        1 = start on first page load (default), 0 = manual
"""
from __future__ import annotations

import atexit
import os
import platform
import queue
import re
import shutil
import stat
import subprocess
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import streamlit as st

BASE_URL = "https://github.com/cloudflare/cloudflared/releases/latest/download"
ASSET = {
    "x86_64": "cloudflared-linux-amd64",
    "aarch64": "cloudflared-linux-arm64",
    "arm64": "cloudflared-linux-arm64",
    "amd64": "cloudflared-linux-amd64",
}
DEFAULT_PORT = int(os.environ.get("LOCAL_PORT", "8080") or 8080)
ORIGIN_URL = os.environ.get("ORIGIN_URL", f"http://127.0.0.1:{DEFAULT_PORT}").strip()
BINDIR = Path(os.environ.get("BINDIR", "/tmp/bin"))
TAIL_LINES = 200
# Registration is the signal that egress to Cloudflare works at all. Give up
# after this long rather than spinning a fragment forever.
REGISTER_TIMEOUT_S = 60

URL_RE = re.compile(r"https://[A-Za-z0-9._-]+")
HOST_RE = re.compile(r"hostname=([A-Za-z0-9._-]+)")


# ── client ────────────────────────────────────────────────────────────
def _asset_name() -> str:
    key = platform.machine().lower()
    if key not in ASSET:
        raise RuntimeError(f"unsupported architecture: {platform.machine()}")
    return ASSET[key]


def client_path() -> Path:
    return BINDIR / "cloudflared"


def ensure_client(progress) -> Path:
    """Download cloudflared without sudo into a user-writable directory.

    The asset is a RAW ELF BINARY, not a tarball — unpacking it with tar
    fails with "gzip: invalid magic". Guarding on the ELF magic also turns a
    captive-portal or 403 HTML page into a clear message instead of an
    exec format error.
    """
    path = client_path()
    if path.is_file() and os.access(path, os.X_OK):
        progress(f"cloudflared already present: {client_version(path)}")
        return path
    BINDIR.mkdir(parents=True, exist_ok=True)
    url = f"{BASE_URL}/{_asset_name()}"
    progress(f"downloading {_asset_name()} → {path}")
    tmp = path.with_suffix(".part")
    req = urllib.request.Request(url, headers={"User-Agent": "streamflare/1"})
    with urllib.request.urlopen(req, timeout=120) as resp, open(tmp, "wb") as fh:  # noqa: S310
        shutil.copyfileobj(resp, fh)
    if tmp.read_bytes()[:4] != b"\x7fELF":
        preview = tmp.read_bytes()[:200].decode("utf-8", "replace")
        tmp.unlink(missing_ok=True)
        raise RuntimeError(
            "the download was not an ELF binary — egress to GitHub releases "
            f"is returning an error page:\n{preview}")
    tmp.replace(path)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    progress(f"installed: {client_version(path)}")
    return path


def client_version(path: Path) -> str:
    try:
        out = subprocess.run([str(path), "--version"], capture_output=True,
                             text=True, timeout=20)
        return (out.stdout or out.stderr).strip().splitlines()[0]
    except (OSError, subprocess.SubprocessError, IndexError):
        return "version unknown"


# ── origin ────────────────────────────────────────────────────────────
def origin_alive(timeout: float = 2.0) -> bool:
    try:
        with urllib.request.urlopen(ORIGIN_URL, timeout=timeout) as resp:  # noqa: S310
            return 200 <= resp.status < 500
    except urllib.error.HTTPError as exc:
        # The service answered, it just dislikes the root path. That still
        # proves something is listening.
        return True
    except Exception:
        return False


# ── supervision ───────────────────────────────────────────────────────
@dataclass
class TunnelState:
    proc: subprocess.Popen | None = None
    lines: list[str] = field(default_factory=list)
    url: str = ""
    host: str = ""
    error: str = ""
    started_at: float = 0.0
    registered: bool = False
    drain: threading.Thread | None = None
    wanted: bool = False
    restarts: int = 0

    def tail(self) -> str:
        return "\n".join(self.lines[-TAIL_LINES:])


def keep_alive(state: TunnelState) -> None:
    """Restart a dead connector.

    Streamlit Cloud recycles containers and a tunnel silently drops its edge
    connections after idle periods. A connector that only runs until someone
    presses a button answers 502 for everything in between, which looks
    exactly like a broken tunnel. This runs on its own thread and restarts
    with a bounded backoff.
    """
    backoff = 3.0
    while True:
        time.sleep(2)
        try:
            if not state.wanted:
                continue
            if state.proc is not None and state.proc.poll() is None:
                backoff = 3.0
                continue
            if state.proc is not None:
                state.restarts += 1
                state.lines.append(
                    f"--- connector exited with {state.proc.returncode}; "
                    f"restart #{state.restarts} in {backoff:.0f}s ---")
                state.registered = False
                state.proc = None
            time.sleep(backoff)
            fresh = start()
            fresh.wanted = True
            state.proc = fresh.proc
            state.url = fresh.url
            state.host = fresh.host
            state.error = fresh.error
            state.registered = fresh.registered
            state.drain = fresh.drain
            if fresh.error:
                state.lines.append(f"restart failed: {fresh.error}")
            backoff = min(backoff * 1.6, 60.0)
        except Exception as exc:
            state.lines.append(f"keepalive error: {type(exc).__name__}: {exc}")
            time.sleep(5)


def _reader(proc: subprocess.Popen, state: TunnelState, sink: queue.Queue) -> None:
    """Pump cloudflared's stderr into a queue, then into the state.

    A pipe nobody reads fills its buffer and blocks the process, so this has
    to run for the whole life of the tunnel, not once at start.
    """
    try:
        assert proc.stderr is not None
        for raw in iter(proc.stderr.readline, b""):
            line = raw.decode("utf-8", "replace").rstrip()
            if not line:
                continue
            state.lines.append(line)
            if len(state.lines) > 2000:
                del state.lines[:-2000]
            sink.put(line)
            m = URL_RE.search(line)
            if m and not state.url and "Registered" in " ".join(state.lines[-12:]):
                state.url = m.group(0)
            h = HOST_RE.search(line)
            if h and not state.host:
                state.host = h.group(1)
            if "Registered tunnel connection" in line and not state.registered:
                state.registered = True
    except Exception:
        pass


def stop(state: TunnelState) -> None:
    proc = state.proc
    if proc is None or proc.poll() is not None:
        state.proc = None
        return
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    except OSError:
        pass
    state.proc = None
    state.registered = False


def start() -> TunnelState:
    state = TunnelState(started_at=time.time())
    try:
        binary = ensure_client(lambda m: state.lines.append(m))
    except Exception as exc:
        state.error = f"{type(exc).__name__}: {exc}"
        return state
    tok = (st.secrets.get("TUNNEL_TOKEN") or os.environ.get("TUNNEL_TOKEN", "")).strip()
    if not tok:
        state.error = ("TUNNEL_TOKEN is not set. Add it under Settings → Secrets "
                       "or export it in the environment.")
        return state
    # The token must be passed as --token, not positionally: a positional
    # argument to `tunnel run` is read as a tunnel name/UUID, and cloudflared
    # then demands cert.pem ("error parsing tunnel ID: Error locating origin
    # cert"). --token needs no login, which is what makes it work in a
    # container with no home directory.
    #
    # No --url here. The tunnel is remotely managed: Cloudflare pushes an
    # ingress config that pins each hostname to a fixed port, and that config
    # wins over the flag. Verified — with --url set, cloudflared still logs
    # `Updated to new configuration config="{... "service":"http://127.0.0.1:8080"}"`.
    # So the port is changed in the Cloudflare dashboard (or via a local
    # config.yml), not on the command line.
    cmd = [str(binary), "tunnel", "--no-autoupdate", "--loglevel", "info",
           "run", "--token", tok]
    try:
        state.proc = subprocess.Popen(  # noqa: S603
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            start_new_session=True, text=False, bufsize=0)
    except OSError as exc:
        state.error = f"could not start cloudflared: {exc}"
        return state
    sink: queue.Queue = queue.Queue()
    state.drain = threading.Thread(target=_reader,
                                  args=(state.proc, state, sink),
                                  daemon=True)
    state.drain.start()
    return state


def wait_registration(state: TunnelState, timeout_s: int = REGISTER_TIMEOUT_S) -> None:
    """Block until the tunnel registers, so the first paint is not empty."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if state.error:
            return
        if state.proc is not None and state.proc.poll() is not None:
            state.error = (f"cloudflared exited with {state.proc.returncode}; "
                           "see the log below")
            return
        if state.registered:
            return
        time.sleep(0.5)


INGRESS_RE = re.compile(r'"service":"http://127\.0\.0\.1:(\d+)"')


def ingress_port(state: TunnelState) -> int:
    """The port Cloudflare actually routes to, read back from its own config.

    The tunnel is remotely managed, so the origin port comes from the ingress
    config Cloudflare pushes — not from ORIGIN_URL, and not from --url, which
    is ignored when a remote config exists. Reading it back is the only way to
    tell which port a 502 is about.
    """
    for line in reversed(state.lines[-200:]):
        m = INGRESS_RE.search(line)
        if m:
            return int(m.group(1))
    return 0


def check_public(state: TunnelState) -> tuple[int, str]:
    """Request through the tunnel.

    A 502 is never a tunnel failure: cloudflared reached the edge and the edge
    could not reach the origin. The edge's own reason is already in the log, so
    return it alongside the code instead of a bare number that sends people
    hunting in the wrong place.
    """
    url = state.url or (f"https://{state.host}" if state.host else "")
    if not url:
        return 0, "no public hostname yet"
    try:
        with urllib.request.urlopen(url, timeout=25) as resp:  # noqa: S310
            return resp.status, resp.read(400).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        body = exc.read(400).decode("utf-8", "replace")
        if exc.code in (502, 503):
            return exc.code, _origin_detail(state) or body
        return exc.code, body
    except Exception as exc:
        return 0, f"{type(exc).__name__}: {exc}"


def _origin_detail(state: TunnelState) -> str:
    """The edge's dial error, pulled out of cloudflared's own log."""
    for line in reversed(state.lines[-60:]):
        m = re.search(r"dial tcp ([^;\"]+)", line)
        if m:
            return m.group(1).strip()
    return ""


# ── UI ────────────────────────────────────────────────────────────────
st.set_page_config(page_title="streamflare", layout="wide")

if "sf_state" not in st.session_state:
    st.session_state.sf_state = TunnelState()
state: TunnelState = st.session_state.sf_state
atexit.register(lambda: stop(state))

# The connector owns itself. A tunnel that only runs while a button is held
# answers 502 the moment the page is closed, which is indistinguishable from
# a broken tunnel — so it starts on first paint and a watchdog restarts it.
token_present = bool((st.secrets.get("TUNNEL_TOKEN")
                      or os.environ.get("TUNNEL_TOKEN", "")).strip())
if token_present and not state.wanted:
    state.wanted = True
    with st.spinner("downloading client and starting the tunnel…"):
        fresh = start()
        fresh.wanted = True
        st.session_state.sf_state = fresh
        state = fresh
        wait_registration(fresh)
if token_present and not any(t.name == "sf-keepalive"
                             for t in threading.enumerate()):
    threading.Thread(target=keep_alive, args=(state,),
                     name="sf-keepalive", daemon=True).start()

st.title("streamflare")
st.caption(f"origin {ORIGIN_URL} · client {client_path()}")

token = st.secrets.get("TUNNEL_TOKEN") or os.environ.get("TUNNEL_TOKEN", "")
c1, c2, c3, c4 = st.columns(4)
c1.metric("Token", f"{len(token)} chars" if token else "missing")
c2.metric("Origin", "up" if origin_alive() else "down")
c3.metric("Registered", "yes" if state.registered else "no")
c4.metric("Restarts", str(state.restarts))

cols = st.columns([1, 1, 1, 2])
if cols[0].button("Start", type="primary", use_container_width=True,
                  disabled=state.wanted):
    state.wanted = True
    stop(state)
    with st.spinner("starting the tunnel…"):
        fresh = start()
        fresh.wanted = True
        st.session_state.sf_state = fresh
        wait_registration(fresh)
    st.rerun()
if cols[1].button("Stop", use_container_width=True, disabled=not state.wanted):
    state.wanted = False
    stop(state)
    st.rerun()
if cols[2].button("Request", use_container_width=True,
                  disabled=not (state.url or state.host)):
    code, body = check_public(state)
    (st.success if code == 200 else st.error)(
        f"HTTP {code}" + ("" if code in (0, 200) else f" — {body[:200]}"))

url = state.url or (f"https://{state.host}" if state.host else "")
if url:
    st.code(url, language="text")

if state.error:
    st.error(state.error)

if state.proc is not None and state.proc.poll() is not None:
    st.warning(f"cloudflared exited with {state.proc.returncode} — see the log")

routed = ingress_port(state)
if origin_alive():
    st.caption(f"Origin answered at {ORIGIN_URL}. A 502 from Cloudflare means the "
               "tunnel is up and the origin is not reachable — the exact dial "
               "error is in the log below.")
else:
    st.warning(f"Nothing is listening at {ORIGIN_URL}. Start the local service. "
               "Requests through the tunnel will return 502 until then.")

if routed and routed != int(ORIGIN_URL.rsplit(":", 1)[-1] or 0):
    st.error(f"Cloudflare routes this tunnel to port {routed}, but you are "
             f"showing {ORIGIN_URL}. The port is set in the Cloudflare "
             f"dashboard, not here — `--url` is ignored when a remote config "
             f"exists. Either serve on {routed} or change the route to match.")

st.subheader("cloudflared log")
st.code(state.tail() or "(empty — the tunnel has not produced output yet)",
         language="text")

if state.registered and st.button("Live tail (5s refresh)"):
    for _ in range(int(REGISTER_TIMEOUT_S / 5)):
        time.sleep(5)
        st.rerun()
