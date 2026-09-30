"""
Heimdall IDS Dashboard — NGINX front end
    sudo heimdall --setup-nginx   [--nginx-cert FILE --nginx-key FILE] [--nginx-server-name NAME]
    sudo heimdall --remove-nginx

Puts Heimdall behind NGINX so only NGINX is exposed to the network:
  * installs nginx with apt if it is missing
  * uses the given certificate, or generates a self-signed one in
    /etc/heimdall/tls/ (reused on later runs)
  * writes ONE NGINX site: HTTPS on 443, HTTP 80 → HTTPS redirect, live-alert
    stream (/events) unbuffered. Other NGINX sites are never modified; if
    another site or program already uses port 443, setup stops.
  * binds Heimdall to 127.0.0.1 and enables --behind-proxy through a managed
    block at the end of /etc/heimdall/heimdall.conf (a backup is kept)
  * validates with `nginx -t`; any failure rolls every change back

--remove-nginx reverses the Heimdall-side changes. The nginx package and the
certificate are left in place.

Everything goes through Env so tests can use a temporary root directory and a
fake command runner.
"""

import hashlib
import ipaddress
import os
import re
import ssl
import subprocess
import time
from pathlib import Path

MARKER      = "# Managed by `heimdall --setup-nginx` — remove with `sudo heimdall --remove-nginx`"
BLOCK_START = "# >>> managed by heimdall --setup-nginx (do not edit inside this block)"
BLOCK_END   = "# <<< managed by heimdall --setup-nginx"

HEIMDALL_CONF = "/etc/heimdall/heimdall.conf"
TLS_DIR       = "/etc/heimdall/tls"
STOCK_DEFAULT = "/etc/nginx/sites-enabled/default"


class SetupError(Exception):
    pass


class Env:
    """Filesystem root, command runner and privilege check (injectable for tests)."""

    def __init__(self, root="/", runner=None, is_root=None, out=print):
        self.root    = Path(root)
        self.out     = out
        self._runner = runner or self._run
        self.is_root = (os.geteuid() == 0) if is_root is None else is_root

    def p(self, path) -> Path:
        return self.root / str(path).lstrip("/")

    def run(self, cmd, env=None):
        return self._runner(cmd, env)

    @staticmethod
    def _run(cmd, env=None):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=600,
                               env={**os.environ, **(env or {})})
            return r.returncode, (r.stdout or "") + (r.stderr or "")
        except FileNotFoundError:
            return 127, f"{cmd[0]}: command not found"
        except subprocess.TimeoutExpired:
            return 124, f"{cmd[0]}: timed out"


# ── Pure helpers ─────────────────────────────────────────────────────────────

def render_site(port: int, crt: str, key: str, server_name: str = None,
                default_80: bool = True, ipv6: bool = True,
                https_port: int = 443, http_port: int = 80) -> str:
    """The NGINX site. https_port/http_port exist only for tests."""
    name  = server_name or "_"
    d80   = " default_server" if default_80 else ""
    v6_80 = f"    listen [::]:{http_port}{d80};\n" if ipv6 else ""
    v6_43 = f"    listen [::]:{https_port} ssl;\n" if ipv6 else ""
    proxy = f"""        proxy_pass         http://127.0.0.1:{port};
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_set_header   Connection        "";
"""
    return f"""{MARKER}
# Heimdall itself listens on 127.0.0.1:{port} only; this site is its only way in.

server {{
    listen {http_port}{d80};
{v6_80}    server_name {name};
    return 301 https://$host$request_uri;
}}

server {{
    listen {https_port} ssl;
{v6_43}    server_name {name};

    ssl_certificate      {crt};
    ssl_certificate_key  {key};
    ssl_protocols        TLSv1.2 TLSv1.3;
    ssl_session_cache    shared:heimdall_ssl:10m;
    ssl_session_timeout  1d;

    server_tokens        off;
    client_max_body_size 5m;      # Heimdall caps request bodies at 4 MB

    # Live alert stream (Server-Sent Events): must not be buffered
    location = /events {{
{proxy}        proxy_buffering    off;
        proxy_cache        off;
        proxy_read_timeout 1h;
    }}

    location / {{
{proxy}    }}
}}
"""


def set_managed_block(text: str, lines: list) -> str:
    """Replace (or append) the managed block. Later lines in heimdall.conf win,
    so the block goes at the end."""
    body = remove_managed_block(text).rstrip("\n")
    block = "\n".join([BLOCK_START, *lines, BLOCK_END])
    return (body + "\n\n" if body else "") + block + "\n"


def remove_managed_block(text: str) -> str:
    out, inside = [], False
    for line in text.splitlines():
        if line.strip() == BLOCK_START:
            inside = True; continue
        if line.strip() == BLOCK_END:
            inside = False; continue
        if not inside:
            out.append(line)
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out) + ("\n" if out else "")


_LISTEN_RE = re.compile(r"^\s*listen\s+([^;]+);", re.M)


def listened_ports(conf_text: str) -> set:
    """Ports in `listen` directives (comments ignored)."""
    text  = "\n".join(l.split("#", 1)[0] for l in conf_text.splitlines())
    ports = set()
    for spec in _LISTEN_RE.findall(text):
        addr = spec.split()[0]
        m = re.search(r"(?:^|:)(\d+)$", addr)
        ports.add(int(m.group(1)) if m else 80)   # bare address → port 80
    return ports


def cert_fingerprint(pem_path: Path) -> str:
    der = ssl.PEM_cert_to_DER_cert(pem_path.read_text())
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


# ── Setup ────────────────────────────────────────────────────────────────────

def _site_paths(env: Env):
    """Debian layout (sites-available + symlink) when present, else conf.d."""
    if env.p("/etc/nginx/sites-available").is_dir():
        return (env.p("/etc/nginx/sites-available/heimdall"),
                env.p("/etc/nginx/sites-enabled/heimdall"))
    return env.p("/etc/nginx/conf.d/heimdall.conf"), None


def _other_confs(env: Env, own: Path):
    for d, pat in (("/etc/nginx/sites-enabled", "*"), ("/etc/nginx/conf.d", "*.conf")):
        for f in sorted(env.p(d).glob(pat)) if env.p(d).is_dir() else []:
            try:
                if f.resolve() == own.resolve() or f.name in ("heimdall", "heimdall.conf"):
                    continue
                yield f, f.read_text(errors="replace")
            except OSError:
                continue


def _check_ports(env: Env, site: Path):
    """Stop if anything else owns 443; report whether some other site has 80."""
    other_80 = False
    for f, text in _other_confs(env, site):
        ports = listened_ports(text)
        if 443 in ports:
            raise SetupError(f"Another NGINX site already listens on 443 ({f}). "
                             "Setup stopped to avoid changing it.")
        other_80 |= 80 in ports
    rc, out = env.run(["ss", "-ltnpH"])
    if rc == 0:
        for line in out.splitlines():
            cols = line.split()
            if len(cols) < 4:
                continue
            m = re.search(r":(\d+)$", cols[3])
            if m and int(m.group(1)) in (80, 443) and "nginx" not in line:
                raise SetupError(f"Port {m.group(1)} is already used by another program: "
                                 f"{line.strip()}")
    return other_80


def _host_ips(env: Env) -> list:
    rc, out = env.run(["hostname", "-I"])
    ips = []
    for tok in out.split() if rc == 0 else []:
        try:
            ip = ipaddress.ip_address(tok)
        except ValueError:
            continue
        if not ip.is_loopback and not ip.is_link_local:
            ips.append(str(ip))
    return ips


def _certificate(env: Env, cert: str, key: str, name: str) -> tuple:
    """Return (cert_path, key_path) as absolute system paths."""
    if cert or key:
        if not (cert and key):
            raise SetupError("--nginx-cert and --nginx-key must be given together.")
        # Relative paths are relative to the directory the command was run from.
        cert, key = os.path.abspath(cert), os.path.abspath(key)
        try:
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(str(env.p(cert)), str(env.p(key)))
        except (OSError, ssl.SSLError) as exc:
            raise SetupError(f"Cannot use the certificate/key ({exc}).") from None
        return cert, key

    crt_l, key_l = f"{TLS_DIR}/heimdall.crt", f"{TLS_DIR}/heimdall.key"
    crt_p, key_p = env.p(crt_l), env.p(key_l)
    if crt_p.exists() and key_p.exists():
        env.out(f"  Reusing the self-signed certificate in {TLS_DIR}/")
        return crt_l, key_l
    crt_p.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(crt_p.parent, 0o700)
    san = ",".join([f"DNS:{name}", "DNS:localhost", "IP:127.0.0.1"] +
                   [f"IP:{ip}" for ip in _host_ips(env)])
    rc, out = env.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256",
                       "-days", "825", "-nodes", "-keyout", str(key_p), "-out", str(crt_p),
                       "-subj", f"/CN={name}", "-addext", f"subjectAltName={san}"])
    if rc != 0:
        raise SetupError("Could not generate a self-signed certificate with openssl "
                         f"(install openssl, or pass --nginx-cert/--nginx-key):\n{out.strip()}")
    os.chmod(key_p, 0o600)
    env.out(f"  Generated a self-signed certificate for {name} in {TLS_DIR}/ (valid 825 days)")
    return crt_l, key_l


def setup(env: Env, port: int, cert: str = None, key: str = None,
          server_name: str = None, builtin_tls: bool = False) -> int:
    if not env.is_root:
        raise SetupError("Run as root: sudo heimdall --setup-nginx")
    if builtin_tls:
        raise SetupError("Built-in HTTPS (--tls-cert/--tls-key) is enabled in heimdall.conf. "
                         "Remove those lines first: NGINX will provide HTTPS.")

    undo = []                                      # callables, run in reverse on failure
    try:
        # 1. NGINX present?
        installed_now = False
        if env.run(["nginx", "-v"])[0] != 0:
            env.out("  NGINX not found — installing with apt…")
            apt_env = {"DEBIAN_FRONTEND": "noninteractive"}
            rc, out = env.run(["apt-get", "install", "-y", "nginx"], env=apt_env)
            if rc != 0:                           # stale package lists? refresh once
                env.run(["apt-get", "update"], env=apt_env)
                rc, out = env.run(["apt-get", "install", "-y", "nginx"], env=apt_env)
            if rc != 0:
                raise SetupError(f"apt-get install nginx failed:\n{out.strip()[-800:]}")
            installed_now = True

        site, link = _site_paths(env)
        if site.exists() and MARKER not in site.read_text(errors="replace"):
            raise SetupError(f"{site} exists but was not created by Heimdall; not overwriting it.")

        # 2. A fresh install enables the stock default site on :80 — ours replaces it.
        default_link = env.p(STOCK_DEFAULT)
        if installed_now and default_link.is_symlink():
            target = os.readlink(default_link)
            default_link.unlink()
            undo.append(lambda: default_link.symlink_to(target))
        other_80 = _check_ports(env, site)

        # 3. Certificate
        name = server_name
        if not name:
            rc, out = env.run(["hostname", "-f"])
            name = out.strip().split()[0] if rc == 0 and out.strip() else "heimdall"
        crt, keyf = _certificate(env, cert, key, name)

        # 4. Site file (+ symlink on Debian layout)
        old_site = site.read_text() if site.exists() else None
        site.parent.mkdir(parents=True, exist_ok=True)
        site.write_text(render_site(port, crt, keyf, server_name,
                                    default_80=not other_80,
                                    ipv6=env.p("/proc/net/if_inet6").exists()))
        undo.append(lambda: site.write_text(old_site) if old_site is not None else site.unlink())
        if link is not None and not link.is_symlink():
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to(site)
            undo.append(lambda: link.unlink())

        # 5. Validate before anything is reloaded
        rc, out = env.run(["nginx", "-t"])
        if rc != 0:
            raise SetupError(f"nginx -t rejected the configuration:\n{out.strip()}")

        # 6. Heimdall: loopback only, trust the local proxy's client-IP header
        conf = env.p(HEIMDALL_CONF)
        old_conf = conf.read_text() if conf.exists() else None
        if old_conf is not None:
            backup = conf.with_name(f"heimdall.conf.bak-{time.strftime('%Y%m%d-%H%M%S')}")
            backup.write_text(old_conf)
            env.out(f"  Backed up heimdall.conf to {backup.name}")
        conf.parent.mkdir(parents=True, exist_ok=True)
        conf.write_text(set_managed_block(old_conf or "", ["--host 127.0.0.1", "--behind-proxy"]))
        undo.append(lambda: conf.write_text(old_conf) if old_conf is not None else conf.unlink())

        # 7. Apply
        for cmd in (["systemctl", "enable", "--now", "nginx"],
                    ["systemctl", "reload", "nginx"],
                    ["systemctl", "restart", "heimdall"]):
            rc, out = env.run(cmd)
            if rc != 0:
                raise SetupError(f"{' '.join(cmd)} failed:\n{out.strip()}")
    except Exception:
        for fn in reversed(undo):
            try:
                fn()
            except OSError:
                pass
        if undo:
            env.run(["systemctl", "reload", "nginx"])
            env.run(["systemctl", "restart", "heimdall"])
            env.out("  All changes were rolled back.")
        raise

    fp = ""
    try:
        fp = cert_fingerprint(env.p(crt))
    except (OSError, ValueError):
        pass
    env.out("")
    env.out("  Heimdall is now behind NGINX.")
    env.out(f"  URL:        https://{server_name or name}/")
    env.out(f"  Heimdall:   127.0.0.1:{port} only (not reachable from the network)")
    env.out(f"  NGINX site: {site}")
    if fp:
        env.out(f"  Certificate SHA-256 fingerprint:\n    {fp}")
    if not cert:
        env.out("  The certificate is self-signed: browsers will warn until it is trusted.")
    env.out("  Undo with: sudo heimdall --remove-nginx")
    return 0


def remove(env: Env) -> int:
    if not env.is_root:
        raise SetupError("Run as root: sudo heimdall --remove-nginx")
    site, link = _site_paths(env)
    changed = False
    if site.exists():
        if MARKER not in site.read_text(errors="replace"):
            raise SetupError(f"{site} was not created by Heimdall; not removing it.")
        if link is not None and link.is_symlink():
            link.unlink()
        site.unlink()
        changed = True
        rc, out = env.run(["nginx", "-t"])
        if rc == 0:
            env.run(["systemctl", "reload", "nginx"])
        else:
            env.out(f"  Warning: nginx -t reports a problem in other sites:\n{out.strip()}")
    conf = env.p(HEIMDALL_CONF)
    if conf.exists() and BLOCK_START in conf.read_text():
        conf.write_text(remove_managed_block(conf.read_text()))
        changed = True
    if not changed:
        env.out("  Nothing to remove: Heimdall is not set up behind NGINX.")
        return 0
    rc, out = env.run(["systemctl", "restart", "heimdall"])
    if rc != 0:
        env.out(f"  Warning: could not restart heimdall:\n{out.strip()}")
    env.out("  Removed the Heimdall NGINX site; Heimdall uses its own --host/--port again.")
    env.out(f"  Kept: the nginx package and any certificate in {TLS_DIR}/.")
    return 0
