#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import pathlib
import sys
import json
import base64
import requests
from urllib.parse import urlparse, parse_qs, unquote, unquote_plus
from ruamel.yaml import YAML

ROOT = pathlib.Path(__file__).resolve().parents[1]

# ---- Конфиг через ENV ----
SERVER_FILE = os.getenv("SERVER_FILE", "Server.txt")           # твой файл в репо
TARGET_FILE = os.getenv("TARGET_FILE", "proxy for clashx pro.yaml")
BACKUP_FILE = TARGET_FILE + ".bak"
GROUPS_TO_FILL = set(os.getenv("GROUPS_TO_FILL", "PROXY,GLOBAL,节点选择,Proxy").split(","))

SERVER_TXT = ROOT / SERVER_FILE
TARGET_YAML = ROOT / TARGET_FILE
BACKUP_YAML = ROOT / BACKUP_FILE

yaml = YAML()
yaml.preserve_quotes = True
yaml.indent(mapping=2, sequence=4, offset=2)


# ----------------- helpers -----------------
def safe_b64decode(s: str) -> str:
    s = s.strip()
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode()).decode(errors="ignore")


def read_lines():
    if not SERVER_TXT.exists():
        print(f"[WARN] {SERVER_TXT} not found, nothing to do.")
        return []
    return [
        l.strip()
        for l in SERVER_TXT.read_text(encoding="utf-8").splitlines()
        if l.strip() and not l.strip().startswith("#")
    ]


def ensure_lists(cfg):
    if "proxies" not in cfg and "Proxy" in cfg:
        cfg["proxies"] = cfg.pop("Proxy")
    if "proxy-groups" not in cfg and "Proxy Group" in cfg:
        cfg["proxy-groups"] = cfg.pop("Proxy Group")
    if "rules" not in cfg and "Rule" in cfg:
        cfg["rules"] = cfg.pop("Rule")
    cfg.setdefault("proxies", [])
    cfg.setdefault("proxy-groups", [])
    return cfg


def dedup_by_name(items):
    seen = set()
    out = []
    for it in items:
        name = it.get("name")
        if name in seen:
            continue
        seen.add(name)
        out.append(it)
    return out


def percent_decode(s: str) -> str:
    try:
        return unquote_plus(s)
    except Exception:
        return s


# -------------- parsers ----------------
def parse_vless(uri: str):
    if not uri.startswith("vless://"):
        return None

    # стандартный формат vless://uuid@host:port?...
    try:
        parsed = urlparse(uri)
        if parsed.username and parsed.hostname and parsed.port:
            q = parse_qs(parsed.query)
            network = q.get("type", ["tcp"])[0]
            if "obfs" in q and "websocket" in q.get("obfs", [""])[0].lower():
                network = "ws"
            path = percent_decode(q.get("path", ["/"])[0] or "/")
            host_header = q.get("host", [""])[0] or q.get("obfsParam", [""])[0]
            tls_val = q.get("security", [""])[0] or q.get("tls", ["0"])[0]
            tls = tls_val in ("tls", "1", "reality")
            sni = q.get("sni", [""])[0] or q.get("peer", [""])[0] or host_header
            name = percent_decode(q.get("remarks", [""])[0]) or percent_decode(parsed.fragment) or f"{parsed.hostname}:{parsed.port}"

            proxy = {
                "name": name,
                "type": "vless",
                "server": parsed.hostname,
                "port": parsed.port,
                "uuid": parsed.username,
                "udp": True,
                "tls": tls,
                "encryption": "none",
                "network": network,
            }
            if tls and sni:
                proxy["servername"] = sni
            if network == "ws":
                ws_opts = {"path": path}
                if host_header:
                    ws_opts["headers"] = {"Host": host_header}
                proxy["ws-opts"] = ws_opts
            return proxy
    except Exception:
        pass

    # формат с base64 в userinfo
    rest = uri[len("vless://"):]
    if "@" not in rest:
        raise ValueError("vless url without @")
    userinfo, after_at = rest.split("@", 1)

    try:
        decoded = safe_b64decode(userinfo)
        if ":" in decoded:
            encryption, uuid = decoded.split(":", 1)
        else:
            encryption, uuid = "none", decoded
    except Exception as e:
        raise ValueError(f"cannot decode userinfo: {e}")

    if "?" in after_at:
        hp, q = after_at.split("?", 1)
        query = parse_qs(q)
    else:
        hp = after_at
        query = {}

    if ":" not in hp:
        raise ValueError("no port in host:port")
    host, port = hp.rsplit(":", 1)
    port = int(port)

    obfs = (query.get("obfs", [""])[0] or "").lower()
    network = "ws" if "websocket" in obfs else query.get("type", ["tcp"])[0]

    raw_path = query.get("path", [""])[0]
    path = percent_decode(raw_path) if raw_path else "/"

    host_header = query.get("obfsParam", [""])[0] or query.get("host", [""])[0]
    host_header = host_header.strip()

    tls = False
    tls_param = query.get("tls", ["0"])[0] or query.get("security", [""])[0]
    if tls_param in ("1", "tls", "reality"):
        tls = True

    sni = query.get("peer", [""])[0] or query.get("sni", [""])[0] or host_header

    remarks = query.get("remarks", [""])[0]
    name = percent_decode(remarks) if remarks else f"{host}:{port}"

    proxy = {
        "name": name,
        "type": "vless",
        "server": host,
        "port": port,
        "uuid": uuid,
        "udp": True,
        "tls": tls,
        "encryption": "none",
        "network": network,
    }

    if tls and sni:
        proxy["servername"] = sni

    if network == "ws":
        ws_opts = {"path": path}
        if host_header:
            ws_opts["headers"] = {"Host": host_header}
        proxy["ws-opts"] = ws_opts

    return proxy


def parse_vmess(uri: str):
    if not uri.startswith("vmess://"):
        return None
    payload = uri[len("vmess://"):]
    try:
        data = json.loads(safe_b64decode(payload))
    except Exception as e:
        raise ValueError(f"vmess decode error: {e}")

    add = data.get("add")
    port = int(data.get("port", 0))
    uuid = data.get("id")
    aid = int(data.get("aid", 0))
    net = data.get("net", "tcp")
    tls = data.get("tls", "").lower() == "tls"
    host = data.get("host") or data.get("sni") or ""
    sni = data.get("sni") or host
    path = data.get("path", "/") or "/"
    name = data.get("ps") or f"{add}:{port}"

    proxy = {
        "name": name,
        "type": "vmess",
        "server": add,
        "port": port,
        "uuid": uuid,
        "alterId": aid,
        "cipher": "auto",
        "udp": True,
        "tls": tls,
        "network": net,
    }
    if tls and sni:
        proxy["servername"] = sni

    if net == "ws":
        ws_opts = {"path": path}
        if host:
            ws_opts["headers"] = {"Host": host}
        proxy["ws-opts"] = ws_opts
    elif net == "h2":
        proxy["http-opts"] = {"path": [path], "headers": {"Host": [host]}} if host else {"path": [path]}

    return proxy


def parse_trojan(uri: str):
    if not uri.startswith("trojan://"):
        return None
    parsed = urlparse(uri)
    if not parsed.hostname or not parsed.port:
        raise ValueError("trojan: missing host/port")

    password = parsed.username or ""
    q = parse_qs(parsed.query)
    sni = q.get("sni", [""])[0] or q.get("peer", [""])[0] or parsed.hostname
    name = percent_decode(q.get("remarks", [""])[0]) or percent_decode(parsed.fragment) or f"{parsed.hostname}:{parsed.port}"
    network = q.get("type", ["tcp"])[0]

    proxy = {
        "name": name,
        "type": "trojan",
        "server": parsed.hostname,
        "port": parsed.port,
        "password": password,
        "udp": True,
        "sni": sni if sni else None,
        "network": network,
    }
    if network == "ws":
        path = percent_decode(q.get("path", ["/"])[0] or "/")
        host = q.get("host", [""])[0]
        ws_opts = {"path": path}
        if host:
            ws_opts["headers"] = {"Host": host}
        proxy["ws-opts"] = ws_opts
    return proxy


def parse_ss(uri: str):
    if not uri.startswith("ss://"):
        return None

    main = uri[len("ss://"):]
    name = ""
    if "#" in main:
        main, frag = main.split("#", 1)
        name = percent_decode(frag)

    plugin = None
    if "?" in main:
        main, query = main.split("?", 1)
        q = parse_qs(query)
        plugin = q.get("plugin", [None])[0]

    host = None
    port = None
    method = None
    password = None

    def parse_host_port(hp: str):
        if "@" not in hp:
            if ":" not in hp:
                raise ValueError("ss no port")
            return None, None, *hp.rsplit(":", 1)
        left, right = hp.split("@", 1)
        if ":" not in left:
            raise ValueError("ss invalid cred")
        m, p = left.split(":", 1)
        if ":" not in right:
            raise ValueError("ss no port")
        h, prt = right.rsplit(":", 1)
        return m, p, h, prt

    try:
        decoded = safe_b64decode(main)
        method, password, host, port = parse_host_port(decoded)
    except Exception:
        method, password, host, port = parse_host_port(main)

    port = int(port)

    if not name:
        name = f"{host}:{port}"

    proxy = {
        "name": name,
        "type": "ss",
        "server": host,
        "port": port,
        "cipher": method,
        "password": password,
        "udp": True,
    }

    if plugin:
        proxy["plugin"] = plugin.split(";")[0]
        opts = {}
        for kv in plugin.split(";")[1:]:
            if not kv:
                continue
            if "=" in kv:
                k, v = kv.split("=", 1)
                opts[k] = v
            else:
                opts[kv] = True
        proxy["plugin-opts"] = opts

    return proxy


def parse_socks(uri: str):
    parsed = urlparse(uri)
    if parsed.scheme not in ("socks5", "socks"):
        return None
    if not parsed.hostname or not parsed.port:
        raise ValueError("socks missing host/port")
    name = percent_decode(parsed.fragment) or f"{parsed.hostname}:{parsed.port}"
    proxy = {
        "name": name,
        "type": "socks5",
        "server": parsed.hostname,
        "port": parsed.port,
        "udp": True,
    }
    if parsed.username:
        proxy["username"] = parsed.username
    if parsed.password:
        proxy["password"] = parsed.password
    return proxy


def parse_http_proxy(uri: str):
    parsed = urlparse(uri)
    if parsed.scheme != "http":
        return None
    if not parsed.hostname or not parsed.port:
        raise ValueError("http proxy missing host/port")
    if not (parsed.username or parsed.password):
        return None  # скорее всего это YAML-подписка

    name = percent_decode(parsed.fragment) or f"{parsed.hostname}:{parsed.port}"
    proxy = {
        "name": name,
        "type": "http",
        "server": parsed.hostname,
        "port": parsed.port,
        "udp": True,
    }
    if parsed.username:
        proxy["username"] = parsed.username
    if parsed.password:
        proxy["password"] = parsed.password
    return proxy


def is_yaml_subscription(url: str) -> bool:
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        return False
    if p.username or p.password:
        return False
    return True


def try_parse_line(line: str):
    if line.startswith("http://") or line.startswith("https://"):
        if is_yaml_subscription(line):
            return "yaml-url", line
        http_p = parse_http_proxy(line)
        if http_p:
            return "proxy", http_p

    if line.startswith("vless://"):
        return "proxy", parse_vless(line)
    if line.startswith("vmess://"):
        return "proxy", parse_vmess(line)
    if line.startswith("trojan://"):
        return "proxy", parse_trojan(line)
    if line.startswith("ss://"):
        return "proxy", parse_ss(line)
    if line.startswith("socks5://") or line.startswith("socks://"):
        return "proxy", parse_socks(line)

    raise ValueError(f"Unknown/unsupported line format: {line[:60]}...")


def load_yaml_from_url(url: str):
    headers = {"User-Agent": "clash/meta"}
    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    return yaml.load(r.text)


def merge_proxies(base_cfg, proxies):
    base_cfg = ensure_lists(base_cfg)
    old_names = {p.get("name") for p in base_cfg.get("proxies", [])}

    if not proxies:
        return base_cfg, []

    all_proxies = base_cfg.get("proxies", []) + proxies
    all_proxies = dedup_by_name(all_proxies)
    base_cfg["proxies"] = all_proxies

    actually_new = [p.get("name") for p in proxies if p.get("name") not in old_names]
    return base_cfg, actually_new


def add_to_groups(cfg, proxy_names):
    if not proxy_names:
        return
    for g in cfg.get("proxy-groups", []):
        if g.get("name") in GROUPS_TO_FILL and g.get("type") == "select":
            g.setdefault("proxies", [])
            existed = set(g["proxies"])
            for n in proxy_names:
                if n not in existed:
                    g["proxies"].append(n)


# -------------- main -----------------
def main():
    if not TARGET_YAML.exists():
        print(f"[ERROR] {TARGET_YAML} not found. Создай/положи файл базового конфига.")
        sys.exit(1)

    base_cfg = yaml.load(TARGET_YAML.read_text(encoding="utf-8"))
    base_cfg = ensure_lists(base_cfg)

    lines = read_lines()
    if not lines:
        print("Нет ссылок/строк в Server.txt — выходим без ошибок.")
        return

    collected_yaml_cfgs = []
    collected_proxies = []

    for ln in lines:
        try:
            kind, payload = try_parse_line(ln)
            if kind == "yaml-url":
                inc = load_yaml_from_url(payload)
                collected_yaml_cfgs.append(inc)
                print(f"[OK] YAML {payload}")
            elif kind == "proxy":
                if payload is None:
                    print(f"[WARN] can't parse proxy: {ln[:60]}...")
                    continue
                collected_proxies.append(payload)
                print(f"[OK] Node: {payload.get('type')} -> {payload.get('name')}")
        except Exception as e:
            print(f"[WARN] line: {ln[:80]} -> {e}")

    for inc in collected_yaml_cfgs:
        inc = ensure_lists(inc)
        if "proxies" in inc and inc["proxies"]:
            collected_proxies.extend(inc["proxies"])

    base_cfg, new_names = merge_proxies(base_cfg, collected_proxies)
    add_to_groups(base_cfg, new_names)

    # backup (останется untracked, т.к. *.bak в .gitignore)
    try:
        if TARGET_YAML.exists():
            TARGET_YAML.replace(BACKUP_YAML)
    except Exception as e:
        print(f"[WARN] backup failed: {e}")

    with TARGET_YAML.open("w", encoding="utf-8") as f:
        yaml.dump(base_cfg, f)

    print(f"Готово. Новых узлов: {len(new_names)}")
    if new_names:
        print("Новые:", ", ".join(new_names))


if __name__ == "__main__":
    main()
