#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import pathlib
import sys
import requests
from urllib.parse import urlparse, parse_qs, unquote
import base64
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
    # нормализуем padding
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode()).decode()


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
    # Нормализуем альтернативные ключи
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


# -------------- parsers ----------------
def parse_vless(uri: str):
    """
    Поддержка формата, который ты прислал:
    vless://<base64("none:<uuid>")>@host:port?obfs=websocket&obfsParam=<host>&tls=1&peer=...&path=...
    + remarks=... (имя)
    """
    if not uri.startswith("vless://"):
        return None

    # Отрезаем схему
    rest = uri[len("vless://"):]
    # userinfo(base64)@host:port ? query
    if "@" not in rest:
        raise ValueError("vless url without @")
    userinfo, after_at = rest.split("@", 1)

    # decode userinfo
    try:
        decoded = safe_b64decode(userinfo)
        # ожидаем none:<uuid>
        if ":" in decoded:
            encryption, uuid = decoded.split(":", 1)
        else:
            # fallback: иногда просто uuid
            encryption, uuid = "none", decoded
    except Exception as e:
        raise ValueError(f"cannot decode userinfo: {e}")

    # host:port[?query]
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

    # map query -> clash fields
    # обfs=websocket -> network=ws
    obfs = (query.get("obfs", [""])[0] or "").lower()
    network = "ws" if "websocket" in obfs else query.get("type", ["tcp"])[0]

    # path
    raw_path = query.get("path", [""])[0]
    path = unquote(raw_path) if raw_path else "/"

    # host header
    host_header = query.get("obfsParam", [""])[0] or query.get("host", [""])[0]
    host_header = host_header.strip()

    # tls
    tls = False
    tls_param = query.get("tls", ["0"])[0] or query.get("security", [""])[0]
    if tls_param in ("1", "tls", "reality"):
        tls = True

    # sni (peer)
    sni = query.get("peer", [""])[0] or query.get("sni", [""])[0] or host_header

    # name
    remarks = query.get("remarks", [""])[0]
    try:
        name = unquote(remarks) if remarks else f"{host}:{port}"
    except Exception:
        name = f"{host}:{port}"

    # fp (fingerprint) игнорируем — Clash не использует (кроме reality, тут нет)
    # udp включим по умолчанию
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


def try_parse_line(line: str):
    # 1) если это http/https — предполагаем ссылку на Clash YAML подписку
    if line.startswith("http://") or line.startswith("https://"):
        return "yaml-url", line

    # 2) vless
    if line.startswith("vless://"):
        return "proxy", parse_vless(line)

    # TODO: можно добавить vmess/ss/trojan при необходимости
    raise ValueError(f"Unknown/unsupported line format: {line[:40]}...")


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
                print(f"[OK] VLESS node: {payload.get('name')}")
        except Exception as e:
            print(f"[WARN] line: {ln[:80]} -> {e}")

    # прокси из yaml-подписок
    for inc in collected_yaml_cfgs:
        inc = ensure_lists(inc)
        if "proxies" in inc and inc["proxies"]:
            collected_proxies.extend(inc["proxies"])

    # merge
    base_cfg, new_names = merge_proxies(base_cfg, collected_proxies)
    add_to_groups(base_cfg, new_names)

    # backup
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
