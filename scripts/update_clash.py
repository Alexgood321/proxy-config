#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import pathlib
import sys
import requests
from ruamel.yaml import YAML

ROOT = pathlib.Path(__file__).resolve().parents[1]

# ---- Настраиваемые через ENV имена файлов ----
SERVER_FILE = os.getenv("SERVER_FILE", "Server.txt")  # у тебя файл с заглавной S
TARGET_FILE = os.getenv("TARGET_FILE", "proxy for clashx pro.yaml")
BACKUP_FILE = TARGET_FILE + ".bak"

SERVER_TXT = ROOT / SERVER_FILE
TARGET_YAML = ROOT / TARGET_FILE
BACKUP_YAML = ROOT / BACKUP_FILE

# В эти группы автоматически добавляем новые прокси (подкорректируй под свой конфиг)
GROUPS_TO_FILL = set(
    os.getenv("GROUPS_TO_FILL", "PROXY,GLOBAL,节点选择,Proxy").split(",")
)

yaml = YAML()
yaml.preserve_quotes = True
yaml.indent(mapping=2, sequence=4, offset=2)


def read_lines():
    if not SERVER_TXT.exists():
        print(f"[WARN] {SERVER_TXT} not found, nothing to do.")
        return []
    return [
        l.strip()
        for l in SERVER_TXT.read_text(encoding="utf-8").splitlines()
        if l.strip() and not l.strip().startswith("#")
    ]


def load_yaml_from_url(url: str):
    headers = {"User-Agent": "clash/meta"}  # некоторые провайдеры проверяют UA
    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    return yaml.load(r.text)


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


def merge_proxies(base_cfg, incoming_cfgs):
    base_cfg = ensure_lists(base_cfg)
    old_names = {p.get("name") for p in base_cfg.get("proxies", [])}

    new_proxies = []
    for inc in incoming_cfgs:
        inc = ensure_lists(inc)
        if inc.get("proxies"):
            new_proxies.extend(inc["proxies"])

    if not new_proxies:
        return base_cfg, []

    all_proxies = base_cfg.get("proxies", []) + new_proxies
    all_proxies = dedup_by_name(all_proxies)
    base_cfg["proxies"] = all_proxies

    actually_new = [
        p.get("name") for p in new_proxies if p.get("name") not in old_names
    ]

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


def main():
    if not TARGET_YAML.exists():
        print(f"[ERROR] {TARGET_YAML} not found. Создай/положи файл базового конфига.")
        sys.exit(1)

    base_cfg = yaml.load(TARGET_YAML.read_text(encoding="utf-8"))
    base_cfg = ensure_lists(base_cfg)

    urls = read_lines()
    if not urls:
        print("Нет ссылок в Server.txt — выходим без ошибок.")
        return

    incoming_cfgs = []
    for u in urls:
        try:
            inc = load_yaml_from_url(u)
            incoming_cfgs.append(inc)
            print(f"[OK] {u}")
        except Exception as e:
            print(f"[WARN] {u}: {e}")

    base_cfg, new_names = merge_proxies(base_cfg, incoming_cfgs)
    add_to_groups(base_cfg, new_names)

    # Бэкап
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
