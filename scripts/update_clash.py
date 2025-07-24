
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pathlib
import sys
import requests
from ruamel.yaml import YAML

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVER_TXT = ROOT / "server.txt"
TARGET_YAML = ROOT / "proxy for clashx pro.yaml"   # путь к твоему основному файлу
BACKUP_YAML = ROOT / "proxy for clashx pro.yaml.bak"

# В эту(эти) группу(ы) мы автоматически добавляем новые прокси
GROUPS_TO_FILL = {"PROXY", "GLOBAL", "节点选择", "Proxy"}  # подкорректируй под себя

yaml = YAML()
yaml.preserve_quotes = True
yaml.indent(mapping=2, sequence=4, offset=2)

def read_lines():
    if not SERVER_TXT.exists():
        print(f"{SERVER_TXT} not found")
        sys.exit(1)
    return [l.strip() for l in SERVER_TXT.read_text(encoding="utf-8").splitlines() if l.strip() and not l.strip().startswith("#")]

def load_yaml_from_url(url: str):
    headers = {"User-Agent": "clash/meta"}  # некоторые провайдеры проверяют UA
    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    return yaml.load(r.text)

def ensure_lists(cfg):
    # Нормализуем старые поля типа 'Proxy', 'Proxy Group'
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
    # соберём все новые прокси
    new_proxies = []
    for inc in incoming_cfgs:
        inc = ensure_lists(inc)
        if "proxies" in inc and inc["proxies"]:
            new_proxies.extend(inc["proxies"])

    if not new_proxies:
        return base_cfg, []

    # дедуп по имени
    all_proxies = base_cfg.get("proxies", []) + new_proxies
    all_proxies = dedup_by_name(all_proxies)
    base_cfg["proxies"] = all_proxies

    # имена новых нод (по сравнению с тем, что было)
    old_names = {p.get("name") for p in base_cfg.get("proxies", [])}
    new_names = {p.get("name") for p in new_proxies if p.get("name")}
    actually_new = sorted(list(new_names))  # просто вернём инфу

    return base_cfg, actually_new

def add_to_groups(cfg, proxy_names):
    if not proxy_names:
        return
    for g in cfg.get("proxy-groups", []):
        if g.get("type") == "select" and g.get("name") in GROUPS_TO_FILL:
            g.setdefault("proxies", [])
            # добавим только то, чего не было
            existed = set(g["proxies"])
            for n in proxy_names:
                if n not in existed:
                    g["proxies"].append(n)

def main():
    # загрузим базовый конфиг
    if not TARGET_YAML.exists():
        print(f"{TARGET_YAML} not found")
        sys.exit(1)

    base_cfg = yaml.load(TARGET_YAML.read_text(encoding="utf-8"))
    base_cfg = ensure_lists(base_cfg)

    urls = read_lines()
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

    # бэкап и запись
    TARGET_YAML.replace(BACKUP_YAML)
    with TARGET_YAML.open("w", encoding="utf-8") as f:
        yaml.dump(base_cfg, f)

    print(f"Готово. Добавлено/обновлено {len(new_names)} узлов.")

if __name__ == "__main__":
    main()
