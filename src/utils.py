import re
import sys
import requests
import json


SUPPORTED_CMS = [
    "WordPress",
    "Joomla",
    "Drupal",
    "Magento",
    "vBulletin",
    "OpenCart",
    "phpBB",
    "Typo3"
]


def normalize_target(address: str, port: int | None, tls: bool | None) -> dict:
    schema_pattern: re.Pattern = re.compile(r'^(http[s]?)://')
    match_schema: re.Match | None = schema_pattern.match(address)

    if match_schema:
        if tls is None:
            scheme: str = match_schema.group(1)
        else:
            if match_schema.group(1) == 'https' and tls:
                scheme: str = match_schema.group(1)          
            elif match_schema.group(1) == 'http' and not tls:
                scheme: str = match_schema.group(1)
            else:
                print("[!] Error: incompatible protocol in address and --http(s) flag.")
                sys.exit(1)
        address = address[len(scheme)+3:]
    else:
        if tls is None or tls:
            scheme: str = "https"
        else:
            scheme: str = "http"

    if ":" in address:
        parts: list = address.split(':')

        if len(parts) != 2:
            print("[!] Error: incorrect target format. Expected: [http(s)://]target.domain[:port]")
            sys.exit(1)
        else:
            if int(port) != int(parts[1]):
                print("[!] Error: incompatible port in address and --port flag.")
                sys.exit(1)
            address = address[:len(address)-len(port)]
    else:
        if port is None:
            port = 443

    return {
        "host": address,
        "port": port,
        "scheme": scheme,
        "url": f"{scheme}://{address}:{port}"
    }


def check_accessibility(url: str) -> bool:
    try:
        _ = requests.get(url, timeout=10)
        return True
    except requests.RequestException:
        return False
    

def check_cms_support(whatweb_report: str) -> bool:
    try:
        with open(whatweb_report, "r", encoding="utf-8") as file:
            content = file.read().lower()
        for cms in SUPPORTED_CMS:
            if cms.lower() in content:
                return True
        return False
    except Exception as e:
        print(f"[!] Error searching for CMS in WhatWeb report: {e}")
        return False
    

def find_queried_uris(zap_report: str) -> set:
    with open(zap_report, encoding='utf-8') as f:
        data = json.load(f)

    uris = set()

    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            for instance in alert.get("instances", []):
                uri = instance.get("uri", "")
                if "?" in uri:
                    uris.add(uri)

    return sorted(uris)


def gerenate_report() -> None:
    pass