import json
import os
import re
import sys

import requests


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


def generate_report() -> None:
    print("[*] Generating general report for analized target")

    base_dir = "../results"
    report = {}

    for root, _, files in os.walk(base_dir):
        if root == base_dir:
            continue

        dir_name = os.path.basename(root)

        if "results.json" in files:
            try:
                with open(os.path.join(root, "results.json"), "r", encoding="utf-8") as f:
                    data = json.load(f)
                report[dir_name] = data
            except Exception as e:
                print(f"[!] Error reading {dir_name}/results.json: {e}")

        if dir_name.lower() == "gobuster":
            gobuster_data = {}
            for fname in ["directories_results.txt", "subdomains_results.txt"]:
                if fname in files:
                    path = os.path.join(root, fname)
                    try:
                        with open(path, "r", encoding="utf-8") as f:
                            gobuster_data[fname] = f.read().splitlines()
                    except Exception as e:
                        print(f"[!] Error reading {path}: {e}")
            if gobuster_data:
                report[dir_name] = gobuster_data

        if dir_name.lower() == "whatweb":
            whatweb_results = []
            for file in files:
                path = os.path.join(root, file)
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        whatweb_results.extend([line.strip() for line in f if line.strip()])
                except Exception as e:
                    print(f"[!] Error reading {path}: {e}")
            if whatweb_results:
                report[dir_name] = whatweb_results

    output_path = os.path.join(base_dir, "general-report.json")
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[!] Error generating general report: {e}")

    print("[*] Report saved to /home/alex/Study/SRW/sanner/results/report.json")
