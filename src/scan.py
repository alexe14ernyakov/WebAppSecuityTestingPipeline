import os
import sys
import time

from tools.cmsscan import CMSscanTool
from tools.gobuster import GoBusterScanner
from tools.nikto import NiktoScanner
from tools.sqlmap import SQLmapScanner
from tools.sslyze import SslyzeScanner
from tools.tplmap import TplmapScanner
from tools.whatweb import WhatWebScanner
from tools.zap import OwaspZapScanner

import utils


def scan(
    addr: str,
    port: int = None,
    tls: bool = False,
    wwagr: int = 3,
    subdomswordlist: str = "../wordlists/subdomain-list.txt",
    dirswordlist: str = "../wordlists/directory-list.txt"
):
    target: dict = utils.normalize_target(addr, port, tls)

    if utils.check_accessibility(target["url"]):
        print(f"[*] Starting scanning target on {target['url']}")
    else:
        print("[!] Error: could not connect to the target")
        sys.exit(1)

    scanners: dict = {
        "whatweb": WhatWebScanner(),
        "cmsscan": CMSscanTool(),
        "nikto": NiktoScanner(),
        "gobuster": GoBusterScanner(),
        "zap": OwaspZapScanner(),
        "sqlmap": SQLmapScanner(),
        "tplmap": TplmapScanner(),
        "sslyze": SslyzeScanner()
    }

    # ========================================================================
    #                              WHATWEB SCANNING
    # ========================================================================
    start = time.time()
    scanners["whatweb"].scan(target["url"].replace("localhost", "127.0.0.1"), wwagr)
    print(f"[*] Process took {time.time() - start:.3f} seconds")

    # ========================================================================
    #                              CMSSCAN SCANNING
    # ========================================================================
    if utils.check_cms_support("../results/whatweb/results.json"):
        start = time.time()
        scanners["cmsscan"].scan(target["url"].replace("localhost", "127.0.0.1"))
        print(f"[*] Process took {time.time() - start:.3f} seconds")
    else:
        print("[*] CMSscan skipped. No supported CMS detected.")

    # ========================================================================
    #                               NIKTO SCANNING
    # ========================================================================
    start = time.time()
    scanners["nikto"].scan(target["url"].replace("localhost", "127.0.0.1"))
    print(f"[*] Process took {time.time() - start:.3f} seconds")

    # ========================================================================
    #                        GOBUSTER SUBDOMAIN SCANNING
    # ========================================================================
    start = time.time()
    scanners["gobuster"].scan_subdomains(
        target["host"].replace("localhost", "127.0.0.1"),
        os.path.abspath(subdomswordlist)
    )
    print(f"[*] Process took {time.time() - start:.3f} seconds")

    # ========================================================================
    #                       GOBUSTER DIRECTORY SCANNING
    # ========================================================================
    start = time.time()
    scanners["gobuster"].scan_directories(
        target["url"].replace("localhost", "127.0.0.1"),
        os.path.abspath(dirswordlist)
    )
    print(f"[*] Process took {time.time() - start:.3f} seconds")

    # ========================================================================
    #                  ZAP DAST + SQLMAP & TPLMAP VULN SCANS
    # ========================================================================
    start = time.time()
    try:
        with open("../results/gobuster/subdomains_results.txt", "r") as f:
            subdomains = f.readlines()

        if subdomains:
            for subdomain in subdomains:
                scanners["zap"].scan(subdomain.strip())

    except FileNotFoundError:
        print("[*] Subdomains results file not found. Scan only given target with OWASP ZAP.")
    finally:
        scanners["zap"].scan(target["url"].replace("localhost", "127.0.0.1"))

        print("[*] Starting vulnerability scan in query params with sqlmap and tplmap...")
        queried_uris: set = utils.find_queried_uris(
            f"../results/zap/{target['host'].replace('localhost', '127.0.0.1')}-results.json"
        )
        for uri in queried_uris:
            uri = uri.replace("localhost", "127.0.0.1")
            scanners["sqlmap"].scan(uri)
            scanners["tplmap"].scan(uri)

    print(f"[*] Process took {time.time() - start:.3f} seconds")

    # ========================================================================
    #                              SSLYZE ANALYSIS
    # ========================================================================
    if target["scheme"] == "https":
        start = time.time()
        addr = f"{target['host'].replace('localhost', '127.0.0.1')}:{target['port']}"
        scanners["sslyze"].scan(addr)
        print(f"[*] Process took {time.time() - start:.3f} seconds")
    else:
        print("[*] Skipping sslyze scan. Target is not using HTTPS.")

    utils.generate_report()
