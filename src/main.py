import argparse
import utils
import sys
import os
import time

from tools.whatweb import WhatWebScanner
from tools.cmsscan import CMSscanTool
from tools.nikto import NiktoScanner
from tools.gobuster import GoBusterScanner
from tools.zap import OwaspZapScanner
from tools.sqlmap import SQLmapScanner
from tools.tplmap import TplmapScanner
from tools.sslyze import SslyzeScanner

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Automated web-application security testing pipleline', 
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        '-t', '--target',
        help='Address of the target web-application',
        required=True,
        dest='addr', type=str
    )
    parser.add_argument(
        '-p', '--port',
        help='Port of the testing web-application',
        required=False,
        dest='port', type=int
    )
    https_group = parser.add_mutually_exclusive_group()
    https_group.add_argument(
        '--http',
        action='store_false', 
        help='Use HTTP in testing process',
        dest='tls'
    )
    https_group.add_argument(
        '--https', 
        action='store_true', 
        help='Use HTTPS in testing process',
        dest='tls'
    )
    parser.add_argument(
        '--whatweb-aggression',
        help='''Aggression levels are:
                1. Stealthy     Makes one HTTP request per target. Also follows redirects.\n
                3. Aggressive   If a level 1 plugin is matched, additional requests will be made.\n
                4. Heavy        Makes a lot of HTTP requests per target. Aggressive tests from''',
        required=False,
        dest='wwagr', type= int,
        default=3
    )
    parser.add_argument(
        '--subdomains-wordlist',
        help='Path to the subdomains wordlist',
        required=False,
        dest='subdomswordlist', type= str,
        default=os.path.join(os.path.dirname(__file__), "../wordlists/subdomain-list.txt")
    )
    parser.add_argument(
        '--directories-wordlist',
        help='Path to the directories wordlist',
        required=False,
        dest='dirswordlist', type= str,
        default=os.path.join(os.path.dirname(__file__), "../wordlists/directory-list.txt")
    )

    return parser.parse_args()


def main():
    args: argparse.Namespace = parse_args()

    target: dict = utils.normalize_target(args.addr, args.port, args.tls)

    if utils.check_accessibility(target['url']):
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

    '''================================================================================================================================
    |||                                                WHATWEB SCANING                                                              |||
    ================================================================================================================================'''
    start: float = time.time()
    scanners["whatweb"].scan(target["url"].replace('localhost', '127.0.0.1'), args.wwagr)
    print(f"[*] Process took {time.time() - start:.3f} seconds")


    '''================================================================================================================================
    |||                                                CMSSCAN SCANING                                                              |||
    ================================================================================================================================'''
    if utils.check_cms_support(f"../results/whatweb/results.json"):
        start: float = time.time()
        scanners["cmsscan"].scan(target["url"].replace('localhost', '127.0.0.1'))
        print(f"[*] Process took {time.time() - start:.3f} seconds")
    else:
        print("[*] CMSscan skipped. No supported CMS detected.")


    '''================================================================================================================================
    |||                                                NIKTO SCANING                                                                |||
    ================================================================================================================================'''
    start: float = time.time()
    scanners["nikto"].scan(target["url"].replace('localhost', '127.0.0.1'))
    print(f"[*] Process took {time.time() - start:.3f} seconds")


    '''================================================================================================================================
    |||                                          GOBUSTER SUBDOMAIN SEARCH                                                          |||
    ================================================================================================================================'''
    start: float = time.time()
    scanners["gobuster"].scan_subdomains(target["host"].replace('localhost', '127.0.0.1'), args.subdomswordlist)
    print(f"[*] Process took {time.time() - start:.3f} seconds")


    '''================================================================================================================================
    |||                                          GOBUSTER DIRECTORIES SEARCH                                                        |||
    ================================================================================================================================'''
    start: float = time.time()
    scanners["gobuster"].scan_directories(target["url"].replace('localhost', '127.0.0.1'), args.dirswordlist)
    print(f"[*] Process took {time.time() - start:.3f} seconds")


    '''================================================================================================================================
    |||                                           OWASP ZAP DAST + TPL/SQL MAP                                                      |||
    ================================================================================================================================'''
    start: float = time.time()
    try:
        with open("../results/gobuster/subdomains_results.txt", "r") as f:
            subdomains = f.readlines()

        if len(subdomains):
            for subdomain in subdomains:
                scanners["zap"].scan(subdomain.strip())

    except FileNotFoundError:
        print("[*] Subdomains results file not found. Scan only given target with OWASP ZAP.")
    finally:
        scanners["zap"].scan(target["url"].replace('localhost', '127.0.0.1'))

        queried_uris: set = utils.find_queried_uris(f"../results/zap/{target['host'].replace('localhost', '127.0.0.1')}-results.json")
        for uri in queried_uris:
            scanners["sqlmap"].scan(uri.replace('localhost', '127.0.0.1'))
            scanners["tplmap"].scan(uri.replace('localhost', '127.0.0.1'))
    print(f"[*] Process took {time.time() - start:.3f} seconds")


    '''================================================================================================================================
    |||                                                    SSLYZE ANALYSIS                                                          |||
    ================================================================================================================================'''
    if target["scheme"] == "https":
        start: float = time.time()
        addr: str =f"{target['host'].replace('localhost', '127.0.0.1')}:{target['port']}"
        scanners["sslyze"].scan(addr)
        print(f"[*] Process took {time.time() - start:.3f} seconds")
    else:
        print("[*] Skipping sslyze scan. Target is not using HTTPS.")


    '''================================================================================================================================
    |||                                               GENERATING GENERAL REPORT                                                     |||
    ================================================================================================================================'''

    pass

if __name__ == "__main__":
    main()
