import argparse
import utils
import sys
import os

from tools.whatweb import WhatWebScanner
from tools.nikto import NiktoScanner
from tools.gobuster import GoBusterScanner


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
                1. Stealthy     Makes one HTTP request per target. Also follows redirects.
                3. Aggressive   If a level 1 plugin is matched, additional requests will be made.
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
        "nikto": NiktoScanner(),
        "gobuster": GoBusterScanner()
    }

    #scanners["whatweb"].scan(target["url"].replace('localhost', '127.0.0.1'), args.wwagr)
    #scanners["nikto"].scan(target["url"].replace('localhost', '127.0.0.1'))
    scanners["gobuster"].scan_subdomains(target["host"].replace('localhost', '127.0.0.1'), wordlist=args.subdomswordlist)
    scanners["gobuster"].scan_directories(target["host"].replace('localhost', '127.0.0.1'), wordlist=args.dirswordlist)


if __name__ == "__main__":
    main()
