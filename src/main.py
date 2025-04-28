import argparse
import utils

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

    return parser.parse_args()


def main():
    args: argparse.Namespace = parse_args()

    target: dict = utils.normalize_target(args.addr, args.port, args.tls)

    if utils.check_accessibility(target['url']):
        print(f"[*] Starting scanning target on {target['url']}")
    else:
        print("[!] Error: could not connect to the target")


if __name__ == "__main__":
    main()
