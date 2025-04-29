from .tool import Tool
import os


SUBDOMAINS_WORDLIST = os.path.join(os.path.dirname(__file__), "../../wordlists/directory-list.txt")
DIRS_WORDLIST=os.path.join(os.path.dirname(__file__), "../../wordlists/subdomain-list.txt")


class GoBusterScanner(Tool):
    def __init__(self):
        super().__init__(
            image="gobuster",
            dockerfile_path=os.path.join(os.path.dirname(__file__), "../../Dockerfiles/gobuster"),
            results_dir=os.path.join(os.path.dirname(__file__), "../../results/gobuster")
        )

    def scan_subdomains(self, target: str, wordlist: str = SUBDOMAINS_WORDLIST):
        wordlist_dir: str = os.path.dirname(wordlist)
        wordlist_filename: str = os.path.basename(wordlist)

        cmd: str = (
            f"dns -d {target} "
            f"-w /wordlists/{wordlist_filename} "
            f"-o /results/subdomains_results.json -q"
        )
        volumes = {
            wordlist_dir: {"bind": "/wordlists", "mode": "ro"}
        }

        self.ensure_image()
        self.run_container(
            command=cmd,
            extra_volumes=volumes
        )

    def scan_directories(self, target: str, wordlist: str = DIRS_WORDLIST):
        wordlist_dir: str = os.path.dirname(wordlist)
        wordlist_filename: str = os.path.basename(wordlist)

        cmd: str = (
            f"dir -u {target} "
            f"-w /wordlists/{wordlist_filename} "
            f"-o /results/directories_results.json "
            f"-f -q -z -e -t 20 -k -x php,html"
        )
        volumes = {
            wordlist_dir: {"bind": "/wordlists", "mode": "ro"}
        }

        self.ensure_image()
        self.run_container(
            command=cmd,
            extra_volumes=volumes
        )