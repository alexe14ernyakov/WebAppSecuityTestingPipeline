from .tool import Tool
from urllib.parse import urlparse
import os

class OwaspZapScanner(Tool):
    def __init__(self):
        super().__init__(
            image="owasp-zap",
            dockerfile_path=os.path.join(os.path.dirname(__file__), "../../Dockerfiles/zap"),
            results_dir=os.path.join(os.path.dirname(__file__), "../../results/zap")
        )

    def scan(self, target: str):
        self.ensure_image()

        host: str = urlparse(target).hostname
        cmd: str =(
            f"-t {target} "
            f"-J {host}-results.json "
        )
        volumes = {
            self.results_path: {'bind': '/zap/wrk', 'mode': 'rw'}
        }

        self.run_container(
            command=cmd,
            extra_volumes=volumes
        )