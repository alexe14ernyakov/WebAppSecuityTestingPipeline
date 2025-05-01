from .tool import Tool
from urllib.parse import urlparse
import os
import docker

class OwaspZapScanner(Tool):
    def __init__(self):
        super().__init__(
            image="owasp-zap",
            dockerfile_path=os.path.join(os.path.dirname(__file__), "../../Dockerfiles/zap"),
            results_dir=os.path.join(os.path.dirname(__file__), "../../results/zap")
        )

    def run_container(self, command: list[str], extra_volumes: dict = None) -> None:
        print(f"[*] Starting container {self.image}")
        try:
            volumes = {
                self.results_path: {'bind': '/results', 'mode': 'rw'}
            }

            if extra_volumes:
                volumes.update(extra_volumes)

            _ = self.client.containers.run(
                image=self.image,
                command=command,
                remove=True,
                network_mode="host",
                volumes=volumes
            )

            print(f"[+] Scan with {self.image} completed. Results saved to {self.results_path}")
        except docker.errors.ContainerError as e:
            if os.path.exists(f"{self.results_path}/{self.host}-results.json"):
                print(f"[+] Scan with {self.image} completed. Results saved to {self.results_path}")
            else:
                print(f"[!] Container {self.image} execution failed: {e}")
        except Exception as e:
            print(f"[!] Unexpected error during running {self.image}: {e}")

    def scan(self, target: str):
        self.ensure_image()

        self.host: str = urlparse(target).hostname
        cmd: str =(
            f"-t {target} "
            f"-J {self.host}-results.json "
        )
        volumes = {
            self.results_path: {'bind': '/zap/wrk', 'mode': 'rw'}
        }

        self.run_container(
            command=cmd,
            extra_volumes=volumes
        )