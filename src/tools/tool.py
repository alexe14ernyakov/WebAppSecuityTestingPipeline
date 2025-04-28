import docker
import sys
import os

import docker.errors


class Tool:
    def __init__(self, image: str, dockerfile_path: str, results_dir: str):
        self.client = docker.from_env()
        self.image = image
        self.dockerfile_path = dockerfile_path
        self.results_path = results_dir
        os.makedirs(self.results_path, exist_ok=True)

    def build_image(self):
        try:
            _, logs = self.client.images.build(
                path=self.dockerfile_path,
                tag=self.image
            )
            for log in logs:
                if "stream" in log:
                    print(log['stream'].strip())
            print(f"[+] Successfully built image {self.image}")
        except docker.errors.BuildError as e:
            print(f"[!] Error building image {self.image}: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Unexpected error during building image {self.image}: {e}")
            sys.exit(1)

    def ensure_image(self):
        try:
            self.client.images.get(self.image)
        except docker.errors.ImageNotFound:
            print(f"[*] Image {self.image} did not found locally. Start building it")
            self.build_image()

    def run_container(self, command: list[str]):
        print(f"[*] Starting container {self.image}")
        try:
            output = self.client.containers.run(
                image=self.image,
                command=command,
                remove=True,
                stdout=True,
                stderr=True,
                volumes={self.results_path: {'bind': '/results', 'mode': 'rw'}}
            )

            print(f"[+] Scan completed. Results saved to {self.results_path}")
        except docker.errors.ContainerError as e:
            print(f"[!] Container {self.image} execution failed: {e}")
        except Exception as e:
            print(f"[!] Unexpected error during running {self.image}: {e}")