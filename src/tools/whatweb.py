from .tool import Tool
import os

class WhatWebScanner(Tool):
    def __init__(self):
        super().__init__(
            image="whatweb",
            dockerfile_path=os.path.join(os.path.dirname(__file__), "../../Dockerfiles/whatweb"),
            results_dir=os.path.join(os.path.dirname(__file__), "../../results/whatweb")
        )

    def scan(self, target: str, aggression: int):
        self.ensure_image()

        results_file = os.path.join(self.results_path, "results.json")
        if os.path.exists(results_file):
            os.remove(results_file)

        self.run_container(
            command=f"-a {aggression} {target} --log-json-verbose=/results/results.json"
        )