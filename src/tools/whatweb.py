from .tool import Tool
import os

class WhatWebScanner(Tool):
    def __init__(self):
        super().__init__(
            image="whatweb-own",
            dockerfile_path=os.path.join(os.path.dirname(__file__), "../../Dockerfiles/whatweb"),
            results_dir=os.path.join(os.path.dirname(__file__), "../../results/whatweb")
        )

    def scan(self, target: str, aggression: int):
        self.ensure_image()
        self.run_container(
            command=f"-a {aggression} {target} --log-json-verbose=/results/results.json"
        )