from .tool import Tool
import os

class Nikto(Tool):
    def __init__(self):
        super().__init__(
            image="nikto-own",
            dockerfile_path=os.path.join(os.path.dirname(__file__), "../../Dockerfiles/nikto"),
            results_dir=os.path.join(os.path.dirname(__file__), "../../results/nikto")
        )

    def scan(self, target: str):
        self.ensure_image()

        results_file = os.path.join(self.results_path, "results.json")
        if os.path.exists(results_file):
            os.remove(results_file)

        self.run_container(
            command=f"-h {target} -Format json -output /results/results.json"
        )