from .tool import Tool
import os

class TplmapScanner(Tool):
    def __init__(self):
        super().__init__(
            image="sqlmap",
            dockerfile_path=os.path.join(os.path.dirname(__file__), "../../Dockerfiles/tplmap"),
            results_dir=os.path.join(os.path.dirname(__file__), "../../results/tplmap")
        )

    def scan(self, uri: str):
        self.ensure_image()

        results_file = os.path.join(self.results_path, "results.json")
        if os.path.exists(results_file):
            os.remove(results_file)

        self.run_container(
            command=f"-u {uri} "
        )