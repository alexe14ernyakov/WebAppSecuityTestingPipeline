from .tool import Tool
import os

class CMSscanTool(Tool):
    def __init__(self):
        super().__init__(
            image="cmsscan",
            dockerfile_path=os.path.join(os.path.dirname(__file__), "../../Dockerfiles/cmsscan"),
            results_dir=os.path.join(os.path.dirname(__file__), "../../results/cmsscan")
        )

    def scan(self, target: str):
        self.ensure_image()

        self.run_container(
            command=(
                f"--url {target} "
                f"--output-format json "
                f"--output /results/results.json"
            )
        )