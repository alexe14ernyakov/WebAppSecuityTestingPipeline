from .tool import Tool
import os

class SslyzeScanner(Tool):
    def __init__(self):
        super().__init__(
            image="sslyze",
            dockerfile_path=os.path.join(os.path.dirname(__file__), "../../Dockerfiles/sslyze"),
            results_dir=os.path.join(os.path.dirname(__file__), "../../results/sslyze")
        )

    def scan(self, target: str):
        self.ensure_image()

        self.run_container(
            command=(
                f"--regular "
                f"--json_out /results/results.json"
                f"--certinfo --tlsv1_2 --tlsv1_3 "
                f"--http_headers --compression "
                f"{target} "
            )
        )