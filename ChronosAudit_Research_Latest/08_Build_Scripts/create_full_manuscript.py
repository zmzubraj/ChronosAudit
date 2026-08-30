from pathlib import Path
import runpy
runpy.run_path(str(Path(__file__).resolve().parent / "create_submission_manuscript_v2.py"), run_name="__main__")
