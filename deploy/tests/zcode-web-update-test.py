"""Exercise entrypoint persistence with fake executables in an isolated directory."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class ZCodeWebUpdateTest(unittest.TestCase):
    def test_persistent_upgrade_and_recreation(self):
        source = Path(__file__).resolve().parents[1] / "docker-entrypoint.sh"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = root / "app"
            app.mkdir()
            mock_bin = root / "bin"
            mock_bin.mkdir()
            (mock_bin / "id").write_text("#!/bin/sh\necho 1000\n")
            (mock_bin / "id").chmod(0o755)
            entrypoint = root / "entrypoint.sh"
            # Relocate fixed container paths; execute the production shell logic.
            entrypoint.write_text(source.read_text().replace("/app/", str(app) + "/"))
            env = dict(os.environ, PATH=str(mock_bin) + os.pathsep + os.environ["PATH"],
                       SUB2API_UPDATE_CHANNEL="zcode")

            def binary(path, version, channel="zcode"):
                path.write_text(f"#!/bin/sh\necho 'Sub2API {version} (build_type: {channel})'\n")
                path.chmod(0o755)

            def run():
                return subprocess.run(["/bin/sh", str(entrypoint), str(app / "sub2api")],
                                      env=env, text=True, capture_output=True, check=False)

            binary(app / "sub2api", "1-zcode.1")
            self.assertIn("1-zcode.1", run().stdout)
            persistent = app / "data/zcode-bin/sub2api"
            self.assertTrue(persistent.exists())
            # The updater atomically replaces this executable; the image stays old.
            binary(persistent.with_suffix(".new"), "1-zcode.2")
            persistent.with_suffix(".new").replace(persistent)
            self.assertIn("1-zcode.2", run().stdout)
            # Recreating with another image must preserve the volume's web update.
            binary(app / "sub2api", "1-zcode.1-recreated")
            self.assertIn("1-zcode.2", run().stdout)
            binary(persistent, "ordinary", "release")
            self.assertNotEqual(0, run().returncode)
            env["SUB2API_UPDATE_CHANNEL"] = "release"
            self.assertIn("1-zcode.1-recreated", run().stdout)


if __name__ == "__main__":
    unittest.main()
