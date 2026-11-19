"""Render the chart and assert the restricted security defaults."""
import shutil
import subprocess
import unittest
from pathlib import Path

CHART = Path(__file__).resolve().parents[1] / "chart" / "vaultwarden-eso-bridge"


@unittest.skipUnless(shutil.which("helm"), "helm not installed")
class ChartSecurityDefaultsTest(unittest.TestCase):
    def _deployment(self, *extra):
        out = subprocess.run(
            ["helm", "template", "t", str(CHART), *extra, "--show-only", "templates/deployment.yaml"],
            check=True, capture_output=True, text=True,
        ).stdout
        return out

    def test_defaults_are_restricted(self):
        out = self._deployment()
        for needle in (
            "runAsNonRoot: true",
            "allowPrivilegeEscalation: false",
            "readOnlyRootFilesystem: true",
            "type: RuntimeDefault",
            "- ALL",
            "mountPath: /data",
            "mountPath: /tmp",
            "memory: 512Mi",
        ):
            self.assertIn(needle, out)

    def test_security_context_overridable(self):
        out = self._deployment("--set", "securityContext.readOnlyRootFilesystem=false")
        self.assertIn("readOnlyRootFilesystem: false", out)


if __name__ == "__main__":
    unittest.main()
