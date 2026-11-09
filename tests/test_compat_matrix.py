"""Static checks for the ESO / bw CLI compatibility matrix."""

import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "compat_matrix.py"


def _load():
    spec = importlib.util.spec_from_file_location("compat_matrix", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


compat = _load()


CRD_FIXTURE = """
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: clustersecretstores.external-secrets.io
spec:
  versions:
    - additionalPrinterColumns:
        - jsonPath: .status
          name: Status
          type: string
      name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          properties:
                    webhook:
                      description: Webhook configures this store
                      properties:
                        headers:
                          type: object
                        method:
                          type: string
                        result:
                          properties:
                            jsonPath:
                              type: string
                        secrets:
                          type: array
                        url:
                          type: string
    - additionalPrinterColumns:
        - name: Status
      deprecated: true
      name: v1beta1
      served: false
      storage: false
"""


class CompatMatrixTests(unittest.TestCase):
    def test_parse_versions_honors_served_flag(self):
        doc = compat.extract_crd(CRD_FIXTURE, "clustersecretstores.external-secrets.io")
        entries = compat.parse_versions(doc)
        self.assertEqual(
            [(entry["name"], entry["served"], entry["storage"]) for entry in entries],
            [("v1", True, True), ("v1beta1", False, False)],
        )
        self.assertEqual(compat.served_names(entries), ["v1"])

    def test_webhook_schema_requires_contract_fields(self):
        matrix = compat.load_matrix(ROOT)
        doc = compat.extract_crd(CRD_FIXTURE, "clustersecretstores.external-secrets.io")
        errors = compat.check_webhook_blocks(
            compat.webhook_blocks(doc),
            matrix["eso"],
            "fixture",
        )
        self.assertEqual(errors, [])

    def test_webhook_schema_flags_new_service_account_field(self):
        matrix = compat.load_matrix(ROOT)
        doc = CRD_FIXTURE.replace(
            "                        url:\n",
            "                        serviceAccountRef:\n                          type: object\n                        url:\n",
            1,
        )
        extracted = compat.extract_crd(doc, "clustersecretstores.external-secrets.io")
        errors = compat.check_webhook_blocks(
            compat.webhook_blocks(extracted),
            matrix["eso"],
            "fixture",
        )
        self.assertTrue(any("serviceAccountRef" in error for error in errors), errors)

    def test_repo_static_checks_pass(self):
        matrix = compat.load_matrix(ROOT)
        errors = compat.check_static(ROOT, matrix)
        self.assertEqual(errors, [], "\n".join(errors))


if __name__ == "__main__":
    unittest.main()
