import json
import tempfile
import unittest
from pathlib import Path

from sbom_v3 import CONTEXT, SPEC_VERSION, build_document, write_atomic


class SbomV3GenerationTests(unittest.TestCase):
    def setUp(self):
        self.metadata = {
            "workspace_members": ["path+file:///repo#balancify-core@0.1.0"],
            "packages": [
                {
                    "id": "path+file:///repo#balancify-core@0.1.0",
                    "name": "balancify-core",
                    "version": "0.1.0",
                    "source": None,
                    "license": "Proprietary",
                    "checksum": None,
                    "targets": [{"kind": ["lib"]}],
                },
                {
                    "id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0",
                    "name": "serde",
                    "version": "1.0.0",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "license": "MIT OR Apache-2.0",
                    "checksum": "a" * 64,
                    "targets": [{"kind": ["lib"]}],
                },
                {
                    "id": "registry+https://github.com/rust-lang/crates.io-index#test-only@0.1.0",
                    "name": "test-only",
                    "version": "0.1.0",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "license": "MIT",
                    "checksum": "b" * 64,
                    "targets": [{"kind": ["lib"]}],
                },
            ],
            "resolve": {
                "nodes": [
                    {
                        "id": "path+file:///repo#balancify-core@0.1.0",
                        "deps": [
                            {
                                "pkg": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0",
                                "dep_kinds": [{"kind": None}],
                            },
                            {
                                "pkg": "registry+https://github.com/rust-lang/crates.io-index#test-only@0.1.0",
                                "dep_kinds": [{"kind": "dev"}],
                            },
                        ],
                    },
                    {"id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0", "deps": []},
                    {"id": "registry+https://github.com/rust-lang/crates.io-index#test-only@0.1.0", "deps": []},
                ]
            },
        }

    def test_uses_official_301_context_and_locked_production_graph(self):
        document = build_document(
            self.metadata,
            created="2026-10-21T00:00:00Z",
            namespace="https://example.test/spdx/balancify",
        )
        self.assertEqual(document["@context"], CONTEXT)
        self.assertEqual(SPEC_VERSION, "3.0.1")
        elements = document["@graph"]
        packages = [e for e in elements if e.get("type") == "software_Package"]
        names = {package["name"] for package in packages}
        self.assertIn("serde", names)
        self.assertIn("balancify-core", names)
        self.assertIn("balancify-driver-source", names)
        self.assertNotIn("test-only", names)
        driver = next(p for p in packages if p["name"] == "balancify-driver-source")
        self.assertEqual(driver["software_primaryPurpose"], "source")
        self.assertIn("no WDK binary", driver["software_sourceInfo"])
        sbom = next(e for e in elements if e.get("type") == "software_Sbom")
        self.assertEqual(sbom["software_sbomType"], ["source"])
        self.assertIsInstance(sbom["software_sbomType"], list)

    def test_preserves_hashes_purls_and_dependency_relationships(self):
        graph = build_document(
            self.metadata,
            created="2026-10-21T00:00:00Z",
            namespace="https://example.test/spdx/balancify",
        )["@graph"]
        serde = next(e for e in graph if e.get("name") == "serde")
        self.assertEqual(serde["verifiedUsing"][0]["algorithm"], "sha256")
        self.assertEqual(serde["verifiedUsing"][0]["hashValue"], "a" * 64)
        self.assertEqual(serde["software_packageUrl"], "pkg:cargo/serde@1.0.0")
        core = next(e for e in graph if e.get("name") == "balancify-core")
        edge = next(e for e in graph if e.get("type") == "Relationship")
        self.assertEqual(edge["from"], core["spdxId"])
        self.assertEqual(edge["to"], [serde["spdxId"]])
        self.assertEqual(edge["relationshipType"], "dependsOn")

    def test_document_graph_references_are_closed_and_no_vex_is_invented(self):
        document = build_document(
            self.metadata,
            created="2026-10-21T00:00:00Z",
            namespace="https://example.test/spdx/balancify",
        )
        graph = document["@graph"]
        ids = {element.get("spdxId") for element in graph if element.get("spdxId")}
        ids.update(element.get("@id") for element in graph if element.get("@id"))
        self.assertEqual(len(ids), sum(1 for e in graph if e.get("spdxId") or e.get("@id")))
        creation_info = next(e for e in graph if e.get("type") == "CreationInfo")
        self.assertEqual(creation_info["specVersion"], SPEC_VERSION)
        self.assertIn(creation_info["createdBy"][0], ids)
        self.assertIn(creation_info["createdUsing"][0], ids)
        for element in graph:
            if "creationInfo" in element:
                self.assertIn(element["creationInfo"], ids)
            for key in ("element", "rootElement", "to"):
                if key in element:
                    self.assertTrue(set(element[key]).issubset(ids), key)
            if "from" in element:
                self.assertIn(element["from"], ids)
        self.assertFalse(any("vex" in key.lower() or "vulnerability" in key.lower()
                             for element in graph for key in element))
        self.assertFalse(any("CVE-" in str(element) for element in graph))

    def test_atomic_writer_creates_parseable_jsonld(self):
        document = build_document(self.metadata, namespace="https://example.test/spdx/balancify")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "sbom.spdx3.json"
            write_atomic(output, document)
            parsed = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(parsed["@context"], CONTEXT)
            self.assertFalse(list(Path(directory).glob("*.tmp")))

    def test_refuses_metadata_without_resolved_graph(self):
        with self.assertRaisesRegex(ValueError, "resolved dependency graph"):
            build_document({"workspace_members": [], "packages": [], "resolve": None})


if __name__ == "__main__":
    unittest.main()
