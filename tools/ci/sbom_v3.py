#!/usr/bin/env python3
"""Generate an SPDX 3.0.1 JSON-LD inventory from Cargo's resolved production graph.

This is a source/build inventory only. It does not emit VEX or infer vulnerability
status, license conclusions, or contents of an unbuilt WDK driver binary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import sbom

CONTEXT = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
SPEC_VERSION = "3.0.1"


def _uri(namespace: str, identifier: str) -> str:
    return f"{namespace}#{identifier}"


def _relationship_id(source: str, target: str) -> str:
    digest = hashlib.sha256(f"{source}\0{target}".encode("utf-8")).hexdigest()[:16]
    return f"Relationship-{digest}"


def build_document(
    metadata: dict,
    *,
    created: str | None = None,
    namespace: str | None = None,
    version_override: str | None = None,
) -> dict:
    """Build a SPDX 3.0.1 document using SPDX 2.3 inventory's resolved graph."""
    v2 = sbom.build_document(
        metadata,
        created=created,
        namespace=namespace,
        version_override=version_override,
    )
    created = v2["creationInfo"]["created"]
    namespace = v2["documentNamespace"]

    creation_info_id = "_:balancifyCreationInfo"
    creator_id = _uri(namespace, "Creator")
    tool_id = _uri(namespace, "Generator")
    document_id = _uri(namespace, "Document")
    sbom_id = _uri(namespace, "SBOM")

    package_by_spdx_id = {package["SPDXID"]: package for package in v2["packages"]}
    package_uris = {
        spdx_id: _uri(namespace, spdx_id)
        for spdx_id in package_by_spdx_id
    }
    root_ids = {
        relationship["relatedSpdxElement"]
        for relationship in v2["relationships"]
        if relationship["spdxElementId"] == "SPDXRef-DOCUMENT"
        and relationship["relationshipType"] == "DESCRIBES"
    }
    missing_roots = root_ids - package_uris.keys()
    if missing_roots:
        raise ValueError(f"SPDX 2 inventory roots have no package: {sorted(missing_roots)}")

    graph: list[dict] = [
        {
            "@id": creation_info_id,
            "type": "CreationInfo",
            "specVersion": SPEC_VERSION,
            "created": created,
            "createdBy": [creator_id],
            "createdUsing": [tool_id],
            "comment": (
                "Generated from cargo metadata --locked. Declared manifest license "
                "strings are not independent legal conclusions."
            ),
        },
        {
            "type": "Organization",
            "spdxId": creator_id,
            "name": "Balancify",
            "creationInfo": creation_info_id,
        },
        {
            "type": "Tool",
            "spdxId": tool_id,
            "name": "balancify-sbom-v3",
            "creationInfo": creation_info_id,
        },
    ]

    for package in v2["packages"]:
        spdx_id = package["SPDXID"]
        is_driver_source = spdx_id == sbom.DRIVER_ID
        element = {
            "type": "software_Package",
            "spdxId": package_uris[spdx_id],
            "creationInfo": creation_info_id,
            "name": package["name"],
            "software_primaryPurpose": (
                "source" if is_driver_source else package["primaryPackagePurpose"].lower()
            ),
            "software_sourceInfo": package["sourceInfo"],
        }
        if package.get("versionInfo"):
            element["software_packageVersion"] = package["versionInfo"]
        if package.get("downloadLocation") not in (None, "NOASSERTION"):
            element["software_downloadLocation"] = package["downloadLocation"]
        for reference in package.get("externalRefs", []):
            if reference.get("referenceType") == "purl":
                element["software_packageUrl"] = reference["referenceLocator"]
                break
        hashes = [
            {
                "type": "Hash",
                "algorithm": checksum["algorithm"].lower(),
                "hashValue": checksum["checksumValue"],
            }
            for checksum in package.get("checksums", [])
        ]
        if hashes:
            element["verifiedUsing"] = hashes
        if package.get("licenseDeclared") not in (None, "NOASSERTION"):
            element["comment"] = (
                "Cargo manifest license metadata (not an independent legal conclusion): "
                + package["licenseDeclared"]
            )
        graph.append(element)

    relationship_ids: list[str] = []
    for relationship in v2["relationships"]:
        if relationship["relationshipType"] != "DEPENDS_ON":
            continue
        source_id = relationship["spdxElementId"]
        target_id = relationship["relatedSpdxElement"]
        if source_id not in package_uris or target_id not in package_uris:
            raise ValueError(f"dependency edge references an unknown package: {source_id} -> {target_id}")
        relationship_id = _relationship_id(source_id, target_id)
        relationship_uri = _uri(namespace, relationship_id)
        relationship_ids.append(relationship_uri)
        graph.append({
            "type": "Relationship",
            "spdxId": relationship_uri,
            "creationInfo": creation_info_id,
            "from": package_uris[source_id],
            "to": [package_uris[target_id]],
            "relationshipType": "dependsOn",
        })

    root_uris = sorted(package_uris[spdx_id] for spdx_id in root_ids)
    content_uris = sorted(package_uris.values()) + sorted(relationship_ids)
    graph.extend([
        {
            "type": "software_Sbom",
            "spdxId": sbom_id,
            "creationInfo": creation_info_id,
            "name": "Balancify source/build dependency inventory",
            # SPDX 3 models an SBOM's type as a set, even for a single value.
            "software_sbomType": ["source"],
            "element": content_uris,
            "rootElement": root_uris,
            "comment": (
                "Resolved Cargo production dependency graph plus first-party NDIS/WDF source. "
                "No WDK driver binary or vulnerability assessment is represented."
            ),
        },
        {
            "type": "SpdxDocument",
            "spdxId": document_id,
            "creationInfo": creation_info_id,
            "name": "Balancify SPDX 3.0.1 inventory",
            "profileConformance": ["core", "software"],
            "element": sorted([sbom_id, creator_id, tool_id, *content_uris]),
            "rootElement": root_uris,
            "comment": (
                "Inventory only. No VEX document or vulnerability-status claims are included."
            ),
        },
    ])

    return {"@context": CONTEXT, "@graph": graph}


def write_atomic(path: Path, document: dict) -> None:
    sbom.write_atomic(path, document)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", nargs="?", help="optional first-party release version override")
    parser.add_argument("output", nargs="?", default="sbom.spdx3.json")
    args = parser.parse_args(argv)
    output = Path(args.output)
    if not output.is_absolute():
        output = sbom.ROOT / output
    try:
        document = build_document(sbom.cargo_metadata(), version_override=args.version)
        write_atomic(output, document)
    except (RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"SPDX 3.0.1 SBOM generation failed: {exc}", file=sys.stderr)
        return 1
    print(f"SPDX 3.0.1 SBOM generated: {output}")
    print(f"Graph elements: {len(document['@graph'])}")
    print("VEX was not generated; no vulnerability status is asserted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
