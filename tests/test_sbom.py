import json
from pathlib import Path

import pytest

from factory import sbom
from factory.sbom import SbomError

FIXTURES = Path(__file__).resolve().parent / "fixtures"
OLD = FIXTURES / "sbom-old.cdx.json"
NEW = FIXTURES / "sbom-new.cdx.json"


def test_components_lists_name_version_purl_including_nested():
    items = sbom.components(OLD)
    assert {"name": "qs", "version": "6.11.0", "purl": "pkg:npm/qs@6.11.0"} in items
    assert {"name": "@types/node", "version": "20.11.0", "purl": "pkg:npm/%40types/node@20.11.0"} in items
    assert len(items) == 8
    assert all(set(c) == {"name", "version", "purl"} for c in items)
    assert "factory-test-web" not in {c["name"] for c in items}


def test_components_are_sorted_and_deduped(tmp_path):
    path = tmp_path / "bom.json"
    path.write_text(json.dumps({
        "bomFormat": "CycloneDX",
        "components": [
            {"name": "b", "version": "1"},
            {"name": "a", "version": "2", "purl": "pkg:npm/a@2"},
            {"name": "b", "version": "1"},
            {"version": "9"},
        ],
    }))
    assert sbom.components(path) == [
        {"name": "a", "version": "2", "purl": "pkg:npm/a@2"},
        {"name": "b", "version": "1", "purl": ""},
    ]


@pytest.mark.parametrize(
    "component, key",
    [
        ({"name": "express", "purl": "pkg:npm/express@4.19.2"}, "pkg:npm/express"),
        ({"name": "@types/node", "purl": "pkg:npm/%40types/node@20.11.0"}, "pkg:npm/%40types/node"),
        ({"name": "lodash", "purl": "pkg:npm/lodash@4.17.21?vcs_url=x#sub/path"}, "pkg:npm/lodash"),
        ({"name": "nopurl", "purl": ""}, "nopurl"),
    ],
)
def test_package_key_strips_version_and_qualifiers(component, key):
    assert sbom.package_key(component) == key


def test_diff_reports_added_removed_changed():
    result = sbom.diff(sbom.components(OLD), sbom.components(NEW))
    assert result["added"] == [
        {"name": "helmet", "version": "7.1.0", "purl": "pkg:npm/helmet@7.1.0"},
        {"name": "debug", "version": "1.0.0", "purl": "pkg:pypi/debug@1.0.0"},
    ]
    assert result["removed"] == [
        {"name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"},
    ]
    assert result["changed"] == [
        {"name": "debug", "old_versions": ["2.6.9", "4.3.4"], "new_versions": ["4.3.4"]},
        {"name": "express", "old_versions": ["4.19.2"], "new_versions": ["4.21.0"]},
        {"name": "lodash", "old_versions": ["4.17.20"], "new_versions": ["4.17.21"]},
    ]


def test_diff_of_identical_boms_is_empty():
    items = sbom.components(NEW)
    assert sbom.diff(items, items) == {"added": [], "removed": [], "changed": []}


def test_rejects_non_cyclonedx(tmp_path):
    path = tmp_path / "spdx.json"
    path.write_text(json.dumps({"spdxVersion": "SPDX-2.3"}))
    with pytest.raises(SbomError, match="not a CycloneDX"):
        sbom.components(path)
    path.write_text("{")
    with pytest.raises(SbomError, match="not valid JSON"):
        sbom.components(path)


def test_main_diff_prints_json(capsys):
    assert sbom.main(["diff", str(OLD), str(NEW)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert [c["name"] for c in out["removed"]] == ["left-pad"]


def test_main_components_prints_json(capsys):
    assert sbom.main(["components", str(NEW)]) == 0
    assert len(json.loads(capsys.readouterr().out)) == 8


def test_main_missing_file(tmp_path, capsys):
    assert sbom.main(["components", str(tmp_path / "missing.json")]) == 1
    assert "error:" in capsys.readouterr().err
