import copy
import json
from pathlib import Path

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas" / "attack-tree.schema.json"
MAX_DEPTH = 5
MAX_NODES = 40


class AttackTreeError(Exception):
    pass


def base_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text())


def reply_schema(goals: list[str], names: list[str], asvs: list[str]) -> dict:
    """The tree schema the model must satisfy: root goal from an abuse case, elements and ASVS ids pinned."""
    schema = base_schema()
    defs = schema["$defs"]
    node = defs["node"]
    node["properties"].pop("leaf_threat_id")
    node["properties"]["element"] = {"enum": names}
    defs["mitigation"]["properties"]["asvs_refs"]["items"] = {"enum": asvs}
    root = copy.deepcopy(node)
    root["properties"]["goal"] = {"enum": goals}
    defs["root"] = root
    return {
        "$schema": schema["$schema"],
        "type": "object",
        "additionalProperties": False,
        "required": ["root"],
        "properties": {"root": {"$ref": "#/$defs/root"}},
        "$defs": defs,
    }


def _walk(node: dict, depth: int = 1):
    yield node, depth
    for child in node["children"]:
        yield from _walk(child, depth + 1)


def check_shape(tree: dict) -> None:
    nodes = list(_walk(tree["root"]))
    if len(nodes) > MAX_NODES:
        raise AttackTreeError(f"attack tree for {tree['feature_id']} has {len(nodes)} nodes, the limit is {MAX_NODES}")
    deepest = max(depth for _, depth in nodes)
    if deepest > MAX_DEPTH:
        raise AttackTreeError(f"attack tree for {tree['feature_id']} is {deepest} levels deep, the limit is {MAX_DEPTH}")
    if not tree["root"]["children"]:
        raise AttackTreeError(f"attack tree for {tree['feature_id']} has no steps below its root goal")


def leaves(tree: dict) -> list[dict]:
    return [node for node, _ in _walk(tree["root"]) if not node["children"]]


def threat_items(tree: dict) -> list[dict]:
    """Each leaf as a stride-shaped reply item, in depth-first order. The feature id is the category."""
    return [
        {
            "previous_id": leaf.get("previous_id"),
            "category": tree["feature_id"],
            "element": leaf["element"],
            "title": leaf["goal"],
            "description": leaf["description"],
            "likelihood": leaf["likelihood"],
            "impact": leaf["impact"],
            "mitigations": leaf["mitigations"],
            "status": "open",
        }
        for leaf in leaves(tree)
    ]


def with_leaf_ids(tree: dict, ids: list[str]) -> dict:
    result = copy.deepcopy(tree)
    found = leaves(result)
    if len(found) != len(ids):
        raise AttackTreeError(f"{len(found)} leaves but {len(ids)} threat ids")
    for leaf, threat_id in zip(found, ids):
        leaf["leaf_threat_id"] = threat_id
        leaf.pop("previous_id", None)
    return result


def _label(text: str) -> str:
    text = " ".join(str(text).split()).replace("`", "'")
    for char, entity in (("#", "#35;"), ("&", "#amp;"), ('"', "#quot;"), ("<", "#lt;"), (">", "#gt;")):
        text = text.replace(char, entity)
    return text


def render_mermaid(tree: dict, severities: dict[str, str] | None = None) -> str:
    severities = severities or {}
    lines = ["flowchart TD"]
    edges, mitigations = [], []
    counter = {"node": 0, "mitigation": 0}

    def add(node: dict) -> str:
        name = f"n{counter['node']}"
        counter["node"] += 1
        goal = _label(node["goal"])
        if node["children"]:
            label = f'{node["type"].upper()}: {goal}'
            shape = f'{{{{"{label}"}}}}' if node["type"] == "and" else f'(["{label}"])'
        else:
            label = goal
            threat_id = node.get("leaf_threat_id")
            if threat_id:
                label += f"<br/>{threat_id}" + (f" ({severities[threat_id]})" if threat_id in severities else "")
            shape = f'["{label}"]'
        lines.append(f"    {name}{shape}")
        for mitigation in node["mitigations"]:
            counter["mitigation"] += 1
            mname = f"m{counter['mitigation']}"
            lines.append(f'    {mname}["Mitigation: {_label(mitigation["text"])}"]')
            mitigations.append(mname)
            edges.append(f"    {name} -.-> {mname}")
        for child in node["children"]:
            edges.append(f"    {name} --> {add(child)}")
        return name

    add(tree["root"])
    lines += edges
    if mitigations:
        lines += ["    classDef mitigation stroke-dasharray: 4 2", f"    class {','.join(mitigations)} mitigation"]
    return "\n".join(lines) + "\n"


def render_markdown(tree: dict, feature_name: str, severities: dict[str, str] | None = None) -> str:
    title = " ".join(feature_name.split()).replace("`", "'") or tree["feature_id"]
    return (f"# Attack tree: {title} ({tree['feature_id']})\n\n"
            f"Root goal: {' '.join(tree['root']['goal'].split()).replace(chr(96), chr(39))}\n\n"
            f"```mermaid\n{render_mermaid(tree, severities)}```\n")
