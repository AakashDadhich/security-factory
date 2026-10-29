import json
import re

BRANCH_PATTERN = re.compile(r"factory/[0-9]{1,9}")
MAX_PATCH_BYTES = 2 * 1024 * 1024
ALLOWED_NEW_MODES = ("100644", "100755")
SUPPRESSION_MARKERS = ("nosemgrep", "gitleaks:allow")
GUARDED_NAMES = frozenset({
    ".semgrepignore", ".gitleaksignore", ".gitleaks.toml", ".pre-commit-config.yaml",
    ".gitattributes", ".gitmodules", ".npmrc", ".yarnrc", ".yarnrc.yml", ".pnpmrc",
})
AGENT_PROTECTED_FILES = frozenset({"claude.md", "agents.md", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"})
AGENT_PROTECTED_DIRS = ("security",)
DEPENDENCY_KEYS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "bundledDependencies", "overrides")
LIFECYCLE_SCRIPTS = ("preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly", "prepack", "postpack")
DIFF_HEADER = re.compile(r"^diff --git a/(.+) b/(.+)$")


class PolicyError(Exception):
    pass


def branch_name(issue: int) -> str:
    if not isinstance(issue, int) or isinstance(issue, bool) or issue < 1:
        raise PolicyError(f"issue number must be a positive integer, got {issue!r}")
    name = f"factory/{issue}"
    assert_push_target(name)
    return name


def assert_push_target(branch: str, default_branch: str | None = None) -> None:
    if not BRANCH_PATTERN.fullmatch(branch):
        raise PolicyError(f"refusing to push to '{branch}': only factory/<issue number> branches are allowed")
    if default_branch is not None and branch == default_branch:
        raise PolicyError(f"refusing to push to the default branch '{default_branch}'")


def path_violation(path: str) -> str | None:
    if not path or path != path.strip():
        return "empty or padded path"
    if any(ord(c) < 32 or ord(c) == 127 for c in path) or "\\" in path or '"' in path:
        return "control, backslash or quote character in path"
    if path.startswith("/"):
        return "absolute path"
    parts = path.split("/")
    if any(p in ("", ".", "..") for p in parts):
        return "path escapes or is not normalised"
    lowered = [p.lower() for p in parts]
    if ".git" in lowered:
        return "path inside a .git folder"
    if lowered[0] == ".github":
        return "path inside .github"
    name = lowered[-1]
    if lowered[0] == "factory":
        return "folder named like the factory package"
    if name in ("sitecustomize.py", "usercustomize.py") or name.endswith(".pth"):
        return "Python start-up hook"
    if name.startswith(".env") and name != ".env.example":
        return "environment file"
    if name in GUARDED_NAMES:
        return "scanner, hook or package manager configuration"
    return None


def agent_path_violation(path: str) -> str | None:
    reason = path_violation(path)
    if reason:
        return reason
    parts = path.split("/")
    if parts[0].lower() in AGENT_PROTECTED_DIRS:
        return "factory-owned security folder"
    if len(parts) == 1 and parts[0].lower() in AGENT_PROTECTED_FILES:
        return "factory-owned or lock file"
    if parts[-1].lower() in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"):
        return "lock file"
    return None


def package_json_violation(old: str | None, new: str) -> str | None:
    try:
        new_doc = json.loads(new)
    except json.JSONDecodeError:
        return "package.json is not valid JSON"
    old_doc = {}
    if old:
        try:
            old_doc = json.loads(old)
        except json.JSONDecodeError:
            old_doc = {}
    if not isinstance(new_doc, dict) or not isinstance(old_doc, dict):
        return "package.json is not an object"
    for key in DEPENDENCY_KEYS:
        if new_doc.get(key) != old_doc.get(key):
            return f"package.json {key} changed; dependencies cannot be added without a lock file update"
    old_scripts, new_scripts = old_doc.get("scripts") or {}, new_doc.get("scripts") or {}
    if not isinstance(old_scripts, dict) or not isinstance(new_scripts, dict):
        return "package.json scripts is not an object"
    for name in LIFECYCLE_SCRIPTS:
        if new_scripts.get(name) != old_scripts.get(name):
            return f"package.json lifecycle script {name} changed"
    return None


def inspect_patch(patch: str) -> list[str]:
    problems: list[str] = []
    if len(patch.encode()) > MAX_PATCH_BYTES:
        problems.append(f"patch is larger than {MAX_PATCH_BYTES} bytes")
    if "\x00" in patch:
        problems.append("patch contains a NUL byte")
    file_count = 0
    for line in patch.splitlines():
        if line.startswith('diff --git "'):
            problems.append("quoted path in patch header")
            continue
        header = DIFF_HEADER.match(line)
        if header:
            file_count += 1
            old, new = header.groups()
            if old != new:
                problems.append(f"rename or copy of {old} to {new}")
            for path in {old, new}:
                reason = path_violation(path)
                if reason:
                    problems.append(f"{path}: {reason}")
            continue
        if line.startswith(("new file mode ", "new mode ")):
            mode = line.rsplit(" ", 1)[1]
            if mode not in ALLOWED_NEW_MODES:
                problems.append(f"file mode {mode} is not allowed (symlinks and submodules are refused)")
        elif line.startswith(("old mode ", "rename ", "copy ", "similarity index ")):
            problems.append(f"unsupported patch header: {line.split(' ', 2)[0]} {line.split(' ', 2)[1]}")
        elif line.startswith(("GIT binary patch", "Binary files ")):
            problems.append("binary content in patch")
        elif line.startswith("+"):
            lowered = line.lower()
            for marker in SUPPRESSION_MARKERS:
                if marker in lowered:
                    problems.append(f"added line contains scanner suppression marker '{marker}'")
    if file_count == 0 and patch.strip():
        problems.append("patch has no recognisable file headers")
    return list(dict.fromkeys(problems))
