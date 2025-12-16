import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple


ALLOWED_TYPES = {"task", "adr", "constraint", "runbook", "component_map"}
EVIDENCE_KINDS = {"repo_path", "pr", "issue", "url", "run", "chat"}
PACK_ITEM_KINDS = {"memory_meta", "memory_body", "evidence", "repo_file"}

TYPE_DIR = {
    "task": "tasks",
    "adr": "adr",
    "constraint": "constraints",
    "runbook": "runbooks",
    "component_map": "component_maps",
}

ACTIVE_STATUS = {
    "task": {"active"},
    "adr": {"accepted"},
    "constraint": {"active"},
    "runbook": {"active"},
    "component_map": {"active"},
}


@dataclass(frozen=True)
class MemoryItem:
    id: str
    type: str
    status: str
    title: str
    meta: Dict[str, Any]
    meta_path: str
    body_path: Optional[str]


def _run_git(args: List[str], cwd: Optional[str] = None, text: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
    )


def _git_ok(args: List[str]) -> Tuple[bool, str]:
    proc = _run_git(args, text=True)
    return proc.returncode == 0, (proc.stdout.strip() if proc.stdout else proc.stderr.strip())


def _git_out(args: List[str]) -> str:
    proc = _run_git(args, text=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"git failed: {' '.join(args)}")
    return proc.stdout


def _git_bytes(args: List[str]) -> bytes:
    proc = _run_git(args, text=False)
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace") if isinstance(proc.stderr, (bytes, bytearray)) else str(proc.stderr)
        raise RuntimeError(stderr.strip() or f"git failed: {' '.join(args)}")
    return proc.stdout


def _resolve_commit(commitish: str) -> str:
    return _git_out(["rev-parse", commitish]).strip()


def _ls_tree(commit: str, path: str) -> List[str]:
    out = _git_out(["ls-tree", "-r", "--name-only", commit, "--", path])
    return [line.strip() for line in out.splitlines() if line.strip()]


def _path_exists(commit: str, path: str) -> bool:
    ok, _ = _git_ok(["cat-file", "-e", f"{commit}:{path}"])
    return ok


def _object_type(commit: str, path: str) -> Optional[str]:
    ok, out = _git_ok(["cat-file", "-t", f"{commit}:{path}"])
    if not ok:
        return None
    t = out.strip()
    return t if t else None


def _read_path(commit: str, path: str) -> bytes:
    return _git_bytes(["show", f"{commit}:{path}"])


def _blob_sha(commit: str, path: str) -> str:
    return _git_out(["rev-parse", f"{commit}:{path}"]).strip()


def _tree_sha(commit: str, path: str) -> Optional[str]:
    ok, out = _git_ok(["rev-parse", f"{commit}:{path}"])
    return out.strip() if ok and out.strip() else None


def _last_touch_commit(commit: str, path: str) -> Optional[str]:
    ok, out = _git_ok(["log", "-1", "--format=%H", commit, "--", path])
    return out.strip() if ok and out.strip() else None


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _norm_rel_path(path: str) -> str:
    path = path.strip().replace("\\", "/")
    if "\x00" in path or any(ord(ch) < 32 for ch in path):
        raise ValueError(f"invalid repo-relative path: {path!r}")
    while path.startswith("/"):
        path = path[1:]
    if path == "":
        raise ValueError(f"invalid repo-relative path: {path!r}")
    if ":" in path:
        raise ValueError(f"invalid repo-relative path: {path!r}")

    parts: List[str] = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            raise ValueError(f"invalid repo-relative path: {path!r}")
        parts.append(part)
    if not parts:
        raise ValueError(f"invalid repo-relative path: {path!r}")
    return "/".join(parts)


def _is_active(item: MemoryItem) -> bool:
    return item.status in ACTIVE_STATUS.get(item.type, set())


def load_memory(commit: str) -> Tuple[List[MemoryItem], Dict[str, MemoryItem]]:
    commit = _resolve_commit(commit)
    if not _path_exists(commit, ".ai/memory"):
        return [], {}

    files = _ls_tree(commit, ".ai/memory")
    meta_paths = [p for p in files if p.endswith("/meta.json")]

    items: List[MemoryItem] = []
    by_id: Dict[str, MemoryItem] = {}

    for meta_path in sorted(meta_paths):
        raw = _read_path(commit, meta_path)
        try:
            meta = json.loads(raw.decode("utf-8"))
        except Exception as e:
            raise RuntimeError(f"invalid json: {meta_path}: {e}") from e
        if not isinstance(meta, dict):
            raise RuntimeError(f"invalid json: {meta_path}: meta must be object")

        item_dir = meta_path[: -len("/meta.json")]
        body_path = f"{item_dir}/body.md" if _path_exists(commit, f"{item_dir}/body.md") else None

        item_id = str(meta.get("id", "")).strip()
        item_type = str(meta.get("type", "")).strip()
        item_status = str(meta.get("status", "")).strip()
        item_title = str(meta.get("title", "")).strip()

        item = MemoryItem(
            id=item_id,
            type=item_type,
            status=item_status,
            title=item_title,
            meta=meta,
            meta_path=meta_path,
            body_path=body_path,
        )

        items.append(item)
        if item_id:
            by_id[item_id] = item

    return items, by_id


def validate_memory(commit: str, items: List[MemoryItem], by_id: Dict[str, MemoryItem]) -> List[str]:
    errors: List[str] = []

    def err(msg: str) -> None:
        errors.append(msg)

    seen_ids: Dict[str, str] = {}
    constraint_by_key: Dict[str, str] = {}
    adr_by_topic: Dict[str, str] = {}

    for item in items:
        meta = item.meta

        schema_version = meta.get("schema_version", None)
        if schema_version != 1:
            err(f"{item.meta_path}: schema_version must be 1")

        if not item.id:
            err(f"{item.meta_path}: missing id")
        if not item.type:
            err(f"{item.meta_path}: missing type")
        if item.type and item.type not in ALLOWED_TYPES:
            err(f"{item.meta_path}: invalid type={item.type!r}")
        if not item.status:
            err(f"{item.meta_path}: missing status")
        if not item.title:
            err(f"{item.meta_path}: missing title")

        parts = item.meta_path.split("/")
        if len(parts) >= 5 and parts[0] == ".ai" and parts[1] == "memory":
            type_dir = parts[2]
            entry_dir = parts[3]
            expected_dir = TYPE_DIR.get(item.type)
            if expected_dir and type_dir != expected_dir:
                err(f"{item.meta_path}: type={item.type!r} must live under .ai/memory/{expected_dir}/ (found {type_dir}/)")
            if item.id and not entry_dir.startswith(item.id):
                err(f"{item.meta_path}: entry dir must start with id ({item.id}); found {entry_dir}")

        if item.id:
            if item.id in seen_ids and seen_ids[item.id] != item.meta_path:
                err(f"duplicate id {item.id}: {seen_ids[item.id]} and {item.meta_path}")
            else:
                seen_ids[item.id] = item.meta_path

        scope = meta.get("scope", None)
        if scope is not None and not isinstance(scope, dict):
            err(f"{item.meta_path}: scope must be object")
        if isinstance(scope, dict):
            for k in ("paths", "components"):
                if k in scope and not isinstance(scope[k], list):
                    err(f"{item.meta_path}: scope.{k} must be list")

        watch_paths = meta.get("watch_paths", [])
        if watch_paths is not None and not isinstance(watch_paths, list):
            err(f"{item.meta_path}: watch_paths must be list")

        evidence = meta.get("evidence", None)
        if _is_active(item):
            if not isinstance(evidence, list) or len(evidence) == 0:
                err(f"{item.meta_path}: active/accepted items must have non-empty evidence[]")

        if isinstance(evidence, list):
            for i, ev in enumerate(evidence):
                if not isinstance(ev, dict):
                    err(f"{item.meta_path}: evidence[{i}] must be object")
                    continue
                kind = ev.get("kind", "")
                ref = ev.get("ref", "")
                if kind not in EVIDENCE_KINDS:
                    err(f"{item.meta_path}: evidence[{i}].kind invalid: {kind!r}")
                if not isinstance(ref, str) or not ref.strip():
                    err(f"{item.meta_path}: evidence[{i}].ref must be non-empty string")
                if kind == "repo_path" and isinstance(ref, str) and ref.strip():
                    try:
                        ref_path = _norm_rel_path(ref)
                    except Exception as e:
                        err(f"{item.meta_path}: evidence[{i}].ref invalid repo_path: {e}")
                        continue
                    obj_type = _object_type(commit, ref_path)
                    if obj_type not in ("blob", "tree"):
                        err(
                            f"{item.meta_path}: evidence[{i}].ref repo_path not found as file/dir at {commit}: {ref_path}"
                            if obj_type is None
                            else f"{item.meta_path}: evidence[{i}].ref repo_path must be blob/tree at {commit}: {ref_path} (got {obj_type})"
                        )

        supersedes = meta.get("supersedes", [])
        if supersedes is not None and not isinstance(supersedes, list):
            err(f"{item.meta_path}: supersedes must be list")
        if isinstance(supersedes, list):
            for sid in supersedes:
                if not isinstance(sid, str) or not sid.strip():
                    err(f"{item.meta_path}: supersedes contains non-string/empty id")
                elif sid not in by_id:
                    err(f"{item.meta_path}: supersedes references missing id: {sid}")

        if item.type == "constraint" and _is_active(item):
            key = meta.get("key", None)
            if not isinstance(key, str) or not key.strip():
                err(f"{item.meta_path}: constraint must have non-empty key")
            else:
                if key in constraint_by_key:
                    err(f"constraint.key conflict: {key!r} in {constraint_by_key[key]} and {item.meta_path}")
                constraint_by_key[key] = item.meta_path

        if item.type == "adr" and _is_active(item):
            topic = meta.get("topic", None)
            if not isinstance(topic, str) or not topic.strip():
                err(f"{item.meta_path}: adr must have non-empty topic")
            else:
                if topic in adr_by_topic:
                    err(f"adr.topic conflict: {topic!r} in {adr_by_topic[topic]} and {item.meta_path}")
                adr_by_topic[topic] = item.meta_path

        if item.type == "task":
            pack = meta.get("pack", None)
            if pack is not None and not isinstance(pack, dict):
                err(f"{item.meta_path}: pack must be object")
            if isinstance(pack, dict):
                include_memory_ids = pack.get("include_memory_ids", [])
                include_paths = pack.get("include_paths", [])

                if include_memory_ids is not None and not isinstance(include_memory_ids, list):
                    err(f"{item.meta_path}: pack.include_memory_ids must be list")
                    include_memory_ids = []
                if include_paths is not None and not isinstance(include_paths, list):
                    err(f"{item.meta_path}: pack.include_paths must be list")
                    include_paths = []

                if isinstance(include_memory_ids, list):
                    for j, mid in enumerate(include_memory_ids):
                        if not isinstance(mid, str) or not mid.strip():
                            err(f"{item.meta_path}: pack.include_memory_ids[{j}] must be non-empty string")
                        elif mid not in by_id:
                            err(f"{item.meta_path}: pack.include_memory_ids[{j}] references missing id: {mid}")

                if isinstance(include_paths, list):
                    for j, p in enumerate(include_paths):
                        if not isinstance(p, str) or not p.strip():
                            err(f"{item.meta_path}: pack.include_paths[{j}] must be non-empty string")
                            continue
                        try:
                            p_norm = _norm_rel_path(p)
                        except Exception as e:
                            err(f"{item.meta_path}: pack.include_paths[{j}] invalid path: {e}")
                            continue
                        obj_type = _object_type(commit, p_norm)
                        if obj_type not in ("blob", "tree"):
                            err(
                                f"{item.meta_path}: pack.include_paths[{j}] not found as file/dir at {commit}: {p_norm}"
                                if obj_type is None
                                else f"{item.meta_path}: pack.include_paths[{j}] must be blob/tree at {commit}: {p_norm} (got {obj_type})"
                            )

    return errors


def check_stale(commit: str, items: List[MemoryItem]) -> Tuple[List[str], List[str]]:
    commit = _resolve_commit(commit)
    errors: List[str] = []
    warnings: List[str] = []

    for item in items:
        watch_paths = item.meta.get("watch_paths", [])
        if not isinstance(watch_paths, list) or len(watch_paths) == 0:
            continue

        verified = item.meta.get("verified_commit", None)
        if isinstance(verified, str) and verified.strip():
            try:
                verified_commit = _resolve_commit(verified.strip())
            except Exception as e:
                errors.append(f"{item.meta_path}: verified_commit invalid: {e}")
                continue
        else:
            last = _last_touch_commit(commit, item.meta_path)
            if not last:
                errors.append(f"{item.meta_path}: cannot determine last-touch commit for stale check")
                continue
            verified_commit = last

        ok, _ = _git_ok(["merge-base", "--is-ancestor", verified_commit, commit])
        if not ok:
            errors.append(f"{item.meta_path}: verified_commit {verified_commit} is not an ancestor of {commit}")
            continue

        norm_paths: List[str] = []
        try:
            for p in watch_paths:
                if isinstance(p, str) and p.strip():
                    norm_paths.append(_norm_rel_path(p))
        except Exception as e:
            errors.append(f"{item.meta_path}: invalid watch_paths: {e}")
            continue

        if not norm_paths:
            continue

        diff = _git_out(["diff", "--name-only", f"{verified_commit}..{commit}", "--", *norm_paths]).strip()
        if not diff:
            continue

        exemption = item.meta.get("stale_exemption", None)
        reason = exemption.get("reason", "") if isinstance(exemption, dict) else ""
        if isinstance(reason, str) and reason.strip():
            warnings.append(f"{item.meta_path}: STALE but exempted (reason={reason!r}). Changed:\n{diff}")
        else:
            errors.append(f"{item.meta_path}: STALE. Changed since {verified_commit}:\n{diff}")

    return errors, warnings


def _collect_task_pack_inputs(task: MemoryItem) -> Tuple[List[str], List[str]]:
    pack = task.meta.get("pack", {})
    include_memory_ids = pack.get("include_memory_ids", [])
    include_paths = pack.get("include_paths", [])
    include_memory_ids = [x for x in include_memory_ids if isinstance(x, str) and x.strip()]
    include_paths = [x for x in include_paths if isinstance(x, str) and x.strip()]
    return include_memory_ids, include_paths


def build_pack(commit: str, task_id: str, items: List[MemoryItem], by_id: Dict[str, MemoryItem]) -> Dict[str, Any]:
    commit = _resolve_commit(commit)
    task = by_id.get(task_id)
    if not task or task.type != "task":
        raise RuntimeError(f"task not found: {task_id}")

    include_memory_ids, include_paths = _collect_task_pack_inputs(task)

    active_constraints = sorted([i.id for i in items if i.type == "constraint" and _is_active(i) and i.id], key=str)
    memory_ids: List[str] = []
    for mid in [task_id, *active_constraints, *include_memory_ids]:
        if mid and mid not in memory_ids:
            memory_ids.append(mid)

    file_paths: List[Tuple[str, str]] = []

    def add_file(kind: str, path: str) -> None:
        path = _norm_rel_path(path)
        tup = (kind, path)
        if tup not in file_paths:
            file_paths.append(tup)

    for mid in memory_ids:
        mi = by_id.get(mid)
        if not mi:
            raise RuntimeError(f"pack includes missing memory id: {mid}")
        add_file("memory_meta", mi.meta_path)
        if mi.body_path:
            add_file("memory_body", mi.body_path)

        ev_list = mi.meta.get("evidence", [])
        if isinstance(ev_list, list):
            for ev in ev_list:
                if not isinstance(ev, dict):
                    continue
                if ev.get("kind") != "repo_path":
                    continue
                ref = ev.get("ref", "")
                if not (isinstance(ref, str) and ref.strip()):
                    continue
                ref_path = _norm_rel_path(ref)
                ref_type = _object_type(commit, ref_path)
                if ref_type == "blob":
                    add_file("evidence", ref_path)
                elif ref_type == "tree":
                    for fp in _ls_tree(commit, ref_path):
                        add_file("evidence", fp)

    for p in include_paths:
        p = _norm_rel_path(p)

        obj_type = _object_type(commit, p)
        if obj_type == "blob":
            add_file("repo_file", p)
            continue
        if obj_type == "tree":
            listed = _ls_tree(commit, p)
            if not listed:
                raise RuntimeError(f"include_paths entry not found as file/dir at {commit}: {p}")
            for fp in listed:
                add_file("repo_file", fp)
            continue
        if obj_type is None:
            raise RuntimeError(f"include_paths entry not found as file/dir at {commit}: {p}")
        raise RuntimeError(f"include_paths entry must be blob or tree at {commit}: {p} (got {obj_type})")

    pack_items: List[Dict[str, Any]] = []
    manifest_for_id: List[str] = []

    for kind, path in sorted(file_paths, key=lambda x: (x[0], x[1])):
        obj_type = _object_type(commit, path)
        if obj_type != "blob":
            raise RuntimeError(f"pack path is not a file/blob at {commit}: {path} (got {obj_type})")
        data = _read_path(commit, path)
        blob = _blob_sha(commit, path)
        sha = _sha256_hex(data)
        pack_items.append(
            {
                "kind": kind,
                "path": path,
                "git_blob": blob,
                "sha256": sha,
                "size": len(data),
                "content_b64": base64.b64encode(data).decode("ascii"),
            }
        )
        manifest_for_id.append(f"{path}\n{blob}\n")

    memory_tree = _tree_sha(commit, ".ai/memory")
    pack_id_src = (commit + "\n" + (memory_tree or "") + "\n" + "".join(manifest_for_id)).encode("utf-8")
    pack_id = _sha256_hex(pack_id_src)

    return {
        "pack_version": 1,
        "pack_id": pack_id,
        "task_id": task_id,
        "repo_commit": commit,
        "memory_tree": memory_tree,
        "inputs": {
            "include_memory_ids": include_memory_ids,
            "include_paths": include_paths,
            "auto_included_constraints": active_constraints,
        },
        "items": pack_items,
    }


def _write_json(obj: Dict[str, Any], out_path: str) -> None:
    data = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    if out_path == "-" or out_path.strip() == "":
        sys.stdout.buffer.write(data)
        return
    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(data)


def _is_hex(s: str, n: int) -> bool:
    return bool(re.fullmatch(rf"[0-9a-f]{{{n}}}", s or ""))


def _is_hex_range(s: str, min_n: int, max_n: int) -> bool:
    return bool(re.fullmatch(rf"[0-9a-f]{{{min_n},{max_n}}}", s or ""))


def validate_agent_report(data: Dict[str, Any], expect_task_id: Optional[str]) -> List[str]:
    errors: List[str] = []

    if not isinstance(data, dict):
        return ["report must be a JSON object"]

    if data.get("schema_version") != 1:
        errors.append("schema_version must be 1")

    for k in ("run_id", "agent_id", "task_id"):
        v = data.get(k, "")
        if not isinstance(v, str) or not v.strip():
            errors.append(f"{k} must be non-empty string")

    if expect_task_id and data.get("task_id") != expect_task_id:
        errors.append(f"task_id mismatch: expect {expect_task_id!r}, got {data.get('task_id')!r}")

    ctx = data.get("context")
    if not isinstance(ctx, dict):
        errors.append("context must be object")
        return errors

    pack_id = ctx.get("pack_id", "")
    repo_commit = ctx.get("repo_commit", "")
    memory_tree = ctx.get("memory_tree", None)

    if not isinstance(pack_id, str) or not _is_hex(pack_id, 64):
        errors.append("context.pack_id must be 64-hex sha256 string")
    if not isinstance(repo_commit, str) or not _is_hex_range(repo_commit, 7, 40):
        errors.append("context.repo_commit must be 7-40 hex git sha string")
    if memory_tree not in (None, "") and (not isinstance(memory_tree, str) or not _is_hex_range(memory_tree, 7, 40)):
        errors.append("context.memory_tree must be 7-40 hex git sha string, null, or empty string")

    changes = data.get("changes")
    if not isinstance(changes, list):
        errors.append("changes must be list")
    else:
        for i, ch in enumerate(changes):
            if not isinstance(ch, dict):
                errors.append(f"changes[{i}] must be object")
                continue
            path = ch.get("path", "")
            action = ch.get("action", "")
            if not isinstance(path, str) or not path.strip():
                errors.append(f"changes[{i}].path must be non-empty string")
            else:
                try:
                    _norm_rel_path(path)
                except Exception as e:
                    errors.append(f"changes[{i}].path invalid: {e}")
            if action not in ("add", "modify", "delete", "rename"):
                errors.append(f"changes[{i}].action must be one of add/modify/delete/rename")

    validation = data.get("validation")
    if not isinstance(validation, list):
        errors.append("validation must be list")
    else:
        for i, v in enumerate(validation):
            if not isinstance(v, dict):
                errors.append(f"validation[{i}] must be object")
                continue
            name = v.get("name", "")
            status = v.get("status", "")
            exit_code = v.get("exit_code", None)
            if not isinstance(name, str) or not name.strip():
                errors.append(f"validation[{i}].name must be non-empty string")
            if status not in ("pass", "fail", "skipped"):
                errors.append(f"validation[{i}].status must be one of pass/fail/skipped")
            if exit_code is not None and not isinstance(exit_code, int):
                errors.append(f"validation[{i}].exit_code must be integer when present")

    memory_updates = data.get("memory_updates", None)
    if memory_updates is not None:
        if not isinstance(memory_updates, list):
            errors.append("memory_updates must be list when present")
        else:
            for i, mu in enumerate(memory_updates):
                if not isinstance(mu, dict):
                    errors.append(f"memory_updates[{i}] must be object")
                    continue
                mid = mu.get("id", "")
                action = mu.get("action", "")
                if not isinstance(mid, str) or not mid.strip():
                    errors.append(f"memory_updates[{i}].id must be non-empty string")
                if action not in ("add", "modify", "none"):
                    errors.append(f"memory_updates[{i}].action must be one of add/modify/none")

    return errors


def validate_pack(data: Dict[str, Any], expect_task_id: Optional[str]) -> List[str]:
    errors: List[str] = []

    if not isinstance(data, dict):
        return ["pack must be a JSON object"]

    if data.get("pack_version") != 1:
        errors.append("pack_version must be 1")

    pack_id = data.get("pack_id", "")
    if not isinstance(pack_id, str) or not _is_hex(pack_id, 64):
        errors.append("pack_id must be 64-hex sha256 string")

    task_id = data.get("task_id", "")
    if not isinstance(task_id, str) or not task_id.strip():
        errors.append("task_id must be non-empty string")
    if expect_task_id and task_id != expect_task_id:
        errors.append(f"task_id mismatch: expect {expect_task_id!r}, got {task_id!r}")

    repo_commit_raw = data.get("repo_commit", "")
    if not isinstance(repo_commit_raw, str) or not repo_commit_raw.strip():
        errors.append("repo_commit must be non-empty string")
        repo_commit = None
    else:
        try:
            repo_commit = _resolve_commit(repo_commit_raw.strip())
        except Exception as e:
            errors.append(f"repo_commit invalid: {e}")
            repo_commit = None

    memory_tree_declared = data.get("memory_tree", None)
    if memory_tree_declared not in (None, "") and (
        not isinstance(memory_tree_declared, str) or not _is_hex_range(memory_tree_declared, 7, 40)
    ):
        errors.append("memory_tree must be 7-40 hex string, null, or empty string")
    memory_tree_declared_norm = memory_tree_declared if isinstance(memory_tree_declared, str) and memory_tree_declared.strip() else None

    memory_tree_actual: Optional[str] = None
    memory_tree_computed = False
    if repo_commit is not None:
        try:
            memory_tree_actual = _tree_sha(repo_commit, ".ai/memory")
            memory_tree_computed = True
        except Exception as e:
            errors.append(f"cannot compute memory_tree at {repo_commit}: {e}")
            memory_tree_actual = None
        if (memory_tree_actual or None) != (memory_tree_declared_norm or None):
            errors.append(f"memory_tree mismatch: expect {memory_tree_actual!r}, got {memory_tree_declared_norm!r}")

    items = data.get("items", None)
    if not isinstance(items, list):
        errors.append("items must be list")
        return errors

    seen: Set[Tuple[str, str]] = set()
    last_key: Optional[Tuple[str, str]] = None
    manifest: List[Tuple[str, str, str]] = []
    manifest_ok = True

    for idx, it in enumerate(items):
        if not isinstance(it, dict):
            errors.append(f"items[{idx}] must be object")
            continue

        kind = it.get("kind", "")
        path = it.get("path", "")
        blob = it.get("git_blob", "")
        sha = it.get("sha256", "")
        size = it.get("size", None)
        content_b64 = it.get("content_b64", "")

        if not isinstance(kind, str) or not kind.strip():
            errors.append(f"items[{idx}].kind must be non-empty string")
            manifest_ok = False
            continue
        if kind not in PACK_ITEM_KINDS:
            errors.append(f"items[{idx}].kind must be one of {sorted(PACK_ITEM_KINDS)}")
            manifest_ok = False
        if not isinstance(path, str) or not path.strip():
            errors.append(f"items[{idx}].path must be non-empty string")
            manifest_ok = False
            continue

        try:
            path_norm = _norm_rel_path(path)
        except Exception as e:
            errors.append(f"items[{idx}].path invalid: {e}")
            manifest_ok = False
            continue
        if path_norm != path:
            errors.append(f"items[{idx}].path must be canonical (got {path!r}, normalized {path_norm!r})")
            manifest_ok = False

        key = (kind, path_norm)
        if last_key is not None and key < last_key:
            errors.append("items must be sorted by (kind, path) for canonical pack output")
            last_key = key
        else:
            last_key = key

        if key in seen:
            errors.append(f"duplicate item (kind,path) at items[{idx}]: {key}")
        else:
            seen.add(key)

        if not isinstance(blob, str) or not _is_hex(blob, 40):
            errors.append(f"items[{idx}].git_blob must be 40-hex string")
            manifest_ok = False
        if not isinstance(sha, str) or not _is_hex(sha, 64):
            errors.append(f"items[{idx}].sha256 must be 64-hex string")
            manifest_ok = False
        if not isinstance(size, int) or size < 0:
            errors.append(f"items[{idx}].size must be non-negative integer")
            manifest_ok = False
        if not isinstance(content_b64, str) or not content_b64:
            errors.append(f"items[{idx}].content_b64 must be non-empty string")
            manifest_ok = False

        decoded: Optional[bytes] = None
        if isinstance(content_b64, str) and content_b64:
            try:
                decoded = base64.b64decode(content_b64.encode("ascii"), validate=True)
            except Exception as e:
                errors.append(f"items[{idx}].content_b64 invalid base64: {e}")
                decoded = None
                manifest_ok = False

        if decoded is not None:
            if isinstance(size, int) and size != len(decoded):
                errors.append(f"items[{idx}].size mismatch: expect {len(decoded)}, got {size}")
            if isinstance(sha, str) and _is_hex(sha, 64):
                sha_actual = _sha256_hex(decoded)
                if sha_actual != sha:
                    errors.append(f"items[{idx}].sha256 mismatch: expect {sha_actual}, got {sha}")

        if repo_commit is not None and isinstance(blob, str) and _is_hex(blob, 40):
            try:
                obj_type = _object_type(repo_commit, path_norm)
                if obj_type != "blob":
                    errors.append(f"items[{idx}].path is not a file/blob at {repo_commit}: {path_norm} (got {obj_type})")
                else:
                    blob_actual = _blob_sha(repo_commit, path_norm)
                    if blob_actual != blob:
                        errors.append(f"items[{idx}].git_blob mismatch: expect {blob_actual}, got {blob}")
                    if decoded is not None:
                        data_actual = _read_path(repo_commit, path_norm)
                        if data_actual != decoded:
                            errors.append(f"items[{idx}].content mismatch vs git at {repo_commit}: {path_norm}")
            except Exception as e:
                errors.append(f"items[{idx}] cannot verify against git: {e}")

        if isinstance(blob, str) and _is_hex(blob, 40):
            manifest.append((kind, path_norm, blob))

    if repo_commit is not None and memory_tree_computed and manifest and manifest_ok:
        try:
            manifest_sorted = sorted(manifest, key=lambda x: (x[0], x[1]))
            manifest_for_id = "".join([f"{p}\n{b}\n" for _k, p, b in manifest_sorted])
            pack_id_src = (repo_commit + "\n" + (memory_tree_actual or "") + "\n" + manifest_for_id).encode("utf-8")
            pack_id_actual = _sha256_hex(pack_id_src)
            if isinstance(pack_id, str) and _is_hex(pack_id, 64) and pack_id_actual != pack_id:
                errors.append(f"pack_id mismatch: expect {pack_id_actual}, got {pack_id}")
        except Exception as e:
            errors.append(f"cannot recompute pack_id: {e}")

    return errors


def cmd_validate(args: argparse.Namespace) -> int:
    commit = _resolve_commit(args.commit)
    items, by_id = load_memory(commit)
    errors = validate_memory(commit, items, by_id)
    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        return 1
    print(f"OK: validated {len(items)} memory items at {commit}")
    return 0


def cmd_check_stale(args: argparse.Namespace) -> int:
    commit = _resolve_commit(args.commit)
    items, _ = load_memory(commit)
    errors, warnings = check_stale(commit, items)
    for w in warnings:
        print(f"WARN: {w}", file=sys.stderr)
    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        return 1
    print(f"OK: stale check passed for {len(items)} memory items at {commit}")
    return 0


def cmd_build_pack(args: argparse.Namespace) -> int:
    commit = _resolve_commit(args.commit)
    items, by_id = load_memory(commit)
    pack = build_pack(commit, args.task_id, items, by_id)
    _write_json(pack, args.out)
    return 0


def cmd_validate_report(args: argparse.Namespace) -> int:
    with open(args.report, "r", encoding="utf-8") as f:
        data = json.load(f)

    errors = validate_agent_report(data=data, expect_task_id=args.task_id)
    if errors:
        for e in errors:
            print(f"ERROR: {args.report}: {e}", file=sys.stderr)
        return 1

    print(f"OK: agent report valid: {args.report}")
    return 0


def cmd_validate_pack(args: argparse.Namespace) -> int:
    with open(args.pack, "r", encoding="utf-8") as f:
        data = json.load(f)

    errors = validate_pack(data=data, expect_task_id=args.task_id)
    if errors:
        for e in errors:
            print(f"ERROR: {args.pack}: {e}", file=sys.stderr)
        return 1

    print(f"OK: context pack valid: {args.pack}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="memctl")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_val = sub.add_parser("validate", help="validate curated memory (meta.json)")
    p_val.add_argument("--commit", default="HEAD")
    p_val.set_defaults(func=cmd_validate)

    p_stale = sub.add_parser("check-stale", help="check stale memory items via watch_paths")
    p_stale.add_argument("--commit", default="HEAD")
    p_stale.set_defaults(func=cmd_check_stale)

    p_pack = sub.add_parser("build-pack", help="build deterministic context pack for a task")
    p_pack.add_argument("--commit", default="HEAD")
    p_pack.add_argument("--task-id", required=True)
    p_pack.add_argument("--out", default="-")
    p_pack.set_defaults(func=cmd_build_pack)

    p_rep = sub.add_parser("validate-report", help="validate agent_report.json basics")
    p_rep.add_argument("--report", required=True)
    p_rep.add_argument("--task-id")
    p_rep.set_defaults(func=cmd_validate_report)

    p_vpack = sub.add_parser("validate-pack", help="validate context pack integrity")
    p_vpack.add_argument("--pack", required=True)
    p_vpack.add_argument("--task-id")
    p_vpack.set_defaults(func=cmd_validate_pack)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
