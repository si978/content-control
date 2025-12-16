import base64
import importlib.util
import json
import os
import pathlib
import subprocess
import tempfile
import unittest
from contextlib import contextmanager


AI_DIR = pathlib.Path(__file__).resolve().parents[1]
MEMCTL_PATH = AI_DIR / "tools" / "memctl.py"

spec = importlib.util.spec_from_file_location("memctl", MEMCTL_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError(f"cannot import memctl from {MEMCTL_PATH}")
memctl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(memctl)


def _run(cmd: list[str], cwd: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _write_text(repo_dir: str, rel_path: str, content: str) -> None:
    path = pathlib.Path(repo_dir, rel_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def _write_json(repo_dir: str, rel_path: str, data: dict) -> None:
    _write_text(repo_dir, rel_path, json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2) + "\n")


def _commit_all(repo_dir: str, message: str) -> str:
    _run(["git", "add", "-A"], cwd=repo_dir)
    _run(["git", "commit", "--no-gpg-sign", "-m", message], cwd=repo_dir)
    return _run(["git", "rev-parse", "HEAD"], cwd=repo_dir).stdout.strip()


@contextmanager
def _chdir(path: str):
    old = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(old)


@contextmanager
def _temp_git_repo():
    with tempfile.TemporaryDirectory() as tmp:
        _run(["git", "init"], cwd=tmp)
        _run(["git", "config", "user.email", "test@example.com"], cwd=tmp)
        _run(["git", "config", "user.name", "Test"], cwd=tmp)
        yield tmp


def _basic_evidence(ref: str) -> list[dict]:
    return [{"kind": "repo_path", "ref": ref}]


def _task_meta(task_id: str, *, evidence_ref: str, pack: dict | None = None, **extra) -> dict:
    return {
        "schema_version": 1,
        "id": task_id,
        "type": "task",
        "status": "active",
        "title": "Test Task",
        "evidence": _basic_evidence(evidence_ref),
        "pack": pack or {"include_memory_ids": [], "include_paths": []},
        **extra,
    }


def _constraint_meta(constraint_id: str, *, key: str, evidence_ref: str, **extra) -> dict:
    return {
        "schema_version": 1,
        "id": constraint_id,
        "type": "constraint",
        "status": "active",
        "title": "Test Constraint",
        "key": key,
        "evidence": _basic_evidence(evidence_ref),
        **extra,
    }


class TestMemctlValidateMemory(unittest.TestCase):
    def test_validate_memory_ok_minimal(self) -> None:
        with _temp_git_repo() as repo, _chdir(repo):
            _write_text(repo, ".ai/evidence/conversations/test.md", "hi\n")
            _write_json(
                repo,
                ".ai/memory/constraints/CONSTRAINT-0001/meta.json",
                _constraint_meta("CONSTRAINT-0001", key="K1", evidence_ref=".ai/evidence/conversations/test.md"),
            )
            _write_text(repo, ".ai/memory/constraints/CONSTRAINT-0001/body.md", "constraint\n")
            _write_text(repo, "src/a.txt", "A\n")
            _write_json(
                repo,
                ".ai/memory/tasks/TASK-0001/meta.json",
                _task_meta("TASK-0001", evidence_ref=".ai/evidence/conversations/test.md", pack={"include_paths": ["src"], "include_memory_ids": []}),
            )
            _write_text(repo, ".ai/memory/tasks/TASK-0001/body.md", "task\n")
            head = _commit_all(repo, "baseline")

            items, by_id = memctl.load_memory(head)
            errors = memctl.validate_memory(head, items, by_id)
            self.assertEqual(errors, [])

    def test_validate_memory_duplicate_id_fails(self) -> None:
        with _temp_git_repo() as repo, _chdir(repo):
            _write_text(repo, ".ai/evidence/conversations/test.md", "hi\n")
            meta = _task_meta("TASK-0001", evidence_ref=".ai/evidence/conversations/test.md")
            _write_json(repo, ".ai/memory/tasks/TASK-0001/meta.json", meta)
            _write_json(repo, ".ai/memory/tasks/TASK-0001-copy/meta.json", meta)
            head = _commit_all(repo, "dup id")

            items, by_id = memctl.load_memory(head)
            errors = memctl.validate_memory(head, items, by_id)
            self.assertTrue(any("duplicate id" in e for e in errors), errors)

    def test_validate_memory_constraint_key_conflict_fails(self) -> None:
        with _temp_git_repo() as repo, _chdir(repo):
            _write_text(repo, ".ai/evidence/conversations/test.md", "hi\n")
            _write_json(
                repo,
                ".ai/memory/constraints/CONSTRAINT-0001/meta.json",
                _constraint_meta("CONSTRAINT-0001", key="K1", evidence_ref=".ai/evidence/conversations/test.md"),
            )
            _write_json(
                repo,
                ".ai/memory/constraints/CONSTRAINT-0002/meta.json",
                _constraint_meta("CONSTRAINT-0002", key="K1", evidence_ref=".ai/evidence/conversations/test.md"),
            )
            head = _commit_all(repo, "key conflict")

            items, by_id = memctl.load_memory(head)
            errors = memctl.validate_memory(head, items, by_id)
            self.assertTrue(any("constraint.key conflict" in e for e in errors), errors)

    def test_validate_memory_supersedes_missing_fails(self) -> None:
        with _temp_git_repo() as repo, _chdir(repo):
            _write_text(repo, ".ai/evidence/conversations/test.md", "hi\n")
            _write_json(
                repo,
                ".ai/memory/tasks/TASK-0001/meta.json",
                _task_meta("TASK-0001", evidence_ref=".ai/evidence/conversations/test.md", supersedes=["TASK-MISSING"]),
            )
            head = _commit_all(repo, "bad supersedes")

            items, by_id = memctl.load_memory(head)
            errors = memctl.validate_memory(head, items, by_id)
            self.assertTrue(any("supersedes references missing id" in e for e in errors), errors)


class TestMemctlCheckStale(unittest.TestCase):
    def test_check_stale_verified_commit_detects_change(self) -> None:
        with _temp_git_repo() as repo, _chdir(repo):
            _write_text(repo, "src/a.txt", "A1\n")
            base = _commit_all(repo, "base")

            _write_text(repo, ".ai/evidence/conversations/test.md", "hi\n")
            _write_json(
                repo,
                ".ai/memory/tasks/TASK-0001/meta.json",
                _task_meta(
                    "TASK-0001",
                    evidence_ref=".ai/evidence/conversations/test.md",
                    watch_paths=["src/a.txt"],
                    verified_commit=base,
                ),
            )
            _commit_all(repo, "add task")

            _write_text(repo, "src/a.txt", "A2\n")
            head = _commit_all(repo, "change watched file")

            items, _ = memctl.load_memory(head)
            errors, warnings = memctl.check_stale(head, items)
            self.assertEqual(warnings, [])
            self.assertTrue(any("STALE" in e for e in errors), errors)

    def test_check_stale_exemption_turns_error_into_warning(self) -> None:
        with _temp_git_repo() as repo, _chdir(repo):
            _write_text(repo, "src/a.txt", "A1\n")
            base = _commit_all(repo, "base")

            _write_text(repo, ".ai/evidence/conversations/test.md", "hi\n")
            _write_json(
                repo,
                ".ai/memory/tasks/TASK-0001/meta.json",
                _task_meta(
                    "TASK-0001",
                    evidence_ref=".ai/evidence/conversations/test.md",
                    watch_paths=["src/a.txt"],
                    verified_commit=base,
                    stale_exemption={"reason": "deliberate"},
                ),
            )
            _commit_all(repo, "add task")

            _write_text(repo, "src/a.txt", "A2\n")
            head = _commit_all(repo, "change watched file")

            items, _ = memctl.load_memory(head)
            errors, warnings = memctl.check_stale(head, items)
            self.assertEqual(errors, [])
            self.assertTrue(any("STALE but exempted" in w for w in warnings), warnings)

    def test_check_stale_invalid_watch_paths_reports_error(self) -> None:
        with _temp_git_repo() as repo, _chdir(repo):
            _write_text(repo, ".ai/evidence/conversations/test.md", "hi\n")
            _write_json(
                repo,
                ".ai/memory/tasks/TASK-0001/meta.json",
                _task_meta("TASK-0001", evidence_ref=".ai/evidence/conversations/test.md", watch_paths=["../oops"]),
            )
            head = _commit_all(repo, "bad watch_paths")

            items, _ = memctl.load_memory(head)
            errors, _warnings = memctl.check_stale(head, items)
            self.assertTrue(any("invalid watch_paths" in e for e in errors), errors)


class TestMemctlBuildPack(unittest.TestCase):
    def test_build_pack_includes_expected_kinds(self) -> None:
        with _temp_git_repo() as repo, _chdir(repo):
            _write_text(repo, ".ai/evidence/conversations/test.md", "hi\n")
            _write_json(
                repo,
                ".ai/memory/constraints/CONSTRAINT-0001/meta.json",
                _constraint_meta("CONSTRAINT-0001", key="K1", evidence_ref=".ai/evidence/conversations/test.md"),
            )
            _write_text(repo, ".ai/memory/constraints/CONSTRAINT-0001/body.md", "constraint\n")
            _write_text(repo, "src/a.txt", "A\n")
            _write_json(
                repo,
                ".ai/memory/tasks/TASK-0001/meta.json",
                _task_meta("TASK-0001", evidence_ref=".ai/evidence/conversations/test.md", pack={"include_paths": ["src"], "include_memory_ids": []}),
            )
            _write_text(repo, ".ai/memory/tasks/TASK-0001/body.md", "task\n")
            head = _commit_all(repo, "baseline")

            items, by_id = memctl.load_memory(head)
            pack = memctl.build_pack(head, "TASK-0001", items, by_id)

            self.assertEqual(pack["task_id"], "TASK-0001")
            self.assertEqual(pack["repo_commit"], memctl._resolve_commit(head))
            self.assertTrue(memctl._is_hex(pack["pack_id"], 64), pack["pack_id"])
            self.assertTrue(pack["memory_tree"] is None or memctl._is_hex(pack["memory_tree"], 40), pack["memory_tree"])

            kinds = {(i["kind"], i["path"]) for i in pack["items"]}
            self.assertIn(("memory_meta", ".ai/memory/tasks/TASK-0001/meta.json"), kinds)
            self.assertIn(("memory_body", ".ai/memory/tasks/TASK-0001/body.md"), kinds)
            self.assertIn(("memory_meta", ".ai/memory/constraints/CONSTRAINT-0001/meta.json"), kinds)
            self.assertIn(("memory_body", ".ai/memory/constraints/CONSTRAINT-0001/body.md"), kinds)
            self.assertIn(("evidence", ".ai/evidence/conversations/test.md"), kinds)
            self.assertIn(("repo_file", "src/a.txt"), kinds)

            sample = next(i for i in pack["items"] if i["kind"] == "repo_file" and i["path"] == "src/a.txt")
            decoded = base64.b64decode(sample["content_b64"])
            self.assertEqual(decoded, b"A\n")

    def test_build_pack_include_paths_directory_expansion(self) -> None:
        with _temp_git_repo() as repo, _chdir(repo):
            _write_text(repo, ".ai/evidence/conversations/test.md", "hi\n")
            _write_text(repo, "src/a.txt", "A\n")
            _write_text(repo, "src/b.txt", "B\n")
            _write_json(
                repo,
                ".ai/memory/tasks/TASK-0001/meta.json",
                _task_meta("TASK-0001", evidence_ref=".ai/evidence/conversations/test.md", pack={"include_paths": ["src"], "include_memory_ids": []}),
            )
            head = _commit_all(repo, "baseline")

            items, by_id = memctl.load_memory(head)
            pack = memctl.build_pack(head, "TASK-0001", items, by_id)
            paths = {i["path"] for i in pack["items"] if i["kind"] == "repo_file"}
            self.assertIn("src/a.txt", paths)
            self.assertIn("src/b.txt", paths)

    def test_build_pack_include_paths_missing_raises(self) -> None:
        with _temp_git_repo() as repo, _chdir(repo):
            _write_text(repo, ".ai/evidence/conversations/test.md", "hi\n")
            _write_json(
                repo,
                ".ai/memory/tasks/TASK-0001/meta.json",
                _task_meta("TASK-0001", evidence_ref=".ai/evidence/conversations/test.md", pack={"include_paths": ["missing"], "include_memory_ids": []}),
            )
            head = _commit_all(repo, "baseline")

            items, by_id = memctl.load_memory(head)
            with self.assertRaises(RuntimeError):
                memctl.build_pack(head, "TASK-0001", items, by_id)

    def test_build_pack_is_byte_deterministic(self) -> None:
        with _temp_git_repo() as repo, _chdir(repo):
            _write_text(repo, ".ai/evidence/conversations/test.md", "hi\n")
            _write_text(repo, "src/a.txt", "A\n")
            _write_json(
                repo,
                ".ai/memory/tasks/TASK-0001/meta.json",
                _task_meta("TASK-0001", evidence_ref=".ai/evidence/conversations/test.md", pack={"include_paths": ["src/a.txt"], "include_memory_ids": []}),
            )
            head = _commit_all(repo, "baseline")

            items, by_id = memctl.load_memory(head)
            pack1 = memctl.build_pack(head, "TASK-0001", items, by_id)
            pack2 = memctl.build_pack(head, "TASK-0001", items, by_id)

            with tempfile.TemporaryDirectory() as out:
                p1 = os.path.join(out, "p1.json")
                p2 = os.path.join(out, "p2.json")
                memctl._write_json(pack1, p1)
                memctl._write_json(pack2, p2)
                b1 = pathlib.Path(p1).read_bytes()
                b2 = pathlib.Path(p2).read_bytes()
            self.assertEqual(b1, b2)


class TestMemctlValidateAgentReport(unittest.TestCase):
    def test_validate_agent_report_rejects_missing_fields(self) -> None:
        errors = memctl.validate_agent_report(data={}, expect_task_id=None)
        self.assertTrue(errors)

    def test_validate_agent_report_accepts_valid(self) -> None:
        report = {
            "schema_version": 1,
            "run_id": "R1",
            "agent_id": "A1",
            "task_id": "TASK-0001",
            "context": {"pack_id": "a" * 64, "repo_commit": "b" * 40, "memory_tree": None},
            "changes": [],
            "validation": [],
        }
        errors = memctl.validate_agent_report(data=report, expect_task_id="TASK-0001")
        self.assertEqual(errors, [])

    def test_validate_agent_report_task_id_mismatch(self) -> None:
        report = {
            "schema_version": 1,
            "run_id": "R1",
            "agent_id": "A1",
            "task_id": "TASK-0002",
            "context": {"pack_id": "a" * 64, "repo_commit": "b" * 40, "memory_tree": None},
            "changes": [],
            "validation": [],
        }
        errors = memctl.validate_agent_report(data=report, expect_task_id="TASK-0001")
        self.assertTrue(any("task_id mismatch" in e for e in errors), errors)


class TestMemctlNormRelPath(unittest.TestCase):
    def test_norm_rel_path_rejects_traversal(self) -> None:
        with self.assertRaises(ValueError):
            memctl._norm_rel_path("../x")

    def test_norm_rel_path_strips_leading_slashes(self) -> None:
        self.assertEqual(memctl._norm_rel_path("/x"), "x")

    def test_norm_rel_path_normalizes_backslashes(self) -> None:
        self.assertEqual(memctl._norm_rel_path(r".ai\memory\x"), ".ai/memory/x")

    def test_norm_rel_path_rejects_parent_segment_even_at_end(self) -> None:
        with self.assertRaises(ValueError):
            memctl._norm_rel_path("src/..")

    def test_norm_rel_path_rejects_windows_drive(self) -> None:
        with self.assertRaises(ValueError):
            memctl._norm_rel_path(r"C:\x")


class TestMemctlValidatePack(unittest.TestCase):
    def test_validate_pack_accepts_generated_pack(self) -> None:
        with _temp_git_repo() as repo, _chdir(repo):
            _write_text(repo, ".ai/evidence/conversations/test.md", "hi\n")
            _write_json(
                repo,
                ".ai/memory/constraints/CONSTRAINT-0001/meta.json",
                _constraint_meta("CONSTRAINT-0001", key="K1", evidence_ref=".ai/evidence/conversations/test.md"),
            )
            _write_text(repo, ".ai/memory/constraints/CONSTRAINT-0001/body.md", "constraint\n")
            _write_text(repo, "src/a.txt", "A\n")
            _write_json(
                repo,
                ".ai/memory/tasks/TASK-0001/meta.json",
                _task_meta("TASK-0001", evidence_ref=".ai/evidence/conversations/test.md", pack={"include_paths": ["src"], "include_memory_ids": []}),
            )
            _write_text(repo, ".ai/memory/tasks/TASK-0001/body.md", "task\n")
            head = _commit_all(repo, "baseline")

            items, by_id = memctl.load_memory(head)
            pack = memctl.build_pack(head, "TASK-0001", items, by_id)

            with tempfile.TemporaryDirectory() as out:
                pack_path = os.path.join(out, "pack.json")
                memctl._write_json(pack, pack_path)
                loaded = json.loads(pathlib.Path(pack_path).read_text(encoding="utf-8"))

            errors = memctl.validate_pack(data=loaded, expect_task_id="TASK-0001")
            self.assertEqual(errors, [])

    def test_validate_pack_detects_tampered_content(self) -> None:
        with _temp_git_repo() as repo, _chdir(repo):
            _write_text(repo, ".ai/evidence/conversations/test.md", "hi\n")
            _write_json(
                repo,
                ".ai/memory/tasks/TASK-0001/meta.json",
                _task_meta("TASK-0001", evidence_ref=".ai/evidence/conversations/test.md", pack={"include_paths": [".ai/evidence/conversations/test.md"], "include_memory_ids": []}),
            )
            head = _commit_all(repo, "baseline")

            items, by_id = memctl.load_memory(head)
            pack = memctl.build_pack(head, "TASK-0001", items, by_id)

            tampered = json.loads(json.dumps(pack))
            tampered["items"][0]["content_b64"] = base64.b64encode(b"tampered\n").decode("ascii")

            errors = memctl.validate_pack(data=tampered, expect_task_id="TASK-0001")
            self.assertTrue(any("content mismatch" in e or "sha256 mismatch" in e for e in errors), errors)

    def test_validate_pack_rejects_unsorted_items(self) -> None:
        with _temp_git_repo() as repo, _chdir(repo):
            _write_text(repo, ".ai/evidence/conversations/test.md", "hi\n")
            _write_text(repo, "src/a.txt", "A\n")
            _write_text(repo, "src/b.txt", "B\n")
            _write_json(
                repo,
                ".ai/memory/tasks/TASK-0001/meta.json",
                _task_meta("TASK-0001", evidence_ref=".ai/evidence/conversations/test.md", pack={"include_paths": ["src"], "include_memory_ids": []}),
            )
            head = _commit_all(repo, "baseline")

            items, by_id = memctl.load_memory(head)
            pack = memctl.build_pack(head, "TASK-0001", items, by_id)

            if len(pack["items"]) < 2:
                self.skipTest("pack too small to reorder")
            reordered = json.loads(json.dumps(pack))
            reordered["items"] = list(reversed(reordered["items"]))

            errors = memctl.validate_pack(data=reordered, expect_task_id="TASK-0001")
            self.assertTrue(any("items must be sorted" in e for e in errors), errors)


class TestMemctlRobustnessEdges(unittest.TestCase):
    def test_validate_memory_invalid_evidence_path_reports_error(self) -> None:
        with _temp_git_repo() as repo, _chdir(repo):
            _write_json(
                repo,
                ".ai/memory/constraints/CONSTRAINT-0001/meta.json",
                _constraint_meta("CONSTRAINT-0001", key="K1", evidence_ref="../oops"),
            )
            head = _commit_all(repo, "bad evidence")

            items, by_id = memctl.load_memory(head)
            errors = memctl.validate_memory(head, items, by_id)
            self.assertTrue(any("invalid repo_path" in e for e in errors), errors)

    def test_build_pack_expands_evidence_directory(self) -> None:
        with _temp_git_repo() as repo, _chdir(repo):
            _write_text(repo, ".ai/evidence/d/a.txt", "A\n")
            _write_text(repo, ".ai/evidence/d/b.txt", "B\n")
            _write_json(
                repo,
                ".ai/memory/constraints/CONSTRAINT-0001/meta.json",
                _constraint_meta("CONSTRAINT-0001", key="K1", evidence_ref=".ai/evidence/d"),
            )
            _write_json(
                repo,
                ".ai/memory/tasks/TASK-0001/meta.json",
                _task_meta("TASK-0001", evidence_ref=".ai/evidence/d/a.txt", pack={"include_paths": [], "include_memory_ids": []}),
            )
            head = _commit_all(repo, "baseline")

            items, by_id = memctl.load_memory(head)
            pack = memctl.build_pack(head, "TASK-0001", items, by_id)
            evidence_paths = {i["path"] for i in pack["items"] if i["kind"] == "evidence"}
            self.assertIn(".ai/evidence/d/a.txt", evidence_paths)
            self.assertIn(".ai/evidence/d/b.txt", evidence_paths)


if __name__ == "__main__":
    unittest.main()
