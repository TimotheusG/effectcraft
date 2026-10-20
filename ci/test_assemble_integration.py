"""Exercise real Git merges and failure boundaries using a tiny disposable repository."""

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from assemble_integration import AssemblyError, assemble, git, resolve_conflicts
from verify_integration import verify


class AssemblyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="effectcraft-assembly-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        git(self.source, "init", "-b", "main")
        git(self.source, "config", "core.autocrlf", "false")
        base = b"fn base() {\n}\n"
        first = b"\nfn first_test() {\n    assert!(true);\n}\n"
        second = b"\nfn second_test() {\n    assert!(true);\n}\n"
        ours, theirs = base + first, base + second
        combined = theirs + first
        self.expected = combined
        blobs = [git(self.source, "hash-object", "-w", "--stdin", data=data).stdout.decode().strip()
                 for data in (base, ours, theirs, combined)]
        trees = [git(self.source, "mktree", data=f"100644 blob {blob}\ttests.rs\n".encode()).stdout.decode().strip() for blob in blobs]
        env = {**os.environ, "GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
               "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}
        # Commit objects only in this test's disposable repo; no project commit is made.
        commits = [git(self.source, "commit-tree", tree, "-m", "fixture", env=env).stdout.decode().strip() for tree in trees[:3]]
        git(self.source, "update-ref", "refs/heads/main", commits[0])
        git(self.source, "read-tree", "--reset", "-u", commits[0])
        self.manifest = {"repository": "https://github.com/storytold/effectcraft.git", "base": commits[0],
                         "pull_requests": [{"number": i, "base": commits[0], "head": head} for i, head in enumerate(commits[1:], 1)],
                         "resolutions": [{"path": "tests.rs", "strategy": "append-ours-to-theirs",
                                          "stages": {"1": blobs[0], "2": blobs[1], "3": blobs[2]}, "result": blobs[3]}],
                         "expected_tree": trees[3]}

    def run_cli(self, destination):
        manifest = self.root / "manifest.json"
        manifest.write_text(json.dumps(self.manifest), encoding="utf-8")
        return subprocess.run([os.sys.executable, str(Path(__file__).with_name("assemble_integration.py")),
                               "--source", str(self.source), "--manifest", str(manifest),
                               "--destination", str(destination), "--receipt", str(self.root / "receipt.json")],
                              capture_output=True, text=True)

    def test_real_conflict_preserves_both_test_groups_and_source(self):
        before = git(self.source, "write-tree").stdout
        destination = self.root / "assembled"
        result = self.run_cli(destination)
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads((self.root / "receipt.json").read_text())
        self.assertEqual(destination.joinpath("tests.rs").read_bytes(), self.expected)
        verify(receipt)
        self.assertEqual(git(self.source, "write-tree").stdout, before)
        self.assertEqual(git(self.source, "status", "--porcelain").stdout, b"")
        destination.joinpath("tests.rs").write_text("changed during gate\n")
        with self.assertRaises(AssemblyError):
            verify(receipt)

    def test_existing_destination_survives_refusal(self):
        destination = self.root / "existing"
        destination.mkdir()
        marker = destination / "keep.txt"
        marker.write_text("preserve")
        self.assertNotEqual(self.run_cli(destination).returncode, 0)
        self.assertEqual(marker.read_text(), "preserve")
        self.assertFalse((self.root / "receipt.json").exists())

    def test_nested_destination_refused(self):
        destination = self.source / "nested"
        self.assertNotEqual(self.run_cli(destination).returncode, 0)
        self.assertFalse(destination.exists())

    def test_undeclared_conflict_refused(self):
        self.manifest["resolutions"] = []
        with self.assertRaisesRegex(AssemblyError, "Unapproved merge conflict"):
            assemble(self.source, self.manifest)

    def test_wrong_conflict_inputs_refused(self):
        self.manifest["resolutions"][0]["stages"]["3"] = "0" * 40
        with self.assertRaisesRegex(AssemblyError, "Unapproved merge conflict"):
            assemble(self.source, self.manifest)

    def test_resolution_output_drift_refused(self):
        self.manifest["resolutions"][0]["result"] = "0" * 40
        with self.assertRaisesRegex(AssemblyError, "Resolution content drift"):
            assemble(self.source, self.manifest)

    def test_matching_hashes_do_not_allow_nonappend_side(self):
        rule = self.manifest["resolutions"][0]
        rule["stages"]["2"] = git(self.source, "hash-object", "-w", "--stdin", data=b"fn changed_base() {}\n").stdout.decode().strip()
        output = self.manifest["expected_tree"] + "\n" + "\n".join(
            f"100644 {blob} {stage}\ttests.rs" for stage, blob in rule["stages"].items())
        with self.assertRaisesRegex(AssemblyError, "pure append"):
            resolve_conflicts(self.source, self.manifest["expected_tree"], output, [rule])

    def test_final_tree_drift_refused_before_checkout(self):
        self.manifest["expected_tree"] = "0" * 40
        destination = self.root / "assembled"
        self.assertNotEqual(self.run_cli(destination).returncode, 0)
        self.assertFalse(destination.exists())

    def test_mutable_revision_refused(self):
        self.manifest["pull_requests"][0]["head"] = "main"
        with self.assertRaisesRegex(AssemblyError, "immutable SHA"):
            assemble(self.source, self.manifest)

    def test_duplicate_pr_refused(self):
        self.manifest["pull_requests"].append(copy.deepcopy(self.manifest["pull_requests"][0]))
        with self.assertRaisesRegex(AssemblyError, "Duplicate PR"):
            assemble(self.source, self.manifest)

    def declare_patch(self):
        original_tree = self.manifest["expected_tree"]
        blob = git(self.source, "hash-object", "-w", "--stdin", data=self.expected + b"\nfn worker_change() {}\n").stdout.decode().strip()
        changed_tree = git(self.source, "mktree", data=f"100644 blob {blob}\ttests.rs\n".encode()).stdout.decode().strip()
        data = git(self.source, "diff", "--binary", original_tree, changed_tree).stdout
        path = self.root / "worker.patch"
        path.write_bytes(data)
        self.manifest["patches"] = [{"path": path.name, "sha256": hashlib.sha256(data).hexdigest()}]
        self.manifest["expected_tree"] = changed_tree
        return path

    def test_uncommitted_worker_patch_is_declared_hashed_and_recorded(self):
        self.declare_patch()
        before = git(self.source, "write-tree").stdout
        receipt = assemble(self.source, self.manifest, patch_root=self.root)
        self.assertEqual(receipt["tree"], self.manifest["expected_tree"])
        self.assertEqual(receipt["patches"][0]["sha256"], self.manifest["patches"][0]["sha256"])
        self.assertEqual(git(self.source, "write-tree").stdout, before)

    def test_changed_worker_patch_is_refused(self):
        self.declare_patch().write_bytes(b"different patch bytes")
        with self.assertRaisesRegex(AssemblyError, "patch digest mismatch"):
            assemble(self.source, self.manifest, patch_root=self.root)

    def test_patch_outside_manifest_directory_is_refused(self):
        self.declare_patch()
        self.manifest["patches"][0]["path"] = "../elsewhere.patch"
        with self.assertRaisesRegex(AssemblyError, "within the manifest directory"):
            assemble(self.source, self.manifest, patch_root=self.root)


if __name__ == "__main__":
    unittest.main()
