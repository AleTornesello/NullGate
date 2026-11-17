"""CI must reject cargo's successful zero-test stub output."""
import unittest
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
from verify_test_run import summarize

class BehavioralGuardTests(unittest.TestCase):
    def run_output(self, passed, failed=0, ignored=0):
        result = "FAILED" if failed else "ok"
        return ("Running tests/end_to_end.rs (target/debug/deps/end_to_end-hash)\n"
                f"test result: {result}. {passed} passed; {failed} failed; {ignored} ignored; 0 filtered out; finished in 1s\n")
    def test_real_nonzero_executable_tests_are_required(self):
        self.assertTrue(summarize(self.run_output(3))["guard_ok"])
        for output in ["", "test result: ok. 999 passed; 0 failed; 0 ignored;\n", self.run_output(0), self.run_output(1), self.run_output(3,1), self.run_output(3,0,1)]:
            self.assertFalse(summarize(output)["guard_ok"])
    def test_partial_output_after_aborted_cargo_run_is_rejected(self):
        self.assertFalse(summarize(self.run_output(3), completed=False)["guard_ok"])

    def test_workflow_does_not_mask_cargo_abort_after_passing_e2e(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml").read_text()
        start = workflow.index("      - name: Run all behavioral tests")
        end = workflow.index("\n      - name:", start + 1)
        step = workflow[start:end]
        command = textwrap.dedent(step.split("        run: |\n", 1)[1])
        # GitHub's implicit bash has -e; explicitly selecting bash adds -o pipefail.
        shell = ["bash", "--noprofile", "--norc", "-e"]
        if "        shell: bash" in step:
            shell += ["-o", "pipefail"]
        with tempfile.TemporaryDirectory() as temp:
            stub = Path(temp) / "cargo"
            stub.write_text("#!/bin/sh\nprintf 'Running tests/end_to_end.rs (target/example)\\ntest result: ok. 3 passed; 0 failed; 0 ignored; 0 filtered out;\\n'\nexit 17\n")
            stub.chmod(0o700)
            env = {**os.environ, "PATH": temp + os.pathsep + os.environ["PATH"]}
            env.pop("BASH_ENV", None)
            result = subprocess.run(shell + ["-c", command], cwd=temp, env=env,
                                    capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((Path(temp) / "target/test-exit-code").exists())

    def test_unknown_output_and_credentials_are_never_retained(self):
        secret = "private-key-cookie-password-query-token"
        result = summarize(secret + "\n" + self.run_output(3))
        self.assertNotIn(secret, str(result))
        self.assertEqual(result["workspace"]["passed"], 3)

if __name__ == "__main__":
    unittest.main()
