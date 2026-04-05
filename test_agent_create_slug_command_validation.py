import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

sys.modules.setdefault("pwd", types.SimpleNamespace(getpwnam=lambda _: None, getpwuid=lambda _: None))
sys.modules.setdefault("grp", types.SimpleNamespace(getgrnam=lambda _: None, getgrgid=lambda _: None))

import agent_main


class CreateSlugCommandValidationTest(unittest.TestCase):
    def test_create_slug_command_requires_real_watchdog_result(self):
        tracked_env = {
            "AGENT_ID_FILE": os.environ.get("AGENT_ID_FILE"),
            "AGENT_TOKEN_FILE": os.environ.get("AGENT_TOKEN_FILE"),
        }
        try:
            with tempfile.TemporaryDirectory() as td:
                os.environ["AGENT_ID_FILE"] = str(Path(td) / "agent.id")
                os.environ["AGENT_TOKEN_FILE"] = str(Path(td) / "agent.token")
                runtime = agent_main.AgentRuntime()

                class Proc:
                    returncode = 0
                    stdout = "ok"
                    stderr = ""

                with mock.patch.object(agent_main.subprocess, "run", return_value=Proc()):
                    ok, result, error = runtime._execute_instruction(
                        {
                            "id": "ins-1",
                            "kind": "create-slug",
                            "payload": {
                                "command": "echo ok",
                                "timeout_seconds": 60,
                                "body": {
                                    "slug": "srv-new",
                                    "repo": "https://github.com/org/repo",
                                    "branch": "master",
                                    "port": 1213,
                                    "watchdog_port": 8013,
                                    "public_host": "88.99.104.199",
                                    "host_user": "root",
                                },
                            },
                        }
                    )
        finally:
            for key, value in tracked_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

        self.assertFalse(ok)
        self.assertIn("config.toml", str(error or ""))
        self.assertEqual(result.get("returncode"), 0)


if __name__ == "__main__":
    unittest.main()
