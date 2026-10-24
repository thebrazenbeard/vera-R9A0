"""Reject concealed editor-startup execution from R9A0 source checkouts."""

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class R9A0EditorSecurityTests(unittest.TestCase):
    def test_disguised_node_loader_is_absent(self):
        self.assertFalse((ROOT / "public" / "fonts" / "fa-solid.lkf").exists())

    def test_editor_has_no_automatic_startup_task(self):
        tasks = json.loads((ROOT / ".vscode" / "tasks.json").read_text(encoding="utf-8"))
        self.assertIsInstance(tasks.get("tasks"), list)
        for task in tasks["tasks"]:
            with self.subTest(label=task.get("label")):
                self.assertNotEqual(task.get("runOptions", {}).get("runOn"), "folderOpen")
                self.assertNotIn("fa-solid.lkf", task.get("command", ""))

    def test_workspace_cannot_claim_user_automatic_task_consent(self):
        settings = json.loads((ROOT / ".vscode" / "settings.json").read_text(encoding="utf-8"))
        self.assertNotIn("task.allowAutomaticTasks", settings)
        self.assertNotIn("tasks", settings)


if __name__ == "__main__":
    unittest.main()
