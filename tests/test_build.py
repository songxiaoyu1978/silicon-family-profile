"""验证公开构建的内容一致性、动态偏好和安全转义。"""

from __future__ import annotations

import base64
import hashlib
import importlib
import json
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class BuildTests(unittest.TestCase):
    def setUp(self):
        module_path = Path(__file__).resolve().parents[1] / "scripts" / "build.py"
        self.assertTrue(module_path.is_file(), "公开静态构建尚未实现")
        self.build = importlib.import_module("scripts.build").build
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "data").mkdir()
        (self.root / "config").mkdir()
        (self.root / "updates").mkdir()
        (self.root / "config" / "agents.json").write_text(
            '{"schema_version":1,"agents":[]}', encoding="utf-8"
        )
        (self.root / "PROFILE.md").write_text(
            "# 共同档案\n\n更新时间：2026-10-30T00:00:00+08:00\n"
            "核验短码：abc12345def67890\n\n## 角色\n\n一刻负责内容统筹。\n",
            encoding="utf-8",
        )
        (self.root / "PROJECTS.md").write_text(
            "# 项目方向\n\n更新时间：2026-10-30T00:00:00+08:00\n\n研究空间智能。\n",
            encoding="utf-8",
        )
        self.preferences = [{
            "id": "communication-language", "category": "communication",
            "scope": "global", "value": "请使用简体中文。", "revision": 1,
            "confirmed_at": "2026-10-30T09:00:00+08:00", "source_agent": "yingzi",
        }]
        self.write_preferences()
        self.commit = "1234567890abcdef1234567890abcdef12345678"

    def write_preferences(self):
        (self.root / "data" / "preferences.json").write_text(
            json.dumps({"schema_version": 1, "preferences": self.preferences}, ensure_ascii=False),
            encoding="utf-8",
        )

    def render(self, destination="dist"):
        output = self.root / destination
        result = self.build(self.root, output, self.commit)
        return output, result

    def test_all_outputs_share_current_version_and_content_digest(self):
        output, result = self.render()
        plain = (output / "full.txt").read_bytes()
        page = (output / "index.html").read_text(encoding="utf-8")
        metadata = json.loads((output / "version.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata, result)
        self.assertEqual(metadata["version"], "2026.10.30-1234567890ab")
        self.assertEqual(metadata["content_sha256"], hashlib.sha256(plain).hexdigest())
        self.assertEqual(metadata["commit"], self.commit)
        self.assertEqual(metadata["verification_code"], "abc12345def67890")
        self.assertIn(metadata["version"], plain.decode("utf-8"))
        self.assertIn(metadata["version"], page)
        self.assertIn(metadata["content_sha256"], page)
        for content in ("一刻负责内容统筹。", "研究空间智能。", "请使用简体中文。"):
            self.assertIn(content, plain.decode("utf-8"))
            self.assertIn(content, page)

    def test_markdown_cannot_inject_active_html(self):
        with (self.root / "PROFILE.md").open("a", encoding="utf-8") as file:
            file.write('\n<script>alert("x")</script>\n'
                       '[点我](javascript:alert(1))\n<img src=x onerror=alert(1)>\n')
        output, _ = self.render()
        page = (output / "index.html").read_text(encoding="utf-8")
        self.assertNotIn("<script", page.lower())
        self.assertNotIn("<img", page.lower())
        self.assertNotIn('href="javascript:', page.lower())
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("&lt;img", page)

    def test_signed_event_updates_and_retraction_reach_public_outputs(self):
        key = Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        (self.root / "config" / "agents.json").write_text(json.dumps({
            "schema_version": 1, "agents": [{"id": "yingzi", "key_id": "test-key",
            "public_key": base64.b64encode(public).decode(), "github_user_id": 123,
            "enabled": True}]}), encoding="utf-8")
        payload = {
            "protocol_version": 1, "repository": "songxiaoyu1978/silicon-family-profile",
            "agent_id": "yingzi", "key_id": "test-key", "event_id": str(uuid4()),
            "base_commit": self.commit, "confirmed_at": "2026-10-31T11:00:00+08:00",
            "category": "communication", "preference_id": "communication-language",
            "scope": "global", "expected_revision": 1, "old_value": "请使用简体中文。",
            "new_value": "默认中文，并解释必要术语。", "confirmation": "user_explicit",
            "public_safe": True,
        }

        def write_event(event):
            encoded = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
            envelope = {"payload": event, "signature": base64.b64encode(key.sign(encoded)).decode()}
            (self.root / "updates" / (event["event_id"] + ".json")).write_text(
                json.dumps(envelope, ensure_ascii=False), encoding="utf-8")

        write_event(payload)
        output, metadata = self.render("signed")
        for name in ("index.html", "full.txt"):
            actual = (output / name).read_text(encoding="utf-8")
            self.assertIn("默认中文，并解释必要术语。", actual)
            self.assertNotIn("请使用简体中文。", actual)
            self.assertNotIn("_applied_events", actual)
        self.assertEqual(metadata["updated_at"], "2026-10-31T11:00:00+08:00")
        write_event({**payload, "event_id": str(uuid4()),
                     "expected_revision": payload["event_id"], "old_value": payload["new_value"],
                     "new_value": None, "confirmed_at": "2026-10-31T12:00:00+08:00"})
        output, metadata = self.render("retracted")
        self.assertNotIn("默认中文，并解释必要术语。", (output / "full.txt").read_text(encoding="utf-8"))
        self.assertEqual(metadata["updated_at"], "2026-10-31T12:00:00+08:00")

    def test_unsafe_preference_fails_without_publishing_partial_outputs(self):
        self.preferences[0]["value"] = "<img src=x onerror=alert(1)>"
        self.write_preferences()
        with self.assertRaises(ValueError):
            self.render("unsafe")
        self.assertFalse((self.root / "unsafe").exists())

    def test_current_preferences_change_generated_content_and_timestamp(self):
        output, previous = self.render("before")
        self.preferences[0].update(value="操作说明使用中文，一次讲一个步骤。", revision=2,
                                   confirmed_at="2026-10-31T10:30:00+08:00")
        self.write_preferences()
        output, current = self.render("after")
        plain = (output / "full.txt").read_text(encoding="utf-8")
        self.assertIn("操作说明使用中文，一次讲一个步骤。", plain)
        self.assertNotIn("请使用简体中文。", plain)
        self.assertEqual(current["updated_at"], "2026-10-31T10:30:00+08:00")
        self.assertEqual(current["version"], "2026.10.31-1234567890ab")
        self.assertNotEqual(current["content_sha256"], previous["content_sha256"])

    def test_repeated_builds_are_byte_identical(self):
        first, _ = self.render("first")
        second, _ = self.render("second")
        for name in ("index.html", "full.txt", "version.json"):
            self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())

    def test_invalid_commit_is_rejected_before_outputs_exist(self):
        with self.assertRaises(ValueError):
            self.build(self.root, self.root / "invalid", '<script>invalid</script>')
        self.assertFalse((self.root / "invalid").exists())


if __name__ == "__main__":
    unittest.main()
