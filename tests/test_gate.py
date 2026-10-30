import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

from scripts.github_gate import classify_files, check_pr_identity, parse_event_bytes


class GateBoundaryTests(unittest.TestCase):
    def test_only_one_new_event_can_be_automatic(self):
        path = 'updates/123e4567-e89b-42d3-a456-426614174000.json'
        self.assertEqual(classify_files([{'filename': path, 'status': 'added'}]), path)
        self.assertIsNone(classify_files([{'filename': path, 'status': 'modified'}]))
        self.assertIsNone(classify_files([{'filename': path, 'status': 'added'}, {'filename': 'PROFILE.md', 'status': 'modified'}]))

    def test_workflow_symlink_rename_and_traversal_are_not_automatic(self):
        for name in ['.github/workflows/a.yml', 'updates/../a.json', 'updates/a.json', 'updates/sub/a.json']:
            self.assertIsNone(classify_files([{'filename': name, 'status': 'added'}]))
        self.assertIsNone(classify_files([{'filename': 'updates/123e4567-e89b-42d3-a456-426614174000.json', 'status': 'renamed'}]))

    def test_identity_uses_base_repository_and_numeric_user(self):
        pr = {'base': {'repo': {'full_name': 'songxiaoyu1978/silicon-family-profile'}, 'ref': 'main'},
              'head': {'sha': 'a' * 40}, 'user': {'id': 254205443}, 'state': 'open', 'draft': False}
        self.assertEqual(check_pr_identity(pr), 254205443)
        pr['base']['repo']['full_name'] = 'someone/else'
        with self.assertRaises(ValueError):
            check_pr_identity(pr)

    def test_draft_and_untrusted_sha_are_rejected(self):
        pr = {'base': {'repo': {'full_name': 'songxiaoyu1978/silicon-family-profile'}, 'ref': 'main'},
              'head': {'sha': '$(echo injected)'}, 'user': {'id': 254205443}, 'state': 'open', 'draft': False}
        with self.assertRaises(ValueError):
            check_pr_identity(pr)

    def test_bad_envelope_is_rejected_without_attribute_error(self):
        for raw in [b'[]', b'null', b'{"payload": [], "signature":"x"}']:
            with self.assertRaises(ValueError):
                parse_event_bytes(raw)

    def test_raw_event_limits_and_duplicate_keys_match_history_reader(self):
        for raw in [b'{"payload":{},"payload":{},"signature":"x"}', b' ' * 9000 + b'{}']:
            with self.assertRaises(ValueError):
                parse_event_bytes(raw)

    def test_excessive_json_nesting_is_a_normal_rejection(self):
        with self.assertRaises(ValueError):
            parse_event_bytes(b'[' * 1500 + b']' * 1500)

    def test_malformed_first_pr_does_not_block_later_authorized_pr(self):
        from scripts import github_gate as gate
        calls = []
        base = 'b' * 40
        def pr(number):
            return {'number': number, 'base': {'repo': {'full_name': gate.REPOSITORY}, 'ref': 'main'},
                    'head': {'sha': str(number) * 40}, 'user': {'id': gate.OWNER_ID}, 'state': 'open', 'draft': False}
        class FakeAPI:
            def __init__(self, token): pass
            def pages(self, path):
                if '/pulls?' in path: return [pr(1), pr(2)]
                if '/pulls/1/files' in path: return [{'filename': 'updates/123e4567-e89b-42d3-a456-426614174000.json', 'status': 'added'}]
                return [{'filename': 'PROFILE.md', 'status': 'modified'}]
            def call(self, method, path, payload=None):
                calls.append((method, path, payload))
                if '/git/trees/' in path: return {'tree': [{'path': 'updates/123e4567-e89b-42d3-a456-426614174000.json', 'type': 'blob', 'mode': '100644'}]}
                if '/contents/' in path: return {'type': 'file', 'encoding': 'base64', 'size': 2, 'content': base64.b64encode(b'[]').decode()}
                if path.endswith('/pulls/1'): return pr(1)
                if path.endswith('/pulls/2'): return pr(2)
                if '/git/ref/heads/main' in path: return {'object': {'sha': base}}
                if method == 'PUT' and path.endswith('/merge'): return {'merged': True}
                return {}
        with tempfile.TemporaryDirectory() as temp:
            event = Path(temp) / 'event.json'
            event.write_text(json.dumps({'inputs': {'manual_pr': '2', 'expected_sha': '2' * 40}}))
            env = {'GH_TOKEN': 'test-only', 'GITHUB_EVENT_PATH': str(event), 'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_ACTOR_ID': str(gate.OWNER_ID)}
            with patch.dict(os.environ, env), patch.object(gate, 'API', FakeAPI), patch.object(gate, 'checker_api', return_value=FakeAPI('x')), patch.object(gate.subprocess, 'run', return_value=Mock(returncode=0)), patch.object(gate.subprocess, 'check_output', return_value=base + '\n'):
                gate.main()
        merged = [path for method, path, _ in calls if method == 'PUT' and path.endswith('/merge')]
        self.assertEqual(merged, [f'/repos/{gate.REPOSITORY}/pulls/2/merge'])
        self.assertTrue(any('/pages.yml/dispatches' in path for _, path, _ in calls))


if __name__ == '__main__':
    unittest.main()
