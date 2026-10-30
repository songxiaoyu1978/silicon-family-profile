#!/usr/bin/env python3
"""在受信环境生成签名偏好；提交仅创建事件分支和 PR，不直接修改 main。"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core import REPOSITORY, MAX_EVENT_BYTES, canonical_bytes, load_state, read_json, validate_event


def _private_write(path: Path, data: bytes):
    """独占创建，拒绝覆盖已有私钥或草稿。"""
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)


def keygen(args):
    path = Path(args.private_key).expanduser().resolve()
    if any((parent / ".git").exists() for parent in path.parents):
        raise ValueError("私钥不能保存在 Git 仓库中，请使用仓库外的受控目录")
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    _private_write(path, private)
    result = {"status": "key_created", "public_key": base64.b64encode(public).decode("ascii"), "private_key_path": str(path), "note": "只把 public_key 交给影子登记；私钥不上传、不粘贴到聊天。"}
    if args.public_output:
        _private_write(Path(args.public_output), (json.dumps({"public_key": result["public_key"]}, ensure_ascii=False, indent=2) + "\n").encode())
    return result


def create(args):
    root = Path(args.state).expanduser().resolve()
    state = load_state(root)
    registry = read_json(root / "config/agents.json")
    private_path = Path(args.key).expanduser()
    if private_path.is_symlink() or private_path.stat().st_mode & 0o077:
        raise ValueError("私钥文件必须为本人可读写的普通文件（权限 600）")
    key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("需要 Ed25519 私钥")
    keys = [item for item in registry["agents"] if item.get("id") == args.agent and item.get("enabled") is True and (args.key_id is None or item.get("key_id") == args.key_id)]
    if len(keys) != 1:
        raise ValueError("没有唯一活动密钥，请先登记公钥或指定 --key-id")
    existing = next((item for item in state if item["id"] == args.preference_id), None)
    payload = {"protocol_version": 1, "repository": REPOSITORY, "agent_id": args.agent, "key_id": keys[0]["key_id"], "event_id": str(uuid4()), "base_commit": args.base_commit, "confirmed_at": args.confirmed_at or datetime.now(timezone.utc).isoformat(timespec="seconds"), "category": args.category, "preference_id": args.preference_id, "scope": args.scope, "expected_revision": existing["revision"] if existing else None, "old_value": existing["value"] if existing else None, "new_value": None if args.retract else args.new_value, "confirmation": "user_explicit", "public_safe": True}
    envelope = {"payload": payload, "signature": base64.b64encode(key.sign(canonical_bytes(payload))).decode("ascii")}
    result = validate_event(envelope, registry, state)
    if result["result"] != "valid":
        raise ValueError(result["reason"])
    output = Path(args.output).expanduser().resolve()
    # 草稿默认必须放在仓库外，避免日常 git add 意外公开未经复核的内容。
    if (root / ".git").exists() and (output == root or root in output.parents):
        raise ValueError("签名草稿必须保存在仓库以外的私有暂存目录")
    _private_write(output, (json.dumps(envelope, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    return {"status": "created_locally", "event_id": payload["event_id"], "output": str(output), "note": "仅已生成本地草稿，尚未提交。调用 create 表示来源成员已确认用户明确表达并完成上传前隐私检查。"}


def _gh(endpoint, method="GET", body=None, raw=False):
    command = ["gh", "api", endpoint, "--method", method]
    if raw:
        command += ["--header", "Accept: application/vnd.github.raw+json"]
    data = None
    if body is not None:
        command += ["--input", "-"]
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    result = subprocess.run(command, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
    if result.returncode:
        # 不回显任意远端错误正文，避免工具或代理把凭据写进终端。
        raise RuntimeError(f"GitHub 请求失败（{method} {endpoint.split('?')[0]}，退出码 {result.returncode}）；未确认成功，请检查 gh 登录和权限。")
    if raw:
        return result.stdout
    try:
        return json.loads(result.stdout)
    except (ValueError, UnicodeError) as exc:
        raise RuntimeError("GitHub 返回了无法解析的结果，未确认成功") from exc


def _remote_snapshot(directory: Path, repository: str):
    prefix = f"repos/{repository}"
    head = _gh(f"{prefix}/git/ref/heads/main")["object"]["sha"]
    tree = _gh(f"{prefix}/git/trees/{head}?recursive=1")
    if tree.get("truncated"):
        raise ValueError("远端目录结果不完整，停止提交")
    selected = []
    for item in tree["tree"]:
        path = item["path"]
        if path in {"data/preferences.json", "config/agents.json"} or (path.startswith("updates/") and path.endswith(".json")):
            if item.get("type") != "blob" or item.get("mode") != "100644":
                raise ValueError("远端资料必须是普通文本文件")
            if path.startswith("updates/") and (path.count("/") != 1 or item.get("size", 0) > MAX_EVENT_BYTES):
                raise ValueError("远端事件路径或大小异常")
            selected.append(path)
    if len(selected) > 10000:
        raise ValueError("历史事件过多，请由维护者检查")
    for path in selected:
        content = _gh(f"{prefix}/contents/{path}?ref={head}", raw=True)
        target = directory / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    (directory / "updates").mkdir(exist_ok=True)
    return head


def submit(args):
    if args.repo != REPOSITORY:
        raise ValueError("本客户端仅允许指定的家族公开仓库")
    event_path = Path(args.event).expanduser()
    if event_path.stat().st_size > MAX_EVENT_BYTES:
        raise ValueError("事件文件过大，停止提交")
    envelope = read_json(event_path)
    # 先检查信封结构，避免远端调用前把任意输入插入分支名或接口路径。
    from core import _schema
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
        raise ValueError("签名信封格式错误")
    _schema(envelope["payload"])
    user_id = _gh("user")["id"]
    prefix = f"repos/{REPOSITORY}"
    with tempfile.TemporaryDirectory(prefix="family-profile-preflight-") as temporary:
        root = Path(temporary)
        head = _remote_snapshot(root, REPOSITORY)
        state = load_state(root)
        registry = read_json(root / "config/agents.json")
        result = validate_event(envelope, registry, state, github_user_id=user_id)
        if result["result"] == "idempotent":
            return {"status": "already_in_main", "event_id": envelope["payload"]["event_id"], "main_commit": head, "note": "远端主分支已包含相同事件；网页发布状态未核验。"}
        if result["result"] != "valid":
            raise ValueError(result["reason"])
        base = envelope["payload"]["base_commit"]
        comparison = _gh(f"{prefix}/compare/{base}...{head}")
        if comparison.get("status") not in {"ahead", "identical"}:
            raise ValueError("草稿基础提交不属于当前主分支历史")
        event_id = envelope["payload"]["event_id"]
        branch = f"preference/{event_id}"
        _gh(f"{prefix}/git/refs", method="POST", body={"ref": f"refs/heads/{branch}", "sha": head})
        try:
            content = (json.dumps(envelope, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
            _gh(f"{prefix}/contents/updates/{event_id}.json", method="PUT", body={"message": f"提交偏好更新 {event_id}", "content": base64.b64encode(content).decode("ascii"), "branch": branch})
            pr = _gh(f"{prefix}/pulls", method="POST", body={"title": f"偏好更新：{envelope['payload']['preference_id']}", "head": branch, "base": "main", "body": f"签名事件 `{event_id}`。来源环境：`{envelope['payload']['agent_id']}`。\n\n仅包含已筛选的偏好变更，不包含聊天原文。等待可信门禁核验和合并。"})
        except Exception as exc:
            raise RuntimeError(f"事件分支 {branch} 已创建，但后续提交或 PR 未确认成功；请检查现有分支，不要声称已合并。") from exc
    return {"status": "submitted", "event_id": event_id, "pull_request": pr["html_url"], "note": "已提交更新请求；是否合并与网页是否更新须分别核验。"}


def parser():
    cli = argparse.ArgumentParser(description="硅基家族签名偏好客户端；不会自动采集聊天。")
    commands = cli.add_subparsers(dest="command", required=True)
    key = commands.add_parser("keygen", help="创建私有 Ed25519 密钥，只输出公钥")
    key.add_argument("--private-key", required=True)
    key.add_argument("--public-output")
    key.set_defaults(function=keygen)
    event = commands.add_parser("create", help="用户已明确确认并完成隐私检查后生成本地签名草稿")
    for flag in ("state", "agent", "key", "preference-id", "category", "base-commit", "output"):
        event.add_argument("--" + flag, required=True)
    event.add_argument("--key-id")
    event.add_argument("--scope", default="global")
    event.add_argument("--confirmed-at")
    change = event.add_mutually_exclusive_group(required=True)
    change.add_argument("--new-value")
    change.add_argument("--retract", action="store_true")
    event.set_defaults(function=create)
    upload = commands.add_parser("submit", help="远端预检后只创建独立事件分支和 PR")
    upload.add_argument("--event", required=True)
    upload.add_argument("--repo", default=REPOSITORY)
    upload.set_defaults(function=submit)
    return cli


def main():
    args = parser().parse_args()
    try:
        result = args.function(args)
    except (ValueError, OSError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "failed", "reason": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
