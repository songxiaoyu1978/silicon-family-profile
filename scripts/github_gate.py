#!/usr/bin/env python3
"""只用可信主分支代码检查公开更新，不检出或执行修改申请中的程序。"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

REPOSITORY = 'songxiaoyu1978/silicon-family-profile'
OWNER_ID = 254205443
CHECK_NAME = 'family-profile-authorized'
EVENT_PATH = re.compile(r'^updates/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.json$')
SHA = re.compile(r'^[0-9a-f]{40}$')


def classify_files(files):
    """只有单一新增的签名事件可以自动合并。"""
    if len(files) != 1:
        return None
    item = files[0]
    name = item.get('filename', '')
    return name if item.get('status') == 'added' and EVENT_PATH.fullmatch(name) else None


def check_pr_identity(pr):
    if pr.get('base', {}).get('repo', {}).get('full_name') != REPOSITORY or pr['base'].get('ref') != 'main':
        raise ValueError('目标仓库或主分支不符')
    if pr.get('state') != 'open' or pr.get('draft') or not SHA.fullmatch(pr.get('head', {}).get('sha', '')):
        raise ValueError('修改申请未就绪或提交编号不合法')
    user_id = pr.get('user', {}).get('id')
    if type(user_id) is not int or user_id <= 0:
        raise ValueError('缺少实际 GitHub 用户编号')
    return user_id


def parse_event_bytes(raw):
    """门禁与历史重建共用严格JSON解析，并对原始字节执行同一上限。"""
    from scripts.core import MAX_EVENT_BYTES, read_json
    if len(raw) > MAX_EVENT_BYTES:
        raise ValueError('事件原始文件过大')
    with tempfile.TemporaryDirectory(prefix='family-event-') as temp:
        path = Path(temp) / 'event.json'
        path.write_bytes(raw)
        try:
            envelope = read_json(path)
        except RecursionError as exc:
            raise ValueError('JSON嵌套过深') from exc
    if not isinstance(envelope, dict) or set(envelope) != {'payload', 'signature'} or not isinstance(envelope['payload'], dict):
        raise ValueError('事件信封或payload不是合法对象')
    return envelope


class API:
    def __init__(self, token):
        self.token = token

    def call(self, method, path, payload=None):
        if not path.startswith('/') or path.startswith('//'):
            raise ValueError('不允许外部接口地址')
        data = json.dumps(payload).encode() if payload is not None else None
        req = Request('https://api.github.com' + path, data=data, method=method,
                      headers={'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
                               'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json'})
        try:
            with urlopen(req, timeout=45) as response:
                raw = response.read(2_000_001)
            if len(raw) > 2_000_000:
                raise ValueError('接口响应过大')
            return json.loads(raw) if raw else None
        except HTTPError as exc:
            # 只报告HTTP状态，不把响应内容或认证信息写入公共日志。
            raise RuntimeError('GitHub 接口返回 HTTP ' + str(exc.code)) from None

    def pages(self, path):
        result = []
        for page in range(1, 11):
            separator = '&' if '?' in path else '?'
            batch = self.call('GET', path + separator + f'per_page=100&page={page}')
            result.extend(batch)
            if len(batch) < 100:
                return result
        raise ValueError('分页数量超出范围，交由人工检查')


def checker_api():
    """专用应用只获得本仓内容读取和检查写入，不把私钥分发给成员。"""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    app_id, pem = os.environ.get('CHECK_APP_ID'), os.environ.get('CHECK_APP_PRIVATE_KEY')
    if not app_id or not pem:
        raise RuntimeError('专用校验应用尚未配置，自动合并保持关闭')
    if not app_id.isdigit():
        raise ValueError('应用编号格式错误')
    def encode(value):
        return base64.urlsafe_b64encode(value).rstrip(b'=')
    now = int(time.time())
    body = encode(b'{"alg":"RS256","typ":"JWT"}') + b'.' + encode(json.dumps({'iat': now - 60, 'exp': now + 540, 'iss': app_id}, separators=(',', ':')).encode())
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    jwt = (body + b'.' + encode(key.sign(body, padding.PKCS1v15(), hashes.SHA256()))).decode()
    app = API(jwt)
    installation = app.call('GET', f'/repos/{REPOSITORY}/installation')
    result = app.call('POST', f"/app/installations/{int(installation['id'])}/access_tokens",
                      {'repositories': [REPOSITORY.split('/')[1]], 'permissions': {'checks': 'write', 'contents': 'read'}})
    return API(result['token'])


def report(reporter, sha, conclusion, summary):
    reporter.call('POST', f'/repos/{REPOSITORY}/check-runs',
                  {'name': CHECK_NAME, 'head_sha': sha, 'status': 'completed', 'conclusion': conclusion,
                   'output': {'title': '公开档案来源与范围检查', 'summary': summary}})


def main():
    from scripts.core import MAX_EVENT_BYTES, load_state, validate_event
    root = Path(__file__).resolve().parent.parent
    api = API(os.environ['GH_TOKEN'])
    reporter = checker_api()
    context = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    manual = os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and context.get('inputs', {}).get('manual_pr')
    manual_number = int(context['inputs']['manual_pr']) if manual else None
    if manual and str(os.environ.get('GITHUB_ACTOR_ID')) != str(OWNER_ID):
        raise ValueError('只有维护人能确认非自动修改')
    manual_sha = context.get('inputs', {}).get('expected_sha', '')
    if manual and not SHA.fullmatch(manual_sha):
        raise ValueError('人工确认必须绑定具体提交编号')
    open_prs = api.pages(f'/repos/{REPOSITORY}/pulls?state=open&sort=created&direction=asc')
    merged = 0
    refresh_requested = False
    # 每次触发扫描待处理队列，避免GitHub并发队列取消旧触发时漏掉公开修改申请。
    for listed in open_prs:
        number = int(listed['number'])
        pr = listed
        try:
            pr = api.call('GET', f'/repos/{REPOSITORY}/pulls/{number}')
            if pr.get('draft'):
                continue
            actor_id = check_pr_identity(pr)
            sha = pr['head']['sha']
            files = api.pages(f'/repos/{REPOSITORY}/pulls/{number}/files')
            event_path = classify_files(files)
            confirmed_manual = manual_number == number and sha == manual_sha
            if not event_path and not confirmed_manual:
                report(reporter, sha, 'action_required', '此修改涉及正文、身份、权限或程序，需要影子对这个提交单独核对。')
                continue
            # 只刷新可信main。修改申请的head内容只经Contents API按数据读取。
            subprocess.run(['git', 'fetch', 'origin', 'main'], cwd=root, check=True, capture_output=True)
            subprocess.run(['git', 'reset', '--hard', 'origin/main'], cwd=root, check=True, capture_output=True)
            validated_base = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
            if event_path:
                tree = api.call('GET', f'/repos/{REPOSITORY}/git/trees/{sha}?recursive=1')
                entries = [item for item in tree.get('tree', []) if item.get('path') == event_path]
                if tree.get('truncated') or len(entries) != 1 or entries[0].get('type') != 'blob' or entries[0].get('mode') != '100644':
                    raise ValueError('事件必须是普通文件，不能使用符号链接或其他Git对象')
                obj = api.call('GET', f'/repos/{REPOSITORY}/contents/{quote(event_path)}?ref={sha}')
                if obj.get('type') != 'file' or obj.get('encoding') != 'base64' or int(obj.get('size', 0)) > MAX_EVENT_BYTES:
                    raise ValueError('更新不是允许的小型JSON文件')
                raw = base64.b64decode(obj['content'], validate=False)
                envelope = parse_event_bytes(raw)
                payload = envelope['payload']
                if event_path != 'updates/' + str(payload.get('event_id')) + '.json':
                    raise ValueError('事件编号与文件名不同')
                base = payload.get('base_commit', '')
                if not SHA.fullmatch(base):
                    raise ValueError('基础版本格式错误')
                ancestry = subprocess.run(['git', 'merge-base', '--is-ancestor', base, 'HEAD'], cwd=root, capture_output=True)
                if ancestry.returncode != 0:
                    raise ValueError('基础版本不在可信主分支历史中')
                registry = json.loads((root / 'config/agents.json').read_text())
                outcome = validate_event(envelope, registry, load_state(root), github_user_id=actor_id)
                if outcome['result'] != 'valid':
                    report(reporter, sha, 'failure', '更新未自动通过：' + outcome.get('reason', outcome['result']))
                    continue
                comparison = api.call('GET', f'/repos/{REPOSITORY}/compare/{validated_base}...{sha}')
                if comparison.get('status') != 'ahead':
                    # 严格保护要求候选包含最新main；只更新分支，不更改签名payload。
                    api.call('PUT', f'/repos/{REPOSITORY}/pulls/{number}/update-branch', {'expected_head_sha': sha})
                    refresh_requested = True
                    print(f'修改申请 #{number} 已请求合入最新主分支，将在新提交上重新检查。')
                    continue
            else:
                # 此路径仅由拥有Actions权限的维护人显式dispatch，输入绑定本次head。
                if actor_id != OWNER_ID:
                    raise ValueError('非自动修改需要维护人提交或另行核对')
            fresh = api.call('GET', f'/repos/{REPOSITORY}/pulls/{number}')
            tip = api.call('GET', f'/repos/{REPOSITORY}/git/ref/heads/main')['object']['sha']
            if fresh['head']['sha'] != sha or tip != validated_base:
                report(reporter, sha, 'failure', '检查期间版本变化，请重新触发；没有覆盖现有内容。')
                continue
            report(reporter, sha, 'success', '受信来源、字段范围和当前版本已核对。' if event_path else '维护人已对这个提交显式确认。')
            result = api.call('PUT', f'/repos/{REPOSITORY}/pulls/{number}/merge',
                              {'sha': sha, 'merge_method': 'squash'})
            if result.get('merged'):
                merged += 1
                print(f'修改申请 #{number} 已合并；网页发布另行核验。')
                # 成功一项立即触发，后面的坏申请不能吞掉已经完成的发布请求。
                api.call('POST', f'/repos/{REPOSITORY}/actions/workflows/pages.yml/dispatches', {'ref': 'main'})
        except (ValueError, RuntimeError, KeyError, TypeError, RecursionError, subprocess.CalledProcessError) as exc:
            print(f'修改申请 #{number} 保留待处理：{exc}')
            candidate_sha = pr.get('head', {}).get('sha', '')
            if SHA.fullmatch(candidate_sha):
                try:
                    report(reporter, candidate_sha, 'failure', '未通过本次范围与格式检查，请由来源成员核对。')
                except RuntimeError:
                    print('检查状态暂未写入；不会继续合并这个修改申请。')
    if merged or (os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and not manual_number):
        # 再次运行无输入的门禁会补发最新网页，可恢复合并后网络中断。
        api.call('POST', f'/repos/{REPOSITORY}/actions/workflows/pages.yml/dispatches', {'ref': 'main'})
        print('已请求网页发布，尚不代表部署成功。')
    if refresh_requested:
        api.call('POST', f'/repos/{REPOSITORY}/actions/workflows/guard.yml/dispatches', {'ref': 'main'})
        print('已请求对更新后的分支重新执行门禁。')


if __name__ == '__main__':
    main()
