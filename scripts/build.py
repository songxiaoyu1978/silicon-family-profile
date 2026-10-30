"""由公开正文与经验证偏好生成同一版本的网页、纯文本和校验清单。"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
from html import escape
import json
from pathlib import Path
import re

from scripts.core import load_state


REPOSITORY_URL = "https://github.com/songxiaoyu1978/silicon-family-profile"
SHANGHAI = timezone(timedelta(hours=8))
CATEGORY_LABELS = {
    "communication": "交流", "work": "工作", "content": "内容表达",
    "interest": "兴趣", "lifestyle": "生活偏好",
}


def _timestamp(value: str) -> datetime:
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("更新时间必须包含时区")
    return result.astimezone(SHANGHAI)


def _render_text(source: str) -> str:
    """仅识别标题、普通段落和单层列表；所有来源内容先转义。"""
    result: list[str] = []
    paragraph: list[str] = []
    in_list = False

    def flush_paragraph():
        if paragraph:
            result.append("<p>" + escape(" ".join(paragraph)) + "</p>")
            paragraph.clear()

    def close_list():
        nonlocal in_list
        if in_list:
            result.append("</ul>")
            in_list = False

    for raw_line in source.splitlines():
        line = raw_line.strip()
        heading = re.fullmatch(r"(#{1,5})\s+(.+)", line)
        if not line:
            flush_paragraph()
            close_list()
        elif heading:
            flush_paragraph()
            close_list()
            level = len(heading.group(1)) + 1
            result.append(f"<h{level}>{escape(heading.group(2))}</h{level}>")
        elif line.startswith("- "):
            flush_paragraph()
            if not in_list:
                result.append("<ul>")
                in_list = True
            result.append("<li>" + escape(line[2:]) + "</li>")
        else:
            close_list()
            paragraph.append(line)
    flush_paragraph()
    close_list()
    return "\n".join(result)


def _preference_text(preferences: list[dict]) -> str:
    lines = ["# 已确认偏好（当前有效值）", "",
             "以下由初始偏好及通过验证的更新事件合并生成。撤销条目不再作为当前习惯。", ""]
    active = sorted((item for item in preferences if item["value"] is not None),
                    key=lambda item: (item["category"], item["id"]))
    for item in active:
        category = CATEGORY_LABELS.get(item["category"], item["category"])
        scope = "通用" if item["scope"] == "global" else item["scope"]
        lines.append(f"- {category}／{scope}：{item['value']}")
    if not active:
        lines.append("当前没有有效偏好条目。")
    return "\n".join(lines) + "\n"


def build(repo_root: Path, output_dir: Path, commit: str) -> dict:
    """生成三个公开文件，返回与 version.json 完全一致的版本元数据。"""
    repo_root, output_dir = Path(repo_root), Path(output_dir)
    if re.fullmatch(r"[0-9a-fA-F]{40}", commit) is None:
        raise ValueError("commit 必须是完整的 40 位 Git 提交号")
    commit = commit.lower()
    profile = (repo_root / "PROFILE.md").read_text(encoding="utf-8").strip() + "\n"
    projects = (repo_root / "PROJECTS.md").read_text(encoding="utf-8").strip() + "\n"
    preferences = load_state(repo_root)
    dates = []
    for source in (profile, projects):
        match = re.search(r"^更新时间：([^\n]+)$", source, re.MULTILINE)
        if match is None:
            raise ValueError("每篇正文必须有带时区的更新时间")
        dates.append(_timestamp(match.group(1).strip()))
    dates.extend(_timestamp(item["confirmed_at"]) for item in preferences)
    updated = max(dates)
    updated_at = updated.isoformat(timespec="seconds")
    code_match = re.search(r"^核验短码：([0-9a-f]{16})$", profile, re.MULTILINE)
    if code_match is None:
        raise ValueError("基础档案必须有固定的 16 位随机核验短码")
    verification_code = code_match.group(1)
    version = f"{updated:%Y.%m.%d}-{commit[:12]}"
    preference_text = _preference_text(preferences)
    full_text = (
        f"硅基家族公开共享档案\n版本：{version}\n更新时间：{updated_at}\n"
        f"来源提交：{commit}\n\n"
        "阅读说明：这是公开共同背景。实际读取、持续接续、工具权限与任务完成分别验收。\n\n"
        f"{profile}\n{preference_text}\n{projects}"
    )
    full_bytes = full_text.encode("utf-8")
    content_sha256 = hashlib.sha256(full_bytes).hexdigest()
    metadata = {
        "schema_version": 1,
        "version": version,
        "updated_at": updated_at,
        "commit": commit,
        "content_sha256": content_sha256,
        "verification_code": verification_code,
        "entrypoints": {"html": "index.html", "text": "full.txt", "version": "version.json"},
    }
    page = f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="description" content="宋晓宇与硅基家族的公开共同背景、成员职责、项目方向和已确认偏好。">
<title>硅基家族 · 共同档案</title>
<style>
:root{{color-scheme:light;--ink:#172b46;--muted:#536479;--accent:#006f7b;--line:#dce3e9}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:#f7f8fa;color:var(--ink);font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif;line-height:1.85}}
a{{color:var(--accent);text-underline-offset:.2em}}a:hover{{color:#004650}}a:focus-visible{{outline:3px solid #c58c20;outline-offset:5px}}
.skip{{position:absolute;top:-100px;left:1rem;background:#fff;padding:.5rem}}.skip:focus{{top:.5rem}}
.wrap{{max-width:900px;margin:0 auto;padding:0 30px}}header{{background:#142b45;color:#fff;padding:54px 0 32px;border-bottom:4px solid #47b8b0}}header .eyebrow{{font-size:.8rem;letter-spacing:.15em;color:#a8ddd8;margin:0}}h1{{font-family:"Songti SC","Noto Serif CJK SC",serif;font-size:clamp(2rem,6vw,3.1rem);line-height:1.35;margin:.5rem 0 .8rem}}header p{{max-width:680px;color:#d8e2ed}}header a{{color:#b6e8e3}}.links{{display:flex;gap:12px 22px;flex-wrap:wrap;margin-top:20px}}.meta{{font-size:.82rem;color:#c1cfdd;margin-top:22px;overflow-wrap:anywhere}}
nav{{padding:17px 0;border-bottom:1px solid var(--line);background:#fff}}nav .wrap{{display:flex;gap:12px 24px;flex-wrap:wrap}}nav a{{font-size:.9rem}}
main{{padding-top:20px;padding-bottom:50px}}article{{background:#fff;padding:30px 38px;margin:24px 0;border:1px solid var(--line);border-radius:10px;overflow-wrap:anywhere}}h2{{font-size:1.5rem;line-height:1.5;margin:0 0 1.4rem}}h3{{font-size:1.15rem;margin:2rem 0 .7rem;padding-top:.25rem;border-top:1px solid #edf0f3}}h4{{font-size:1.04rem;color:#006977;margin:1.5rem 0 .55rem}}p{{margin:.7rem 0 1rem}}li{{padding-left:.2rem;margin:.6rem 0}}ul{{padding-left:1.4rem}}.note{{font-size:.9rem;color:var(--muted)}}details{{border-top:1px solid var(--line);padding:18px 0}}summary{{cursor:pointer}}code{{font-family:ui-monospace,monospace;font-size:.8rem;overflow-wrap:anywhere}}footer{{font-size:.85rem;color:var(--muted);padding:12px 0 30px}}
@media(max-width:600px){{.wrap{{padding:0 18px}}header{{padding:34px 0 24px}}article{{padding:24px 20px;margin:18px 0}}h2{{font-size:1.3rem}}body{{font-size:16px}}}}
@media(prefers-reduced-motion:reduce){{html{{scroll-behavior:auto}}}}
@media print{{body{{background:#fff}}header{{background:#fff;color:#000}}header p,header .meta{{color:#333}}nav,.links{{display:none}}article{{border:0;padding:10px 0;break-inside:auto}}}}
</style>
</head>
<body>
<a class="skip" href="#content">跳到档案正文</a>
<header><div class="wrap">
<p class="eyebrow">硅基家族 · 公开共同背景</p>
<h1>同一份背景，各自的伙伴。</h1>
<p>认识小宇哥，理解彼此的分工，接续已经确认的习惯。不同 AI 从这里读取共同背景，保留各自的身份、权限和记忆。</p>
<div class="links"><a href="full.txt">阅读或下载完整纯文本</a><a href="{REPOSITORY_URL}">查看仓库与修改记录</a><a href="version.json">版本校验</a></div>
<div class="meta">版本 {escape(version)} · 更新于 {escape(updated_at)}</div>
</div></header>
<nav aria-label="档案目录"><div class="wrap"><a href="#profile">个人与成员</a><a href="#preferences">当前偏好</a><a href="#projects">项目方向</a><a href="#verification">版本说明</a></div></nav>
<main id="content" class="wrap">
<p class="note">公开可读不等于各端已接入。读取、理解、持续保存和实际执行分别核验；本文不会授予账号权限或恢复旧定时任务。</p>
<article id="profile">{_render_text(profile)}</article>
<article id="preferences">{_render_text(preference_text)}</article>
<article id="projects">{_render_text(projects)}</article>
<details id="verification"><summary>版本与独立校验</summary>
<p>网页和完整纯文本由同一组正文与有效偏好生成。下面的校验值对应 full.txt 实际 UTF-8 字节。</p>
<p>完整文本 SHA-256：<br><code>{content_sha256}</code></p>
<p>来源提交：<br><code>{commit}</code></p>
<p>本页核验短码来自档案正文。它用于辅助确认本次读取，不能单独证明长期记忆或运营能力。</p>
</details>
</main>
<footer class="wrap">由小宇哥确认，影子维护。公开资料只表达共同背景；具体任务使用当次材料与授权。</footer>
</body></html>
"""
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "full.txt").write_bytes(full_bytes)
    (output_dir / "index.html").write_bytes(page.encode("utf-8"))
    (output_dir / "version.json").write_bytes(
        (json.dumps(metadata, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    )
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description="生成硅基家族公开档案")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--output-dir", type=Path, default=Path("dist"))
    parser.add_argument("--commit", required=True, help="完整的 40 位来源提交号")
    args = parser.parse_args()
    result = build(args.repo_root, args.output_dir, args.commit)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
