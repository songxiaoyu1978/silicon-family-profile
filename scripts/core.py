"""公开偏好事件：严格验签、身份核对、确定性归并与防覆盖。"""
from __future__ import annotations

import base64
import binascii
import copy
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import unicodedata
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

REPOSITORY = "songxiaoyu1978/silicon-family-profile"
CATEGORIES = {"communication", "work", "content", "interest", "lifestyle"}
IDENTIFIER = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
PAYLOAD_FIELDS = {"protocol_version", "repository", "agent_id", "key_id", "event_id", "base_commit", "confirmed_at", "category", "preference_id", "scope", "expected_revision", "old_value", "new_value", "confirmation", "public_safe"}
BASE_FIELDS = {"id", "category", "scope", "value", "revision", "confirmed_at", "source_agent"}
MAX_EVENT_BYTES = 8192
MAX_VALUE_LENGTH = 500

# 这些规则是保守的第二道拦截；不能替代来源成员在上传前结合上下文筛选隐私。
UNSAFE = re.compile(
    r"(?:https?://|www\.|file://|[\w.+-]+@[\w.-]+\.[a-z]{2,}|(?:\d{1,3}\.){3}\d{1,3})"
    r"|(?:(?<!\d)1[3-9]\d{9}(?!\d)|(?<!\d)\d{15,19}[0-9Xx]?(?!\d)|\b(?:gh[pousr]_|github_pat_|sk-)[A-Za-z0-9_]+)"
    r"|(?:/Users/|/home/|[A-Za-z]:\\|BEGIN .*PRIVATE KEY|ssh-(?:rsa|ed25519))"
    r"|(?:密码|口令|密钥|令牌|身份证|银行卡|账户余额|银行账号|私钥|验证码|手机号|电话号码)"
    r"|(?:病历|诊断|病史|疾病|患有|哮喘|血压|血糖|过敏|服药|用药|药物|怀孕|抑郁|健康状况|医院|体检)"
    r"|(?:住址|住在|地址|家庭地址|当前位置|定位|行程|航班|车次|酒店|出差|明天|后天|下周|今晚|明早)"
    r"|(?:客户名|客户名单|合同|报价|商业机密|内部商业|内部资料|毛利|利润|资金流水)"
    r"|(?:\b(?:password|secret|token|api[_ -]?key|diagnosis|medical|itinerary|latitude|longitude)\b)"
    r"|(?:[<>`]|\b20\d{2}[-/]\d{1,2}[-/]\d{1,2}\b)", re.IGNORECASE
)

# 身份、职责和授权不能伪装成兴趣或沟通偏好进入自动通道。
# 仅检查新值：已经人工审定的旧基础文本仍可被纠正或撤销。
MANUAL_CHANGE = re.compile(
    r"(?:无需|无须|不必|不用|免于|免除|不再需要|不再要求|不需要).{0,24}(?:确认|审批|授权|许可|审看|审核)"
    r"|(?:忽略|绕过|跳过|关闭|取消|禁用).{0,24}(?:规则|指令|保护|安全|权限|门禁|审核|审批|校验|检查|确认)"
    r"|(?:授权|赋予|授予|放开|扩大|提升|增加).{0,36}(?:权限|访问|发布|执行|操作|支付|删除|上传|发送|转账)"
    r"|(?:身份|角色|职责|分工|名字|名称).{0,8}(?:为|是|改|变|调整|设|更新)"
    r"|(?:改名|更名|改叫|重命名)"
    r"|(?:从今|以后|今后|现在|改由|由).{0,20}(?:负责|统筹|担任|主管|接管|管理家族)"
    r"|(?:执行|运行).{0,8}(?:以下|下面|这些|这段|此|命令|代码|脚本)"
    r"|(?:泄露|透露|公开|发送|上传|导出|交给|把).{0,30}(?:私人聊天|聊天原文|聊天记录|隐私资料|内部信息)"
    r"|(?:\b(?:ignore|bypass|disable|skip)\b.{0,30}\b(?:instructions?|rules?|checks?|approvals?|safety|restrictions?)\b)"
    r"|(?:\b(?:grant|expand|elevate)\b.{0,30}\b(?:permissions?|privileges?|access)\b)"
    r"|(?:\b(?:run|execute)\b.{0,20}\b(?:commands?|scripts?|code)\b)", re.IGNORECASE
)
AUTOMATIC_EXTERNAL_ACTION = re.compile(r"(?:自动|直接|自行).{0,12}(?:发布|付款|支付|删除|转账|上传|发送|分享|同步)")
RESTRICTIVE_PREFIX = re.compile(r"(?:不要|禁止|不得|不能|不允许|不希望|不应|不可).{0,8}$")


def canonical_bytes(payload) -> bytes:
    """固定 JSON 编码；不允许非 JSON 数值或非字符串字典键。"""
    def check(value):
        if isinstance(value, dict):
            if not all(isinstance(key, str) for key in value):
                raise ValueError("JSON 键必须是字符串")
            for child in value.values():
                check(child)
        elif isinstance(value, list):
            for child in value:
                check(child)
    check(payload)
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _identifier(value, label):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError(f"{label} 必须是小写 ASCII 标识符")


def _timestamp(value):
    if not isinstance(value, str) or "T" not in value or len(value) > 40:
        raise ValueError("确认时间必须是含时区的 ISO 时间")
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("确认时间格式错误") from exc
    if date.tzinfo is None or date.utcoffset() is None:
        raise ValueError("确认时间必须包含时区")


def _revision(value, allow_none=True):
    if value is None and allow_none:
        return
    if type(value) is int and value > 0:
        return
    if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value):
        return
    raise ValueError("版本标识错误")


def safe_text(value):
    if value is None:
        return
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_VALUE_LENGTH:
        raise ValueError("偏好必须是非空短文本，或 null 撤销")
    if value != value.strip() or any(unicodedata.category(char).startswith("C") for char in value):
        raise ValueError("偏好文本不能有控制字符、换行或首尾空白")
    if UNSAFE.search(unicodedata.normalize("NFKC", value)):
        raise ValueError("文本命中隐私或不安全格式规则，请在本地检查，勿上传原话")


def _preference_only(value):
    """保守拦截明显越权表达；语义隐含或改写仍需来源成员判断。"""
    if value is None:
        return
    text = unicodedata.normalize("NFKC", value)
    if MANUAL_CHANGE.search(text):
        raise ValueError("内容涉及身份、职责、授权或执行指令，请交影子人工处理")
    for clause in re.split(r"[，,。；;！？!?]", text):
        for match in AUTOMATIC_EXTERNAL_ACTION.finditer(clause):
            if not RESTRICTIVE_PREFIX.search(clause[:match.start()]):
                raise ValueError("自动对外操作不属于偏好更新，请交影子人工确认授权")


def _schema(payload):
    if not isinstance(payload, dict) or set(payload) != PAYLOAD_FIELDS:
        raise ValueError("事件字段缺失或包含未许可字段")
    if type(payload["protocol_version"]) is not int or payload["protocol_version"] != 1:
        raise ValueError("仅支持事件协议 v1")
    if payload["repository"] != REPOSITORY:
        raise ValueError("事件所属仓库不匹配")
    for name in ("agent_id", "key_id", "preference_id", "scope"):
        _identifier(payload[name], name)
    try:
        event_id = payload["event_id"]
        if not isinstance(event_id, str) or str(UUID(event_id)) != event_id:
            raise ValueError
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("event_id 必须是标准小写 UUID") from exc
    if not isinstance(payload["base_commit"], str) or not re.fullmatch(r"[0-9a-f]{40}", payload["base_commit"]):
        raise ValueError("base_commit 必须是完整提交编号")
    _timestamp(payload["confirmed_at"])
    if not isinstance(payload["category"], str) or payload["category"] not in CATEGORIES:
        raise ValueError("类别不在自动公开范围")
    _revision(payload["expected_revision"])
    if payload["confirmation"] != "user_explicit" or payload["public_safe"] is not True:
        raise ValueError("需要用户明确确认和上传前公开范围检查")
    safe_text(payload["old_value"])
    safe_text(payload["new_value"])
    _preference_only(payload["new_value"])
    if payload["old_value"] == payload["new_value"]:
        raise ValueError("偏好没有变化")


def _registry(registry):
    if not isinstance(registry, dict) or set(registry) != {"schema_version", "agents"} or type(registry["schema_version"]) is not int or registry["schema_version"] != 1 or not isinstance(registry["agents"], list):
        raise ValueError("受信注册表格式错误")
    seen = set()
    for item in registry["agents"]:
        if not isinstance(item, dict) or set(item) != {"id", "key_id", "public_key", "github_user_id", "enabled"}:
            raise ValueError("受信密钥登记字段错误")
        _identifier(item["id"], "agent id")
        _identifier(item["key_id"], "key id")
        identity = (item["id"], item["key_id"])
        if identity in seen:
            raise ValueError("密钥登记重复")
        seen.add(identity)
        if type(item["enabled"]) is not bool or type(item["github_user_id"]) is not int or item["github_user_id"] <= 0:
            raise ValueError("密钥状态或 GitHub 用户编号错误")
        try:
            public = base64.b64decode(item["public_key"], validate=True)
            if len(public) != 32:
                raise ValueError
        except (ValueError, TypeError, binascii.Error) as exc:
            raise ValueError("公钥格式错误") from exc


def _verify(envelope, registry, github_user_id=None, historical=False):
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
        raise ValueError("签名信封字段错误")
    if len(canonical_bytes(envelope)) > MAX_EVENT_BYTES:
        raise ValueError("事件过大")
    payload = envelope["payload"]
    _schema(payload)
    _registry(registry)
    matches = [item for item in registry["agents"] if isinstance(item, dict) and item.get("id") == payload["agent_id"] and item.get("key_id") == payload["key_id"]]
    if len(matches) != 1:
        raise ValueError("签名密钥未注册或登记重复")
    registered = matches[0]
    if type(registered.get("github_user_id")) is not int or registered["github_user_id"] <= 0:
        raise ValueError("注册表缺少真实 GitHub 用户编号")
    if type(registered.get("enabled")) is not bool:
        raise ValueError("密钥启用状态错误")
    if not historical and not registered["enabled"]:
        raise ValueError("该签名密钥已停用")
    if github_user_id is not None and (type(github_user_id) is not int or github_user_id != registered["github_user_id"]):
        raise ValueError("提交者的 GitHub 身份与密钥登记不一致")
    try:
        public = base64.b64decode(registered["public_key"], validate=True)
        signature = base64.b64decode(envelope["signature"], validate=True)
        if len(public) != 32 or len(signature) != 64:
            raise ValueError("签名长度错误")
        Ed25519PublicKey.from_public_bytes(public).verify(signature, canonical_bytes(payload))
    except (InvalidSignature, ValueError, TypeError, KeyError, binascii.Error) as exc:
        raise ValueError("Ed25519 签名验证失败") from exc
    return payload


def _digest(payload):
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def _state_result(state, payload):
    if not isinstance(state, list):
        raise ValueError("偏好状态必须是列表")
    digest = _digest(payload)
    for entry in state:
        previous = entry.get("_applied_events", {}).get(payload["event_id"])
        if previous is not None:
            if previous != digest:
                return {"result": "rejected", "reason": "同一 event_id 被用于不同内容"}
            return {"result": "idempotent", "reason": "该事件已应用"}
    entries = [entry for entry in state if entry["id"] == payload["preference_id"]]
    if len(entries) > 1:
        raise ValueError("状态中存在重复偏好编号")
    if not entries:
        if payload["expected_revision"] is not None or payload["old_value"] is not None:
            return {"result": "conflict", "reason": "新条目必须以空版本和空原值开始"}
        if payload["new_value"] is None:
            return {"result": "rejected", "reason": "不能撤销不存在的偏好"}
        return {"result": "valid", "reason": "可新增偏好"}
    entry = entries[0]
    if entry["category"] != payload["category"] or entry["scope"] != payload["scope"]:
        return {"result": "conflict", "reason": "已有条目的类别或适用范围不匹配"}
    if type(entry["revision"]) != type(payload["expected_revision"]) or entry["revision"] != payload["expected_revision"]:
        return {"result": "conflict", "reason": "该字段版本已变化，需要重新确认"}
    if entry["value"] != payload["old_value"]:
        return {"result": "conflict", "reason": "该字段原值不匹配"}
    return {"result": "valid", "reason": "签名事件可以应用"}


def validate_event(envelope, registry, state, github_user_id=None) -> dict:
    """本地校验可不传 GitHub 身份；远端门禁必须传实际认证用户编号。"""
    try:
        payload = _verify(envelope, registry, github_user_id)
        result = _state_result(state, payload)
        result.update(event_id=payload["event_id"], preference_id=payload["preference_id"], github_identity_verified=github_user_id is not None)
        return result
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        return {"result": "rejected", "reason": str(exc)}


def apply_event(state, payload) -> list[dict]:
    """应用已验签事件；保留撤销记录和事件摘要，不原地修改输入。"""
    _schema(payload)
    result = _state_result(state, payload)
    if result["result"] not in {"valid", "idempotent"}:
        raise ValueError(result["reason"])
    changed = copy.deepcopy(state)
    if result["result"] == "idempotent":
        return changed
    existing = next((entry for entry in changed if entry["id"] == payload["preference_id"]), None)
    if existing is None:
        existing = {"id": payload["preference_id"]}
        changed.append(existing)
    existing.update(category=payload["category"], scope=payload["scope"], value=payload["new_value"], revision=payload["event_id"], confirmed_at=payload["confirmed_at"], source_agent=payload["agent_id"])
    existing.setdefault("_applied_events", {})[payload["event_id"]] = _digest(payload)
    return sorted(changed, key=lambda item: item["id"])


def read_json(path: Path):
    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("JSON 存在重复字段")
            value[key] = item
        return value
    if path.is_symlink():
        raise ValueError("资料文件不能是符号链接")
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("JSON 非法数值")))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"无法读取合法 JSON：{path.name}") from exc


def load_state(repo_root: Path) -> list[dict]:
    """仅从可信仓库历史重建；停用旧密钥仍保留公钥以验证已接纳事件。"""
    root = Path(repo_root)
    base = read_json(root / "data/preferences.json")
    registry = read_json(root / "config/agents.json")
    _registry(registry)
    if not isinstance(base, dict) or set(base) != {"schema_version", "preferences"} or type(base["schema_version"]) is not int or base["schema_version"] != 1 or not isinstance(base["preferences"], list):
        raise ValueError("基础偏好格式错误")
    state = copy.deepcopy(base["preferences"])
    ids = set()
    for entry in state:
        if not isinstance(entry, dict) or set(entry) != BASE_FIELDS:
            raise ValueError("基础偏好条目字段错误")
        for key in ("id", "scope", "source_agent"):
            _identifier(entry[key], key)
        if entry["id"] in ids:
            raise ValueError("基础偏好编号重复")
        ids.add(entry["id"])
        if entry["category"] not in CATEGORIES:
            raise ValueError("基础偏好类别错误")
        _revision(entry["revision"], allow_none=False)
        _timestamp(entry["confirmed_at"])
        safe_text(entry["value"])
    pending = []
    events_seen = set()
    updates = root / "updates"
    if updates.is_symlink():
        raise ValueError("更新目录不能是符号链接")
    for path in sorted(updates.glob("*.json")):
        if path.stat().st_size > MAX_EVENT_BYTES:
            raise ValueError("历史事件过大")
        payload = _verify(read_json(path), registry, historical=True)
        event_id = payload["event_id"]
        if path.name != f"{event_id}.json" or event_id in events_seen:
            raise ValueError("历史事件文件名不匹配或事件编号重复")
        events_seen.add(event_id)
        pending.append(payload)
    while pending:
        ready = [event for event in pending if _state_result(state, event)["result"] == "valid"]
        ready_ids = [event["preference_id"] for event in ready]
        if len(ready_ids) != len(set(ready_ids)):
            raise ValueError("同字段事件发生分叉，不能按时间覆盖")
        if not ready:
            raise ValueError("事件存在缺失依赖、循环、重复或字段冲突")
        for event in sorted(ready, key=lambda item: (item["preference_id"], item["event_id"])):
            state = apply_event(state, event)
            pending.remove(event)
    return sorted(state, key=lambda item: item["id"])
