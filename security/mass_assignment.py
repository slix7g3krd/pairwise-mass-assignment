"""Mass-assignment (批量赋值) protection for the user-profile API.

修复点（对应任务清单）:

1. DTO 白名单:        只有 ``_ALLOWED_SCALAR_FIELDS`` / ``_ALLOWED_NESTED_FIELDS``
                      里的字段可以落到模型，其余一律不写入。
2. 敏感字段显式拒绝:  ``is_admin`` / ``role`` / ``tenant`` / ``password`` 等权限或
                      凭据字段永不入参，严格路径直接判非法。
3. 嵌套字段递归过滤:  关联对象（如 ``profile``）按同一套规则递归处理，子表权限
                      字段不会被级联保存。
4. 下划线字段限制:    ``_internal`` 这类绕过 DTO 的私有字段一律拒绝/剥离。
5. PATCH 白名单:      ``apply_patch`` 只合并白名单内、且实际传入的字段。
6. 数组字段拒绝:      ``role[]`` 这类 PHP/Rails 风格的批量覆盖键直接判非法。
7. 大小写归一:        字段名统一小写后再判定，``IsAdmin`` 等同 ``is_admin``。
8. 未知字段报错:      严格绑定路径（``validate_fields`` / ``bind_for_create``）对
                      未声明字段返回 False / 抛异常，而不是静默忽略。
9. 创建与更新分离:    ``bind_for_create``（严格校验 + 全量过滤）与
                      ``bind_for_update``（PATCH 白名单合并）是两个独立绑定器。
10. 关联保存限制:     嵌套关联递归脱敏，关联内的敏感键被剥掉，空关联保留为 {}。
11. 响应脱敏:         ``filter_payload`` 同时用于出站响应，敏感字段不会被回显。
"""

from __future__ import annotations

from typing import Any, Mapping

# --- 1. DTO 白名单 ---------------------------------------------------------

# 允许批量赋值的标量字段（创建/更新共用的用户资料 DTO）。
_ALLOWED_SCALAR_FIELDS: frozenset[str] = frozenset({'name', 'email'})

# 允许出现的嵌套关联字段；其值必须是映射，内部走同一套递归规则。
_ALLOWED_NESTED_FIELDS: frozenset[str] = frozenset({'profile'})

# --- 2. 敏感字段（权限/租户/凭据，永不允许客户端写入，也不允许响应回显）-------

_SENSITIVE_FIELDS: frozenset[str] = frozenset({
    'is_admin',       # 提权
    'role',           # 越权改角色
    'tenant',         # 越权切换租户
    'password',       # 凭据
    'password_hash',
    'secret',
    'token',
    'api_key',
})


class MassAssignmentError(ValueError):
    """严格绑定路径上出现非法字段时抛出。

    错误信息只带字段名，绝不回显字段值或整个请求体，避免错误响应泄露
    被写入的敏感内容（修复点 11）。
    """

    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        self.reason = reason
        super().__init__(f"field '{field}' rejected: {reason}")


# --- 7. 大小写归一 / 4. 下划线 / 6. 数组键 的基础判定 -----------------------

def _normalize(field: Any) -> str:
    """归一化字段名：转字符串、统一小写并去掉下划线。

    同时消除 ``IsAdmin``（大小写变体）与 ``isadmin``/``is_admin``
    （下划线变体）两类绕过；下划线的*私有语义*另由 :func:`_is_internal`
    按原始字段名判定，不受归一化影响。
    """
    return str(field).lower().replace('_', '')


# 归一化后的敏感字段索引，保证任意大小写/下划线变体都能命中。
_SENSITIVE_FIELDS_NORMALIZED: frozenset[str] = frozenset(
    _normalize(name) for name in _SENSITIVE_FIELDS
)


def is_sensitive_field(field: Any) -> bool:
    """判断字段是否为敏感字段（大小写、下划线变体均视为同一字段）。"""
    return _normalize(field) in _SENSITIVE_FIELDS_NORMALIZED


def _is_array_style(field: Any) -> bool:
    """数组形式的字段名（如 ``role[]``、``a[0]``）——批量覆盖攻击面，拒绝。"""
    text = str(field)
    return '[' in text or ']' in text


def _is_internal(field: Any) -> bool:
    """下划线开头的私有字段（如 ``_internal``）——绕过 DTO 的入口，限制。"""
    return str(field).startswith('_')


def allowed_fields() -> set[str]:
    """对外暴露的 DTO 标量白名单。"""
    return set(_ALLOWED_SCALAR_FIELDS)


def _is_allowed_scalar(field: Any) -> bool:
    return _normalize(field) in _ALLOWED_SCALAR_FIELDS


def _is_allowed_nested(field: Any) -> bool:
    return _normalize(field) in _ALLOWED_NESTED_FIELDS


# --- 8. 严格校验：未知/非法字段显式拒绝 ------------------------------------

def validate_fields(payload: Any) -> bool:
    """严格校验整个 payload 是否只包含白名单字段。

    任一非法键（敏感字段、下划线私有字段、数组风格键、未声明字段）都会让
    整体校验失败；嵌套关联递归校验。返回布尔值，不修改入参。
    """
    if not isinstance(payload, Mapping):
        return False

    for key, value in payload.items():
        text = str(key)

        if _is_array_style(text):
            return False
        if _is_internal(text):
            return False
        if is_sensitive_field(text):
            return False

        if _is_allowed_nested(text):
            # 3/10. 关联对象递归校验；非映射值直接判非法，防止用标量覆盖关联。
            if not isinstance(value, Mapping) or not validate_fields(value):
                return False
        elif not _is_allowed_scalar(text):
            # 未知字段：拒绝，而不是静默忽略。
            return False

    return True


# --- 3/4/11. 递归脱敏：输入绑定与出站响应共用的清洗器 -----------------------

def filter_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """按白名单剥离 payload 中的一切非法字段，返回新的安全字典。

    - 敏感字段、下划线私有字段、数组风格键、未声明字段：直接丢弃；
    - 嵌套关联：递归过滤（关联里的敏感键被剥掉，空关联保留为 ``{}``）；
    - 不修改入参；该函数同时用于请求清洗和响应脱敏。
    """
    if not isinstance(payload, Mapping):
        raise TypeError('payload must be a mapping')

    safe: dict[str, Any] = {}

    for key, value in payload.items():
        text = str(key)

        # 6. 数组键 / 4. 下划线私有字段 / 2. 敏感字段 / 8. 未知字段：剥离。
        if _is_array_style(text):
            continue
        if _is_internal(text):
            continue
        if is_sensitive_field(text):
            continue

        if _is_allowed_nested(text):
            if isinstance(value, Mapping):
                # 3/10. 递归过滤子表，权限字段不会随级联保存落库。
                safe[key] = filter_payload(value)
            # 非映射的关联值不写入（保持白名单关联的结构完整性）。
            continue

        if _is_allowed_scalar(text):
            safe[key] = value
        # 其余一律不写入。

    return safe


# --- 5/9. PATCH 白名单合并（更新绑定器） -----------------------------------

def apply_patch(record: Mapping[str, Any],
                payload: Mapping[str, Any]) -> dict[str, Any]:
    """把已清洗的白名单字段合并进现有记录（PATCH 语义）。

    先经 :func:`filter_payload` 全量脱敏，再只合并实际传入的白名单字段；
    嵌套关联做递归合并，关联内部的敏感键在合并前已被剥离。
    返回新字典，不修改 ``record``。
    """
    if not isinstance(record, Mapping):
        raise TypeError('record must be a mapping')

    safe_payload = filter_payload(payload)
    patched = dict(record)

    for key, value in safe_payload.items():
        if _is_allowed_nested(key) and isinstance(value, Mapping):
            existing = patched.get(key)
            if isinstance(existing, Mapping):
                # 关联级联：合并基底先脱敏，杜绝记录里既有的子表权限字段
                # 随级联保存被原样重写；传入值在进入本函数前已递归过滤。
                base = filter_payload(existing)
                patched[key] = apply_patch(base, value)
            else:
                patched[key] = dict(value)
        else:
            patched[key] = value

    return patched


# --- 9. 创建 / 更新绑定器分离 ----------------------------------------------

def bind_for_create(payload: Mapping[str, Any]) -> dict[str, Any]:
    """创建路径的严格绑定器：先拒绝一切非法字段，再做白名单过滤。

    与更新路径不同，创建时对未知字段零容忍（抛 :class:`MassAssignmentError`），
    错误信息只含字段名，不回显值或完整请求体。
    """
    if not validate_fields(payload):
        for key in payload:
            text = str(key)
            if _is_array_style(text):
                raise MassAssignmentError(text, 'array-style field names are forbidden')
            if _is_internal(text):
                raise MassAssignmentError(text, 'underscore-prefixed fields are forbidden')
            if is_sensitive_field(text):
                raise MassAssignmentError(text, 'sensitive field is not assignable')
            if not (_is_allowed_scalar(text) or _is_allowed_nested(text)):
                raise MassAssignmentError(text, 'unknown field is not in the DTO whitelist')
        raise MassAssignmentError('<payload>', 'invalid payload structure')

    return filter_payload(payload)


def bind_for_update(record: Mapping[str, Any],
                    payload: Mapping[str, Any]) -> dict[str, Any]:
    """更新路径的绑定器：PATCH 白名单合并，与创建绑定器完全分离。"""
    return apply_patch(record, payload)
