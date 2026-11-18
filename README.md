# pairwise-mass-assignment

用户资料接口开放批量字段更新后，批量赋值就把权限字段一起写进去了：请求体里的 `is_admin` 直接落到模型；`role` 和 `tenant` 能越权修改；嵌套对象里的敏感字段没有被过滤；下划线字段 `_internal` 绕过 DTO；PATCH 只更新传入字段，但没做白名单；数组形式的字段名能批量覆盖；大小写变体 `IsAdmin` 也被接受；未知字段静默忽略而不是拒绝；更新和创建共用同一个绑定器；关联对象级联保存时把子表权限一起改掉；错误响应回显所有被写入字段。security/mass_assignment.py 是核心，tests/test_mass_assignment.py 15个红。要修的是：DTO 白名单；敏感字段显式拒绝；嵌套字段递归过滤；下划线字段限制；PATCH 白名单；数组字段拒绝；大小写归一；未知字段报错；创建与更新分离；关联保存限制；响应脱敏。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：漏洞检测与攻防；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
