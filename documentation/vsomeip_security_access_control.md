# vsomeip 安全访问控制机制分析

本文结合仓库当前源码与示例配置 `config/vsomeip-local-security.json`，系统阐述 vsomeip 内置 security 的原理、数据流、客户端/服务端校验逻辑、外接扩展与审计模式、以及排错要点。内容面向需要理解从“配置”到“运行时决策”完整链路的开发者。

## 1. 架构与开关概览

| 组件 | 作用 | 关键文件 |
|------|------|----------|
| `security` (封装层) | 对外统一接口，默认指向内置策略实现或动态装载外部库 | `implementation/security/include/security.hpp`, `src/security.cpp` |
| `policy_manager_impl` | 解析配置策略、维护区间结构、执行匹配与缓存 | `implementation/security/include/policy_manager_impl.hpp`, `src/policy_manager_impl.cpp` |
| `policy` | 单条策略数据结构与反序列化、区间容器封装 | `implementation/security/include/policy.hpp`, `src/policy.cpp` |
| 配置解析 | 读取 `security` 节点，加载 policies | `implementation/configuration/src/configuration_impl.cpp` |

开关：
- 存在非空 `security` 节点 → 启用内置安全（internal）。
- `security` 节点为空对象 `{}` → 进入外接模式（external），`security.cpp` 尝试动态加载外部库符号。
- `check_credentials`：
  - `true` 强制模式：未命中策略即拒绝。
  - `false` 审计模式：记录日志但放行（用于观察策略影响面）。

## 2. 配置到策略的数据映射

示例策略片段：
```json
{
  "client": "0x1277",
  "credentials": { "uid": "1000", "gid": "1000" },
  "allow": {
    "offers": [ { "service": "0x1234", "instance": "0x5678" } ]
  }
}
```
映射过程（`policy_manager_impl::load_policy`）：
1. `client` → 绑定到策略适用的 vsomeip 应用 ID（注册自 `applications[].id`）。
2. `credentials` → 构造 uid/gid 区间集合（支持单值或范围，底层 `boost::icl::interval_set`）。
3. `allow.offers` / `allow.requests`：
   - offers：按 `(service, instance)` 构建允许集合。
   - requests：多层结构 service → instance → method 区间（method 可选；未配置时依实现分支视为“该实例全部方法”或特殊处理）。
4. `check_credentials` → 记录策略管理器的决策模式标志。

区间容器的使用使多个范围自动合并，降低匹配复杂度与内存开销。

## 3. 客户端请求路径校验

流程（request / subscribe / method访问 共性）：
1. 应用调用 API 发起请求 → 路由层准备 `(client_id, service, instance, method)`。
2. 进入 `security::default_is_client_allowed_to_request` 或 `default_is_client_allowed_to_access_member`。
3. 委托 `policy_manager_impl::is_client_allowed(...)`：
   - 获取本地 UDS 凭据（`uid,gid`）；远程 TCP/UDP 无法获取时可能直接放行（依条件分支）。
   - 形成 `(uid,gid)` 键并查缓存（命中直接返回）。
   - 遍历策略：顺序匹配 client id → 凭据区间 → 资源(service→instance→method)。
   - 命中：写入缓存；未命中：强制模式拒绝 / 审计模式放行并日志。
4. 返回结果，允许时交由路由与网络栈继续处理。

缓存：`is_client_allowed_cache_` 以 `(uid,gid)` 为一级键，内部存储已允许的资源组合，加速重复访问。

## 4. 服务端提供 (offer) 路径校验

流程：
1. 服务端应用调用 offer API → 进入 `security::default_is_client_allowed_to_offer`。
2. 委托 `policy_manager_impl::is_offer_allowed(...)`：与请求路径类似，但资源只到 `(service, instance)`，无 method 层。
3. 同样按 client id → 凭据 → offers 集合匹配；结果缓存。
4. 拒绝时日志说明（service/instance 或凭据不匹配）。

事件发布与订阅：订阅请求本质仍走客户端请求校验；服务端发布事件时依赖之前订阅阶段的成功校验，不再重复凭据判断。

## 5. 外接插件机制

条件：`security` 节点为空 `{}`。
行为：`security::load()` 使用宏：
- `VSOMEIP_SECURITY_POLICY_LOAD(symbol)` 加载动态库导出的函数（例如 `vsomeip_sec_policy_is_client_allowed_to_request` 等）。
- `VSOMEIP_SECURITY_ASSIGN_FUNCTION` 将默认函数指针替换为外部实现。

意义：允许 OEM 或特定安全策略（如集成企业统一认证）替换内置 `policy_manager_impl`。接口语义保持一致，不影响上层应用代码。

## 6. 审计模式与强制模式

| 模式 | 配置 | 未命中策略行为 | 适用场景 |
|------|------|----------------|----------|
| 强制 | `"check_credentials":"true"` | 直接拒绝 | 生产环境启用访问控制 |
| 审计 | `"check_credentials":"false"` | 记录日志但放行 | 上线前观察策略覆盖面 |

审计模式仍进行全部匹配计算，只在最终决策将“不允许”转为“允许并加“audit”提示”，方便迭代收敛策略。

## 7. 示例配置完整通路

配置摘要：
```json
"security": {
  "check_credentials": "true",
  "policies": [
    { "client": "0x1277", "credentials": {"uid":"1000","gid":"1000"}, "allow": { "offers": [ {"service":"0x1234","instance":"0x5678"}, {"service":"0x1235","instance":"0x5678"} ] } },
    { "client": "0x1344", "credentials": {"uid":"1000","gid":"1000"}, "allow": { "requests": [ {"service":"0x1234","instance":"0x5678"} ] } }
  ]
}
```

场景判定：
| 操作 | 进程(client id / uid,gid) | 资源 | 结果 | 原因 |
|------|--------------------------|------|------|------|
| offer (0x1234,0x5678) | 0x1277 / 1000,1000 | 在 offers 列表 | 允许 | 策略1命中 |
| offer (0x1235,0x5678) | 0x1277 / 1000,1000 | 在 offers 列表 | 允许 | 策略1命中 |
| offer (0x1234,0x5678) | 0x1344 / 1000,1000 | 不在其 offers | 拒绝 | 策略2无 offers |
| request (0x1234,0x5678) | 0x1344 / 1000,1000 | 在 requests 列表 | 允许 | 策略2命中 |
| request (0x1234,0x5678) | 0x1277 / 1000,1000 | 无 requests 权限 | 拒绝 | 策略1仅 offers |
| request (0x9999,0x5678) | 0x1344 / 1000,1000 | service 不匹配 | 拒绝 | 资源未命中 |
| 任意操作 | 0x1277 / 1001,1000 | 凭据不符 | 拒绝 | credentials 不匹配 |

方法层：若需限制方法集合，扩展如下：
```json
"requests": [
  { "service":"0x1234", "instance":"0x5678", "methods":["0x0001","0x0002","0x0010-0x001F"] }
]
```
反序列化后方法范围进入区间集合，判定时 method 必须落入允许区间。

## 8. 匹配与缓存细节

核心函数：
- `policy_manager_impl::is_client_allowed(...)`：请求/订阅/方法访问校验。
- `policy_manager_impl::is_offer_allowed(...)`：服务提供校验。

步骤：
1. 组装 `(uid,gid)` 与资源键。
2. 查缓存（允许集）。
3. 遍历策略顺序匹配：client id → credentials → offers/requests 内的区间结构。
4. 写缓存（命中）或日志（拒绝）。
5. 审计模式在最后一步将拒绝转为允许并加“audit”提示。

缓存失效：策略重载或凭据变化时擦除 `(uid,gid)` 相关条目，保证新策略生效。

## 9. 外接模式注意事项

若采用外部库：
- 需提供与默认相同的函数符号集合（`vsomeip_sec_policy_*`）。
- 负责自身策略解析与缓存；框架只持有函数指针。
- 升级/替换不影响应用的调用方式，但需要确保线程安全与性能等价。

## 10. 排错指南

排错顺序建议：
1. 验证应用 `client id` 是否与策略 `client` 一致（启动日志）。
2. 检查进程实际 `uid/gid` (`id -u`, `id -g`) 是否命中策略。
3. 确认是否使用本地 UDS；远程连接无法获取凭据时策略可能不生效。
4. 确认 `service` / `instance` / `method` 数值与策略写法一致（十六进制解析正确）。
5. 查看拒绝日志：定位是“凭据”还是“资源”不匹配。
6. 若处于审计模式，确认日志中是否有“audit”放行提示，避免误以为真正允许。
7. 对方法级控制，确认 methods 列表或范围是否覆盖目标 method。

常见问题与对策：
- “策略写了但不生效”：凭据不匹配或连接不是 UDS。
- “可以请求却不能提供”：策略仅写了 `requests`，需增加 `offers`。
- “新增方法后被拒绝”：忘记更新 methods 范围；缓存仍旧，需触发策略重载或重启应用。
- “外接库加载失败”：确认 `security` 节点为空，库路径与符号命名正确。

## 11. 设计要点与扩展建议

优势：
- 区间容器减少大量连续 ID 列表配置。
- 缓存机制优化热路径性能。
- 外接模式与审计模式提供迭代与集成灵活性。

潜在扩展：
- 增加基于角色的抽象层，将多个 `(client,credentials)` 聚合到逻辑角色。
- 引入动态策略热更新通知，减少全缓存失效范围。
- 支持远程凭据（TLS 证书 DN）映射到内部 uid/gid 虚拟空间。

## 12. 总结

vsomeip 的安全访问控制以“多维匹配”(client id + uid/gid + 资源三元组) 为核心，通过区间结构与缓存提升判定效率，`check_credentials` 控制执行模式，外接插件使策略体系可插拔。示例配置展示了典型“服务端只提供、客户端只请求”的单向授权模型。掌握匹配顺序与日志排错方法，可快速定位授权问题与策略缺口。
