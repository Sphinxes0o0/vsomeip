# vSomeIP Security 模块与 Routing Manager 深度分析

本文档详细分析了 vSomeIP 的安全访问控制模块（Security Module）的代码实现、设计架构、运行流程，以及核心组件 `routingmanagerd` 在安全体系中的关键作用。

## 1. Security 模块代码实现详细分析

vSomeIP 的安全模块主要位于 `implementation/security` 目录下，核心逻辑由三个类组成：`security`（门面/接口层）、`policy_manager_impl`（核心逻辑层）和 `policy`（数据结构层）。

### 1.1. `security` 类 (Facade 层)
*   **文件**: `implementation/security/include/security.hpp`, `src/security.cpp`
*   **职责**:
    *   作为安全模块的统一对外接口。
    *   支持**动态加载**外部安全库（External Security Library）。
    *   如果未加载外部库，则默认使用内置的 `policy_manager_impl`。
*   **关键实现**:
    *   **函数对象封装**: 使用 `std::function` 封装了所有安全检查接口（如 `is_client_allowed_to_offer`, `is_client_allowed_to_request`）。
    *   **动态加载机制 (`load()` 方法)**:
        *   尝试加载动态库（宏 `VSOMEIP_SEC_LIBRARY` 定义，通常为 `vsomeip3-sec`）。
        *   使用 `dlsym` (Linux) 或 `GetProcAddress` (Windows) 查找符号。
        *   如果加载成功，将内部的 `std::function` 指向外部库的函数；否则保持指向默认实现。

### 1.2. `policy_manager_impl` 类 (核心逻辑层)
*   **文件**: `implementation/security/include/policy_manager_impl.hpp`, `src/policy_manager_impl.cpp`
*   **职责**:
    *   解析和存储安全策略（Policies）。
    *   执行具体的权限检查逻辑。
    *   维护权限检查的缓存（Cache）以提升性能。
    *   处理审计模式（Audit Mode）与强制模式（Enforcement Mode）。
*   **关键成员变量**:
    *   `any_client_policies_`: 存储所有加载的策略。
    *   `is_client_allowed_cache_`: 缓存已通过检查的 `(UID, GID) -> (Service, Instance, Method)` 映射。
    *   `check_credentials_`: `true` 为强制模式（拒绝非法请求），`false` 为审计模式（允许但记录日志）。
*   **核心方法**:
    *   `is_client_allowed(...)`: 
        1.  检查全局开关。
        2.  获取客户端 UID/GID。
        3.  **查缓存**：命中则直接返回 `true`。
        4.  **遍历策略**：匹配 UID/GID 和 Service/Instance/Method。
        5.  **决策**：命中则写入缓存并放行；未命中则根据审计模式决定是拒绝还是仅记录日志。

### 1.3. `policy` 类 (数据结构层)
*   **文件**: `implementation/security/include/policy.hpp`, `src/policy.cpp`
*   **职责**:
    *   表示一条具体的安全策略。
    *   利用 `Boost.ICL` (Interval Container Library) 高效存储 ID 范围。
*   **数据结构**:
    *   `credentials_`: `boost::icl::interval_map`，存储 UID/GID 范围。
    *   `requests_`: 三层嵌套映射 (Service -> Instance -> Method)，支持范围定义。
    *   `offers_`: 两层映射 (Service -> Instance)。

---

## 2. Security 设计架构与原理

### 2.1. 架构图解

```mermaid
[Application]
      |
      v
[Routing / Messaging Layer]
      | (调用 check)
      v
+---------------------------------------------------------------+
| Security Module (Facade)                                      |
| (implementation/security/src/security.cpp)                    |
|                                                               |
|  +----------------+       (Load Success)      +-------------+ |
|  | External Lib   | <-----------------------  | Dynamic     | |
|  | (Optional)     |                           | Loader      | |
|  +----------------+                           +-------------+ |
|          |                                           |        |
|          v (Override)                                v (Fail) |
|  +---------------------------------------------------------+  |
|  | Default Implementation (Internal)                       |  |
|  | -> calls policy_manager_impl                            |  |
+--+---------------------------------------------------------+--+
      |
      v
+---------------------------------------------------------------+
| Policy Manager Impl                                           |
| (implementation/security/src/policy_manager_impl.cpp)         |
|                                                               |
|  +-----------+    +-------------+    +---------------------+  |
|  | Cache     |    | Config      |    | Policy List         |  |
|  | (UID/GID) |    | (Audit/Enf) |    | (vector<policy>)    |  |
|  +-----------+    +-------------+    +----------+----------+  |
```

### 2.2. 核心设计原则
1.  **配置驱动**: 策略由 JSON 定义，无需重新编译。
2.  **白名单机制**: 默认拒绝（强制模式下），必须显式允许。
3.  **范围匹配**: 使用区间算法优化内存和匹配速度。
4.  **可插拔架构**: 支持动态加载外部库，适应 OEM 定制需求。
5.  **审计与强制分离**: 提供 `check_credentials` 开关，便于平滑上线。

---

## 3. 运行流程

### 3.1. 客户端请求校验 (Request/Subscribe)
1.  **发起**: Client 调用 `request_service`。
2.  **拦截**: 路由层调用 `security::is_client_allowed_to_request`。
3.  **身份获取**: 获取发送者的 UID/GID。
4.  **匹配**: 查缓存 -> 遍历策略。
5.  **决策**: 
    *   **Match**: 更新缓存，返回 `true`。
    *   **No Match**: 审计模式打印日志并放行；强制模式打印日志并拒绝。

### 3.2. 服务端发布校验 (Offer)
1.  **发起**: Server 调用 `offer_service`。
2.  **拦截**: 路由层调用 `security::is_client_allowed_to_offer`。
3.  **流程**: 检查 `policy` 中的 `offers_` 集合。

---

## 4. 生效机制与部署

vSomeIP Security 是**深度集成在核心库（libvsomeip3）中**的，采用**分布式执行，中央集中管理**的模式。

### 4.1. 生效机制
*   **Client 端（本地拦截）**: 
    *   Client 进程加载本地配置，在发送请求前进行自检。
    *   作用：快速失败，减少网络垃圾流量。
*   **Routing Manager 端（中央执法）**: 
    *   所有经过 `routingmanagerd` 的消息都会被再次校验。
    *   作用：**关键防线**。即使 Client 被篡改（绕过本地检查），Routing Manager 也会根据独立配置拦截非法请求。
*   **Server 端（自我审查）**: 
    *   Server 进程在发布服务前检查自身权限。
    *   作用：防止恶意程序伪造核心服务。

### 4.2. 部署要求
*   **不需要运行额外插件**: Security 逻辑包含在标准库中。
*   **配置必须**: Client、Server 和 Routing Manager 都需要加载包含 `security` 策略的 JSON 配置。

---

## 5. Routing Manager (routingmanagerd) 深度解析

`routingmanagerd` 是 vSomeIP 架构中的**交通枢纽**和**中央安保中心**。

### 5.1. 角色与作用
1.  **消息路由**: 负责本地应用间（UDS）和跨机（TCP/UDP）的消息转发。
2.  **服务发现 (SD)**: 执行 SOME/IP-SD 协议，收集本地 Offer 并广播，监听远程 Offer。
3.  **中央安全执法**: 它是安全策略的最终执行点，拥有独立的进程空间和权限。

### 5.2. 架构位置
*   **独立守护进程**: 运行在独立的进程空间。
*   **连接方式**: 本地应用通过 UDS 连接到它。
*   **隔离性**: 即使 Client 进程被攻破，攻击者也无法直接控制 Routing Manager。

### 5.3. 设计与实现细节
基于 `implementation/routing/src/routing_manager_impl.cpp`：

*   **启动**: 加载 SD 插件和 E2E 插件，初始化网络监听。
*   **消息流水线 (`on_message`)**:
    1.  **接收**: 解析 SOME/IP 消息头。
    2.  **防伪造检查**: 验证消息头中的 `Client ID` 是否与 Socket 绑定的 ID 一致。
        ```cpp
        if (its_message->get_client() != _bound_client) { ... return false; }
        ```
    3.  **权限验证**: 调用 Security 模块检查访问权限。
        ```cpp
        if (VSOMEIP_SEC_OK != configuration_->get_security()->is_client_allowed_to_access_member(...)) { ... return false; }
        ```
    4.  **转发**: 检查通过后，根据路由表转发消息。

### 5.4. 总结
Routing Manager 的安全检查是系统的**底线**。它不信任客户端的自我检查，而是依据自己独立的配置进行强制执法，确保了即使单点应用沦陷，也无法危害整个系统的通信安全。
