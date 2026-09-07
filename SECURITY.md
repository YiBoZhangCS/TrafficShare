# TrafficShare 安全说明

## 使用边界

TrafficShare 仅用于用户拥有或明确获准管理的 Windows 设备和网络。它不会获取、复制或转移第三方网络凭据，也不能用于规避校园网或运营商的认证、计费、访问策略和设备隔离。

## 已有防护

- 数据面采用官方 WireGuard for Windows；控制服务器不代理用户 Internet 流量。
- 密码使用 bcrypt 哈希，登录令牌由加密随机数生成并带有效期。
- 分享是指定接收用户的私有授权，设备、会话、流量报告均做服务端归属检查。
- 流量只接受对应 Provider 上报，并根据 WireGuard peer counter 累计。
- 所有系统网络修改先预览、后应用；资源都有 `TrafficShare-` 标签和本地恢复快照。
- Consumer 预先固定 Provider 端点路由，断开和异常恢复会恢复原路由并清理专属规则。
- 本地 UI 只绑定 `127.0.0.1`，检查 Host，写操作要求随机 CSRF Token，并发送 CSP、禁止嵌入和 MIME 嗅探等安全响应头。
- Provider 防火墙规则按当前 Windows 网络配置文件创建，不再假设校园 WLAN 必然是 Private。
- 云端入口可直接配置 TLS 证书和私钥。

## 部署要求

- 只从可信来源安装 WireGuard 和 TrafficShare。
- 双击 GUI 程序时核对 Windows UAC 中的文件位置。当前构建未做商业代码签名，Windows 可能显示未知发布者。
- 本地测试的明文 HTTP 只能用于可信、可控的 LAN。公网控制服务器必须使用 HTTPS。
- 云端应启用操作系统和云防火墙，仅开放必要端口，保护 TLS 私钥并定期备份数据库。
- `%ProgramData%\TrafficShare` 包含设备私钥、令牌、数据库和恢复状态。不要共享此目录；应限制本机普通用户读取权限。
- Provider 机器是 Consumer 流量的出口，使用者应理解组织政策、日志、配额和法律责任。

## 当前限制

- Agent 配置中的短期登录令牌目前保存在本机配置文件中，依赖 Windows 文件 ACL；后续可迁移到 DPAPI/凭据管理器。
- 独立控制服务器当前使用 SQLite，适合一个服务实例和中小规模设备；多副本部署需要共享数据库。
- 尚未实现 NAT 穿透、IPv6 数据面和 Windows Service。GUI/本地页面进程需要保持运行，才能持续心跳、计量与自动撤销 peer。
- 程序无法突破校园网 AP/client isolation；A 与 B 必须能够直接互访 UDP 51820。

## 发现问题

不要在公开问题中附上私钥、密码、Bearer Token、真实校园网地址或完整日志。报告时请提供脱敏后的复现步骤、版本、Windows 版本和相关错误码。
