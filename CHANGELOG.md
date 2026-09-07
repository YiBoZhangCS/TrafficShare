# Changelog

## 1.0.0 - 2026-09-07

- 新增 Host、Provider、Client 三个一键启动 Windows GUI 程序。
- 重写中文响应式本地管理界面，覆盖设置、账号、设备、授权、连接、状态、诊断和日志。
- 支持本地嵌入式控制服务器，以及带 TLS 证书的独立云端控制服务器。
- 支持多用户、多 Provider 和同一 Provider 的多个并发 Consumer。
- Consumer 预览改为完全只读，不再创建短暂服务器 session。
- 修复 WireGuard 服务启动竞态、IPv6 防火墙地址兼容、异常虚拟网卡诊断和幂等恢复问题。
- Provider 防火墙按当前 Windows 网络配置文件创建，并为 Host 的 LocalSubnet 控制端口提供显式规则。
- 发布包说明文件改用 ASCII 文件名，避免 ZIP 中文文件名乱码。
