# TrafficShare

TrafficShare 是一个面向已获授权 Windows 设备的安全流量共享程序。Consumer（B）的 IPv4 流量通过 WireGuard 直接发送给 Provider（A），再由 A 的 Windows 转发与 NAT 出口联网。控制服务器只负责账号、设备、授权、会话、心跳和额度，不承载用户的 Internet 数据。

Windows x64 用户可直接下载仓库中的 [`release/TrafficShare-Windows-x64.zip`](release/TrafficShare-Windows-x64.zip)。解压后先阅读包内 `README.md`，无需安装 Go。

> 只能用于你有权管理的设备和网络。本项目不共享校园网账号、密码、Cookie，不代替 Portal 登录，不伪造 MAC，也不绕过第三方认证、计费或访问控制。

## 最简单的双机使用

前提：A、B 均已安装 WireGuard for Windows，并位于能够互相访问的同一校园网。

### A：本机同时作为控制服务器和 Provider

1. 解压发布包。
2. 双击 `TrafficShare-Host.exe`，接受 Windows UAC。
3. TrafficShare 会打开自己的桌面窗口，不再调用外部浏览器；关闭窗口即退出程序和后台监控。
4. 在“设置”确认角色为 Provider；注册或登录，填写设备名并注册设备。
5. 在“提供流量”先点“预览改动”，确认后点“应用初始化”。
6. 输入 B 使用的用户名、额度和有效期，创建私有授权。
7. 使用期间保持 TrafficShare 窗口运行。

### B：Consumer

1. 解压同一个发布包。
2. 双击 `TrafficShare-Client.exe`，接受 Windows UAC。
3. 在 TrafficShare 桌面窗口中继续设置；关闭窗口即退出程序。
4. 在“设置”将控制服务器填为 `http://A的校园网IPv4:8787`，保存并测试连接。
5. 用 A 授权的 B 用户名登录，填写设备名并注册设备。
6. 在“可用流量”先点“预览改动”，再点“连接”。
7. 结束时在“当前会话”点“安全断开”。程序会精确恢复路由、防火墙和隧道资源。

如果 Windows 防火墙阻止 B 访问 A 的 8787/TCP，需要在 A 上为可信校园网范围放行该端口。不要把本机控制服务器直接暴露到公网。

创建共享前，B 必须已经把控制服务器设置为 A 的地址，并在该服务器完成账号注册。A 输入的是 B 的 TrafficShare 用户名，不是 Windows 账户名或计算机名；否则界面会提示“没有找到接收方账号”。

## 发布包中的程序

- `TrafficShare-Host.exe`：本机控制服务器 + Provider，一键启动，当前双机测试使用它。
- `TrafficShare-Provider.exe`：只运行 Provider，供以后连接云端控制服务器。
- `TrafficShare-Client.exe`：Consumer 客户端。
- `trafficshare-server.exe`：独立控制服务器，适合以后部署到 Windows 云主机。
- `TrafficShare.exe`：保留的高级命令行入口；无参数启动时等同 Host。

配置和运行状态保存在 `%ProgramData%\TrafficShare`。Provider 与 Consumer 使用独立的配置、密钥、日志和恢复目录。

发布包中的说明文件固定使用 ASCII 文件名 `README.md` 和 `SECURITY.md`，避免旧版 Windows PowerShell 或部分解压软件错误转换中文 ZIP 文件名。

## 已实现能力

- 基于 Microsoft Edge WebView2 的独立桌面窗口；本地 UI 只监听 `127.0.0.1`，无需外部浏览器、Electron 或 Node。
- PowerShell、WireGuard 等后台命令均使用隐藏窗口启动，不再反复弹出空白控制台。
- 首次设置、账号注册/登录、设备注册、Provider 初始化、私有流量授权、连接/断开、状态和日志均可在 UI 完成。
- 所有网络修改必须先 dry-run 预览；真实应用需要二次确认。
- 官方 WireGuard for Windows 隧道服务；Provider IPv4 forwarding、NetNat 和按当前网络配置文件创建的 UDP 防火墙规则。
- Consumer Provider `/32` 例外路由，避免全隧道路由递归；IPv4-only 会话期间阻止 IPv6 旁路。
- 原网络状态原子持久化，崩溃后可 repair，重复清理保持幂等。
- bcrypt 密码、随机时效 Bearer Token、服务端授权检查、localhost UI CSRF 与 CSP。
- 多用户、多 Provider、多 Consumer；同一 Provider 的并发 Consumer 会自动获得不同的隧道地址。
- Provider 依据 WireGuard peer counter 上报用量；额度耗尽、授权过期、设备离线时服务端撤销会话。
- Consumer 预览是只读操作，不会短暂创建真实会话或改变 Provider peer。

## 云端控制服务器

数据面仍为 B→A；将控制服务器搬到云端不会让 Internet 流量绕云。

1. 在云主机复制 `trafficshare-server.exe` 和 `server-cloud.example.json`。
2. 配置 DNS、可信 TLS 证书/私钥、数据库和日志路径。
3. 启动：

```powershell
.\trafficshare-server.exe -config .\server-cloud.example.json
```

4. A 改为运行 `TrafficShare-Provider.exe`，A/B 都在 UI 中填写 `https://你的域名:8787`。

公网环境必须使用 HTTPS、云防火墙最小放行、定期备份 SQLite。当前服务器适合单实例部署；如果未来需要多副本横向扩展，应把 SQLite 替换为共享数据库，并增加反向代理、集中日志与密钥轮换。

## 构建与验证

运行环境需要 Windows 10/11 x64、WireGuard for Windows 和 Microsoft Edge WebView2 Runtime。Windows 11 及多数仍受支持的 Windows 10 环境已经包含 WebView2；如果系统缺失，程序会给出明确错误。

源码构建需要 Go 1.26 或更新版本，以及 MinGW-w64 C/C++ 工具链：

```powershell
.\scripts\build.ps1
```

脚本依次执行格式化、`go vet`、全量测试，构建三个 GUI 程序、服务器和高级 CLI，并生成：

```text
dist\TrafficShare-Windows-x64.zip
```

高级诊断仍可使用：

```powershell
.\TrafficShare.exe agent doctor
.\TrafficShare.exe agent status --config "$env:ProgramData\TrafficShare\consumer.json"
.\TrafficShare.exe agent repair --config "$env:ProgramData\TrafficShare\consumer.json"
```

## 架构边界

```text
控制面：A / B ──HTTPS──> TrafficShare Server（账号、授权、会话、额度）

数据面：B 应用 → B WireGuard → 校园网直连 → A WireGuard
                                  → A IP Forwarding / NetNat → Internet
```

当前版本聚焦 Windows IPv4 和同一可达 LAN，不实现 NAT 穿透、IPv6 隧道或绕过 AP/client isolation。完整安全边界见 `SECURITY.md`。
