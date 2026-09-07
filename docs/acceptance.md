# 双机验收清单

所有命令均在有权限控制的 A/B Windows PC 上执行。真实修改前必须完成并保存两端 dry-run 输出。

## A（Provider）

```powershell
Get-NetAdapter | Where-Object Name -Like 'TrafficShare-*'
Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -Like '10.66.0.*'
Get-NetIPInterface -AddressFamily IPv4 | Where-Object InterfaceAlias -Like 'TrafficShare-*'
Get-NetNat -Name 'TrafficShare-NAT'
Get-NetFirewallRule -DisplayName 'TrafficShare-*'
& 'C:\Program Files\WireGuard\wg.exe' show TrafficShare-Tunnel
```

确认 A tunnel 地址 `10.66.0.1`、forwarding enabled、NAT prefix `10.66.0.0/24`、UDP 入站仅为 LocalSubnet/Private,Domain。

## B（Consumer）

```powershell
route print -4
Get-NetRoute -AddressFamily IPv4 | Sort-Object DestinationPrefix
ping 10.66.0.1
tracert -4 1.1.1.1
```

确认 A LAN IPv4 的 `/32` route 使用原 interface index 与 gateway；`0.0.0.0/0` 由 WireGuard 接管；IPv6 出站阻断规则存在。

在 B 产生明确的 IPv4 下载流量，前后比较 A 的：

```powershell
& 'C:\Program Files\WireGuard\wg.exe' show TrafficShare-Tunnel transfer
```

对应 B peer counter 必须增加。

## 断开与异常恢复

断开后确认 TrafficShare tunnel、endpoint route、IPv6 block 被移除；原 `0.0.0.0/0`、网关、接口索引和 DNS 未被删除。

异常测试：建立 session，强制停止 Agent，重启后执行 `repair --dry-run`，核对动作后执行 `repair --apply`，再验证直连 Internet 与 DNS。
