# REST API 概览

默认 base URL：`http://A-LAN-IP:8787`。除 `/healthz`、`/v1/register`、`/v1/login` 外均要求 `Authorization: Bearer <token>`。

| Method | Path | 权限/作用 |
|---|---|---|
| POST | `/v1/register` | 注册，密码只以 bcrypt hash 保存 |
| POST | `/v1/login` | 返回随机、时效 token |
| POST | `/v1/devices` | 当前用户注册/更新自己的设备 |
| POST | `/v1/heartbeat` | 更新自己的设备与 session 心跳，返回强制断开列表 |
| POST | `/v1/shares` | 当前用户创建一对一 private share |
| GET | `/v1/shares` | 仅返回授权给当前用户且有效的 share |
| DELETE | `/v1/shares/{id}` | 仅 owner 停止 share |
| POST | `/v1/sessions` | receiver 为自己的设备请求 session |
| POST | `/v1/sessions/preview` | 只读预览 session 配置，不创建会话或修改 Provider |
| GET | `/v1/sessions/{id}/config` | 仅 owner/receiver 获取 public tunnel 信息 |
| GET | `/v1/provider/sessions?device_id=...` | 仅对应 Provider 获取待配置 peer |
| POST | `/v1/sessions/{id}/traffic` | 仅 owner 的对应 Provider device 上报可信计数 |
| POST | `/v1/sessions/{id}/disconnect` | session 双方断开 |
| POST | `/v1/sessions/{id}/revoke` | 仅 owner 撤销 |

所有 private key 均在 Agent 本机生成并保存；API schema 不存在 private key 字段。
