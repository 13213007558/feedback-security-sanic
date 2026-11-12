# 短时下载票据（Sanic 集成）

票据绑定 **用户 + 文件版本快照**，只使用进程内票据存储与临时文件。
一次授权允许同一客户端断开后用 `Range` 恢复，但票据一旦绑定客户端，
其他身份、同用户的其他客户端、以及并发的第二个传输都会被拒绝。

## 票据状态机

| 状态 | 含义 | 进入条件 |
| --- | --- | --- |
| `issued` | 已签发，尚未领取 | `POST /files/<file_id>/tickets` |
| `claimed` | 已绑定 `(user, client_id)`，未开始传输 | 首次 `GET .../download` |
| `streaming` | 正在占用传输槽位发送字节 | 校验通过后原子占用槽位 |
| `interrupted` | 中途断开或未发完，可由同一客户端 `Range` 恢复 | 写入失败 / 提前结束 |
| `consumed` | 终态，快照全部字节均已授权发出 | 覆盖区间并集等于文件长度 |
| `expired` | 终态，超过 TTL | 任意访问时惰性过期 |

恢复只会在 `interrupted` 上发生，且仍受同一用户、同一 `X-Client-Id`、
同一版本快照、同一文件长度约束；非法 Range 返回 `416`，不会推进字节账，
也不会扩大票据权限。

## HTTP 接口

- `POST /admin/files/<file_id>/publish`
  body: `{"content_base64": "..."}`，发布一个不可变版本（返回 version、size、sha256）。
- `POST /files/<file_id>/tickets`，头 `X-User`，按当前最新版本签发票据。
- `GET  /tickets/<ticket_id>`，头 `X-User`，查看票据状态与已发字节。
- `GET  /tickets/<ticket_id>/download`，头 `X-User`、`X-Client-Id`，
  可选 `Range: bytes=start-end`；无 Range 为 `200`，有 Range 为 `206`。

错误码：`401` 缺身份头、`403` 用户/客户端不匹配、`404` 票据不存在、
`409` 客户端冲突或并发传输、`410` 票据已消费/过期/版本失效、`416` Range 越界。

## 版本隔离

发布新版本写入新的临时文件与新快照；票据保存签发时的 `version/size/sha256`。
每次传输前重新对临时文件计算 sha256，发现漂移即 `410` 失败关闭，
旧票据永远读取旧快照，不会把新内容拼进旧下载。

## 字节核对

服务端按“已授权外发”记账：每个分块在写入 socket **之前**记入
`delivered`（一个字节偏移集合），因此触发断开的最后一块也会入账。
票据消费条件是该集合恰好覆盖 `[0, size)`；重复区间不会重复计数。

## 运行

```bash
# 可运行服务（需要允许本地端口绑定）
sanic download_demo.server:app --port 8000

# 无端口的完整集成核对：两个客户端交错领取、Range、断开、恢复、版本切换
python -m download_demo.run_integration

# 同样的场景以 pytest 运行
cd download_demo && python -m pytest
```

集成脚本通过内存 ASGI 驱动 Sanic（不绑定端口），用精确的分块边界模拟
客户端中途断开，并逐项核对外发字节、票据终态与权限拒绝。
