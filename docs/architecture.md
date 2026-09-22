# 实现与运行边界

`worker/index.ts` 负责 HTTP 契约；`convert.ts` 组织配置、解析、过滤、分组、规则和输出；`nodes.ts` / `export.ts` 是协议转换层；`template.ts` 是异步解释执行的声明式模板；`config.ts` 统一 INI/YAML/TOML。`state.ts` 保存配置正文及版本，`resources.ts` 管理所有资源读取。

## 数据与更新

使用一个名为 `global` 的 SQLite Durable Object，保存配置正文、配置版本、总缓存版本、规则缓存版本及可选 Gist ID。更新在事务中提交，校验失败不覆盖旧值；请求取得配置快照后只修改请求本地对象，彼此不共享可变转换状态。

`/updateconf` 的正文直接存为运行配置，不写 Assets。部署资源和配置正文独立：重新部署不会覆盖已存运行配置，`/readconf` 也不会主动放弃已存配置。要恢复默认，将本地 `base/pref.ini` 通过 `/updateconf` 再次提交。

Cache API 缓存远程源数据，键使用 SHA-256 摘要，包含 URL、资源类型、配置版本和相应缓存版本。每次请求先从 Durable Object 读取版本；刷新之后开始的请求不命中旧版本。已经开始的请求允许完成旧快照，不承诺中断执行中的请求。边缘缓存丢失只影响性能，不影响正确性。

Assets 设置 `run_worker_first=true`，所有外部请求由路由表处理；没有默认回落到 Assets。`/render` 限制在 template_path；本地资源不接受绝对路径、`..`、反斜杠或协议路径。所有 Secrets 留在环境绑定，不传入模板上下文。

## 默认预算

| 项目 | 上限 |
|---|---|
| 订阅来源 | 20 |
| 合并节点 | 2,000 |
| 单个资源 | 2 MiB，可通过旧配置降低 |
| 单请求累计读取 | 8 MiB |
| 资源读取/重定向次数 | 40 |
| 单次远程读取超时 | 15 秒，包含读取正文 |
| 重定向 | 最多 5 次 |
| 配置更新正文 | 512 KiB |
| 外部规则集配置条目 | 32 |
| 规则条目 | 20,000，可降低 |
| 模板嵌套 / include 或 import 深度 | 32 / 8 |
| 模板单次循环 | 2,000 |
| 模板输出 | 2 MiB |

当前按顺序读取资源，同一请求中同路径复用 Promise，因此不会产生无界网络并发。应用预算用于提前拒绝明显过大输入，**不保证预算以内的所有输入都能在免费套餐 CPU 限制内完成**。平台硬限制可能直接产生 1102，Worker 无法捕获已被终止的执行。

`docs/benchmark.json` 为本机 Node.js 转换路径测量，不是 Cloudflare 生产 CPU 计费结果。较大规则集合应优先 `expand=false` 使用客户端 rule providers；规模较大时需更低输入上限或付费套餐。

## 运维与回滚

执行 `npm run deploy:check` 只生成本地包并校验绑定，不上传。实际部署由使用者执行 `npm run deploy`。首个 migration 创建 SQLite Durable Object，无需手动填写 namespace ID。

回滚 Worker 代码时使用 Cloudflare Dashboard 的版本回滚；配置使用之前保存的正文再次调用 `/updateconf`。Durable Object 数据不会随 Worker 版本回滚，切勿通过删除 namespace 来回滚配置。

观察日志仅记录错误事件及状态码，不记录订阅 URL、配置正文或令牌。使用 Dashboard 观察 CPU 时间、错误率、1102 及 Durable Object 配额；`npm exec wrangler tail` 可实时检查日志。
