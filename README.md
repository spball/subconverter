# subconverter for Cloudflare Workers

将原 C++ subconverter 重写为 TypeScript Workers 服务，支持订阅转换、规则转换、配置档案、声明式模板及配置/缓存管理。运行时不需要原生二进制、Docker 或外部转换后端。

以本仓库 `ecb63a9` 源码行为为兼容基准，尽量保留原 API；不声称完整或逐字节兼容。详细范围见 [兼容矩阵](docs/compatibility.md)，验证缺口见 [原版基准记录](docs/baseline.md)。

## 本地开发

要求 Node.js 22.12+ 和 npm。

```sh
npm ci
npm run dev
```

默认服务地址为 `http://localhost:8787`。不配置令牌也可使用公开转换接口；管理接口保持关闭。需要管理操作时复制 `.dev.vars.example` 为 `.dev.vars`，设置自己的 `ACCESS_TOKEN`。本地 Durable Object 数据保存在 `.wrangler/`，与生产数据隔离。

## 部署到 Cloudflare

```sh
npm ci
npm run check
npx wrangler login
npx wrangler secret put ACCESS_TOKEN
npm run deploy
```

`wrangler.jsonc` 已配置 Worker、Assets 绑定和 SQLite Durable Object migration，首次部署自动创建所需命名空间，不需要填写 KV/D1/R2 ID。本次仓库改写没有执行实际云端发布。

可修改配置中的 Worker 名称；不要随意删除或重命名已有 Durable Object 类及 migration。Gist 上传可选，启用时另执行 `npx wrangler secret put GIST_TOKEN`，填入具有 gist 权限的 GitHub token。

免费套餐优先，但不保证任意规模输入均能在免费 CPU 限制下处理。大量规则建议使用 `expand=false&classic=true`，由客户端读取规则 provider。输入预算、运行状态与回滚方式见 [架构说明](docs/architecture.md)。

## 调用

```text
/sub?target=clash&url=<URL 编码后的订阅或节点链接>
/sub?target=singbox&url=<订阅链接>
/sub?target=mixed&url=<链接1|链接2>
/sub?target=auto&url=<订阅链接>
/sub?target=clash&url=<订阅链接>&config=<外部配置地址>
/sub?target=clash&url=<订阅链接>&expand=false&classic=true
```

`url`、`config` 等参数使用 URL 编码；多个来源先用 `|` 拼接再编码。例：

```text
http://localhost:8787/sub?target=clash&url=ss%3A%2F%2FYWVzLTEyOC1nY206dGVzdA%3D%3D%40example.com%3A443%23Example
```

支持目标：`clash`、`clashr`、`surge`、`surfboard`、`quan`、`quanx`、`loon`、`mellow`、`singbox`、`ss`、`ssr`、`sssub`、`ssd`、`v2ray`、`trojan`、`vless`、`hysteria2`、`mixed`、`auto`。Surge 用 `ver=2/3/4/5`；简单订阅用 `list=true` 获取未 Base64 编码的节点链接。

目标无法表示的协议会按类型跳过，并返回 `X-Subconverter-Skipped-Nodes`；全部被过滤时返回 400。对于不能安全转换的传输或插件组合，明确报错。

其他接口保留 `/version`、`/sub2clashr`、`/surge2clash`、`/getruleset`、`/getprofile`、`/render`、`/readconf`、`/updateconf`、`/refreshrules` 和 `/flushcache`。`/get`、`/getlocal` 仅在 `api_mode=false` 时开启。

## 配置和资源

- `base/pref.ini`：新部署默认配置，使用 API 模式、缓存和简单 Proxy 分组。
- `base/base/`：各客户端基础模板。
- `base/config/`、`base/snippets/`、`base/rules/`：原仓库的声明式配置、片段和规则。
- `base/profiles/`：档案示例，只使用虚构节点；真实使用前替换节点和档案令牌。
- 所有本地路径相对于 `base/`，例如 `base/all_base.tpl` 映射到仓库中的 `base/base/all_base.tpl`。不是服务器文件系统路径。

资源随 Worker 一起部署，默认不能被直接下载。新增档案或模板只需放入对应目录并重新部署。原配置示例保留用于参考，其中系统代理、脚本等设置不适用于 Workers；完整差异见兼容矩阵。

管理接口支持 `?token=...` 或 `Authorization: Bearer ...`。推荐使用请求头；以下 shell 示例从环境变量读取 token：

```sh
curl -X POST 'http://localhost:8787/updateconf?type=direct' \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  --data-binary @base/pref.ini
```

PowerShell 可使用 `curl.exe` 并将 token 表达式改成 `$env:ACCESS_TOKEN`。配置正文支持 INI、YAML 和 TOML；`type=form` 与旧版一样仍接收原始正文，不是名为 config 的表单字段。

`/readconf` 表示重新加载配置，不是返回配置正文。已通过 API 更新的配置持久化在 Durable Object 中，后续部署不会覆盖；要恢复默认，重新提交默认文件。管理员 Secret 优先于配置文件中的 `api_access_token`。

自定义 JavaScript 过滤、排序、重命名、Emoji、`script:` 订阅及脚本任务不执行，返回 422。正则、规则分组、变量/条件/循环/包含等声明式模板仍可使用。

## 验证

```sh
npm run types         # Wrangler 生成绑定及运行时类型
npm run typecheck
npm test              # 在 Workers/workerd 运行时执行
npm run deploy:check  # 仅打包与部署预检，不发布
npm run benchmark    # 本机测量并更新 docs/benchmark.json
```

测试涵盖各类转换、旧 API 文本、HEAD、鉴权、配置失败回滚、持久化恢复、资源路径、缓存失效、并发隔离、模板边界和模拟 Gist 上传。基准 C++ 构建因缺少 toml11 被阻断，尚未完成原二进制差分；没有用新版本自生成预期冒充原版结果。

## 来源与许可

源自 [spball/subconverter](https://github.com/spball/subconverter)，其原项目注明 [asdlokj1qpi23/subconverter](https://github.com/asdlokj1qpi23/subconverter)，并沿用 subconverter 生态的原有资源。保留 [GPL-3.0 许可证](LICENSE) 及资源自身声明。旧 C++ 实现和构建流程可在 Git 历史 `ecb63a9` 查阅。
