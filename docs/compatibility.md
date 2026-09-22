# 兼容矩阵

基准：本仓库原提交 `ecb63a9`。HTTP 路由和关键文本来自源码；协议回归样例包含原 README 的 SS 示例。本版是独立 TypeScript 实现，**不是原 C++ 二进制的逐字节复刻**。配置字段顺序、空白、默认分组和部分错误响应有差异。

## HTTP API

| 接口 | 状态 | 行为 |
|---|---|---|
| `GET /version` | 已实现 | 返回 Workers 实现版本 |
| `GET /sub`、`HEAD /sub` | 已实现 | 订阅转换；HEAD 具有相同校验和响应头，无响应正文 |
| `GET /sub2clashr?sublink=…` | 已实现 | 兼容简易 ClashR 调用 |
| `GET /surge2clash?link=…` | 已实现 | 转换节点并保留源配置中的策略组和规则 |
| `GET /getruleset` | 已实现 | `type=1..6`；`url`、`group` 使用 URL-safe Base64 |
| `GET /getprofile` | 已实现 | 部署资源档案、独立档案令牌、多档案 URL 合并；档案配置优先于查询覆盖 |
| `GET /render` | 已实现，有语法边界 | 受控资源路径；声明式模板解释器，非完整 Jinja2/Inja 实现 |
| `POST /updateconf?type=direct或form` | 已实现 | 两种 type 均接收原始正文，与原实现一致；校验后原子写入 |
| `GET /readconf` | 已实现，存储适配 | 重新校验并加载持久化配置；首次使用部署默认配置，不返回配置内容 |
| `GET /refreshrules` | 已实现，缓存适配 | 递增规则缓存版本并重新读取配置中的规则集；上游失败返回错误 |
| `GET /flushcache` | 已实现，缓存适配 | 递增缓存版本，全局新请求不再使用旧版本；旧缓存等待 TTL 到期 |
| `GET /get`、`GET /getlocal` | 条件实现 | 仅 `api_mode=false` 开启；本地文件改为部署资源 |
| 配置 aliases | 已实现 | 与原版一样返回 302，附带查询参数 |
| `/`、create/list-profile | 未新增 | 原版根路由和档案写入路由为注释代码，不作为兼容 API |

管理接口总是要求管理员令牌；无令牌配置时关闭。`ACCESS_TOKEN` Secret 优先于旧配置的 `api_access_token`。Gist 上传还必须具有管理员权限。默认 API 模式为 true，避免公开读取部署资源；设置 false 会按旧语义开启读取接口。

## 格式和协议

| 格式 | 输入 | 输出与边界 |
|---|---|---|
| Clash / ClashR | 新旧字段名、YAML/JSON | 新旧字段名、完整配置/节点列表、模板、规则、provider |
| sing-box | outbounds | 完整 JSON/节点列表；保持原项目面向的旧配置结构，未升级到所有新版 sing-box schema |
| Surge | INI 节点、策略组、规则、WireGuard 段 | 2 的 SS custom module 语法；3/4/5 按版本过滤；托管配置头 |
| Surfboard | INI | SS、VMess、Trojan、HTTP、SOCKS |
| Quantumult | SERVER 节点、Base64 订阅 | SERVER 配置、Base64 POLICY、节点列表；部分高级 POLICY 输入不恢复 |
| Quantumult X | server_local / 单行节点 | SS/SSR/VMess/VLESS/Trojan/HTTP/SOCKS，策略组，规则；支持 VLESS Reality 字段 |
| Loon | INI | SS/SSR/VMess/VLESS/Trojan/HTTP/SOCKS/Hysteria2/WireGuard |
| Mellow | Endpoint | ss/vmess1/builtin endpoint，EndpointGroup，规则 |
| SS / SSR / VMess / Trojan | URI、普通/Base64 订阅 | 目标专用订阅；`list=true` 输出明文链接 |
| SSD | URI JSON | 多节点订阅；不恢复机场流量/到期扩展字段 |
| SS 软件订阅 / SIP008 | JSON 数组、servers 包装、单节点 | 按原版 `sssub` 返回 JSON 数组，将基础模板合并到每个节点 |
| Mixed | 多协议明文/Base64 链接列表 | 可表示的协议链接集合；不含 Snell/WireGuard/Mieru 链接 |
| Auto | — | 按 User-Agent 选择目标，包括 Clash、Surge、Quantumult、Loon 等 |

统一模型支持 SS、SSR、VMess、VLESS、Trojan、Snell、HTTP(S)、SOCKS5、WireGuard、Hysteria、Hysteria2、TUIC、AnyTLS、Mieru。每个目标只输出该客户端支持的类型，跳过数量通过 `X-Subconverter-Skipped-Nodes` 返回；没有兼容节点返回 400。不能表达的插件或传输组合明确返回 422。

直接 URI 覆盖 SS、SSR、VMess、VLESS、Trojan、Hysteria、Hysteria2、TUIC、AnyTLS、Mieru、SOCKS 和 Telegram HTTP/SOCKS。Snell/WireGuard 通过结构化配置输入。Netch 只转换通用字段。未覆盖完整 V2Ray 客户端 JSON、所有 Netch 专有字段和所有历史 HTTP Base64 变种。

VLESS/Hysteria2 独立输出目标已接通，修复原源码中“存在输出分支但入口 target 校验拒绝”的不一致。IPv6、Unicode 名称、密码、TLS/SNI、WS/gRPC、Reality、插件等设有回归测试，但不代表所有协议参数组合均已对客户端实机验证。

## 参数、配置与模板

- 已实现：多来源、默认/插入 URL、include/exclude、rename、Emoji、append_type、sort、group、udp/tfo/scv/tls13、fdn、list、new_name、filename、interval/strict、append_info、外部 config、groups/ruleset、expand/classic、upload/upload_path。
- 配置：INI/YAML/TOML；重复 INI 项；规则、分组、Emoji 和重命名列表的 `!!import:`；YAML/TOML 对象形式的基础列表字段。
- 流量信息：优先转发第一个上游的 `Subscription-UserInfo`；没有头时可按 userinfo 正则从名称提取；时间解析使用 UTC，不使用原宿主机时区。
- 策略组：select、url-test、fallback、load-balance、relay、smart；名称正则和 `!!GROUPID=` / `!!GROUP=`。Clash 支持 `!!PROVIDER=`、`use`、`extra` 和常用分组属性；provider 定义需来自基础模板。SSID 和更复杂的选择器尚未完整移植，不能据此声称所有分组语法兼容。
- 模板：`global/request/local`、点路径、if/elif/else、for/else、set、include、表达式及常用函数；fetch 共享资源预算；包含循环检测。仓库 `all_base.tpl` 的所有目标分支设有测试。
- 模板函数：default、bool、int/float/string、trim/trim_of、lower/upper、UrlEncode/UrlDecode、find/replace、startsWith/endsWith、exists/existsIn、length/join/at/first/last、range/round、isArray/isString、tojson、getLink、fetch、set/split/append、and/or。其他函数、宏、继承和任意 JS 执行不支持。
- 正则：JavaScript RegExp 加前导 `(?i)`/`(?m)`/`(?s)`；不支持 PCRE 递归、原子组、条件、分支重置和占有量词，报 400。拒绝常见嵌套量词，但不是完整正则复杂度证明。
- 客户端 Clash script：支持 `expand=false` 的远程 provider 分派；不是服务端脚本执行；不能生成的规则组合返回 422。
- 尚未完整移植：`dev_id` 的 Quantumult X 重写脚本处理、全套 Clash YAML 输出样式、自动 DNS/GeoIP 查询、系统代理、Gist `gistconf.ini` 文件状态迁移、源码中所有冷门规则映射与旧客户端特例。

## 已明确排除

按用户选择，不执行自定义 JS 过滤/排序/重命名/Emoji、`script:` 订阅、脚本定时任务；返回 422。不恢复任意主机文件访问、系统代理、CLI 本地生成、进程管理或二进制构建功能。现有部署资源和纯声明式配置仍可使用。

## 验证边界

C++ 基准构建停在缺少 `toml11`（另报告 rapidjson 缺失），因此**未完成原二进制差分验证**。`test/fixtures/legacy-contract.json` 标注样例来源；`scripts/differential.mjs` 可在原二进制可用后对比本地服务，不能将该脚本的存在视为差分已通过。

Workers Vitest 测试在 workerd 运行时执行，覆盖转换、资源、缓存、Durable Object、鉴权和错误行为；Gist/远程请求使用严格的一次性模拟，未创建真实 Gist。部署仅作 dry-run，未发布云端，也未完成真实客户端连通性测试。
