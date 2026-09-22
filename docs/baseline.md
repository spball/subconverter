# 原版验证记录

- 基准提交：`ecb63a9`。
- 已检查源码：路由注册、查询参数、协议解析、输出器、规则转换、模板辅助函数、配置加载和 Gist 上传。
- 原版编译尝试：`cmake -S . -B .baseline-build -G Ninja`。
- 编译器 GNU 15.2.0 和 CURL 8.15.0 检测成功，配置阶段因缺少 `toml11Config.cmake` / `toml11-config.cmake` 失败，另报告 rapidjson 不可用。
- 未生成原版可执行文件，未执行二进制差分。测试里的源码契约和手写预期不伪称来自原版运行结果。

原源码仍存在 Git 历史中。需要补跑时，可在另外的 checkout/worktree 使用此提交和其构建依赖；不要将旧构建文件重新覆盖到当前 Workers 工程。启动原版与新版本后运行：

```sh
node scripts/differential.mjs http://127.0.0.1:25500 http://127.0.0.1:8787
```

该工具只发送文档中的测试节点，输出本地 `.baseline-build/differential.json`。JSON/YAML 以结构比较，其他输出精确比较；格式或行为差异也会使脚本返回非零，需要逐项检查，不能自动忽略。
