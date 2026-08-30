# CLAUDE.md

JXWAF Agent：通过 jxwaf-cli + 文档体系，让 AI 在 IDE 中用自然语言运维 JXWAF（标准版 / 专业版 / 云WAF）。

## 工作闭环

```
需求理解 → 查 docs/ 文档 → jxwaf-cli generate 生成 → 测试环境 apply + verify 验证
→ cleanup 清理 → 用户确认 → 生产环境 dry-run → --apply 下发
```

## 关键约定

- 所有 CLI 输出为 JSON（stdout），错误在 stderr（`{"result":false,"error":"..."}`），退出码 0/1。先解析 JSON 再继续。
- 写入操作默认 dry-run，必须经用户确认后加 `--apply` 才落地。
- 拦截类配置默认 watch 观察，无误报再转 block。
- 删除操作需用户二次确认。
- 凭据严禁明文输出。

## 常用命令

```bash
jxwaf-cli sandbox init                # 官方沙盒初始化（独立命令组，与自有环境隔离）
jxwaf-cli config show                # 配置查看（脱敏）
jxwaf-cli config validate            # 连通性自检
jxwaf-cli generate <类型> --params file.json [--output cfg.json]
jxwaf-cli sandbox verify <信封文件>    # 沙盒一键闭环：清基线→部署→打流量→查日志→报告→清理
jxwaf-cli sandbox reset|cleanup      # 沙盒清空/删除
jxwaf-cli apply ... [--apply]        # 自有环境下发（dry-run 默认）
jxwaf-cli verify <用例> --url URL    # 通用流量验证（不动配置）
jxwaf-cli rule|namelist|component|website|soc ...
```

官方沙盒（sandbox 命令组）与自有环境命令严格隔离：sandbox 命令默认只操作沙盒环境（sandbox），通用命令默认只操作 active 环境。

完整规范见 `docs/`（requirements.md 为需求基线），运行规则见 `.trae/rules/project_rules.md`（其他 IDE 等价阅读 `AGENTS.md`）。