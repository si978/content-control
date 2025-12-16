# content-control

这是一个“AI 驱动项目开发”的基础设施仓库：把 **长期记忆/约束/决策** 固化到 GitHub 仓库，并用 **确定性的 context pack** 让多个 Agent 在任何时间点都获得一致的上下文视角。

## 你能得到什么
- 长期记忆：`.ai/memory/**`（任务/约束/ADR/Runbook，PR 可审计、可回滚）
- 统一上下文：`memctl build-pack` 生成 `context_pack.json`，同一 `commit+task_id` 可复算、可验证
- 自动把关：PR 打 `ai` 标签触发门禁，校验 memory/stale/pack/report（可配置软/硬模式）

## 在其它标准 GitHub 仓库中使用（最短路径）
1) 复制目录与文件到你的项目根目录：
   - `.ai/`
   - `.github/workflows/ai_*.yml`
   - `.github/PULL_REQUEST_TEMPLATE/ai.md`（可选）
   - `CODEOWNERS`、`.gitignore`（合并相关条目）
2) Push 到 GitHub，确认 Actions 里 `AI Memory Validate` 变绿（代表系统已运行）。
3) 从需求文档开始建第一个任务：`.ai/memory/tasks/TASK-.../meta.json`，并把需求文档路径加入 `pack.include_paths`。

## 用 Codex CLI 跑一条“真流程”（一任务一 PR）
1) 生成上下文包（给 Codex 的唯一资料包）：
   - `python .ai/tools/memctl.py build-pack --commit HEAD --task-id TASK-... --out context_pack.json`
   - `python .ai/tools/memctl.py validate-pack --pack context_pack.json --task-id TASK-...`
2) 在 Codex CLI 里开始任务：让它读取 `context_pack.json`，并要求“缺文件就先提清单，让你把路径加入 TASK 的 pack 再重打包”。
3) 提 PR：PR 正文包含 `Task ID: TASK-...`，并打标签 `ai`，让门禁自动把关（`.ai/config.json` 可调软/硬）。

更多操作细节见：`.ai/README.md` 与 `RUNBOOK-0001`（`.ai/memory/runbooks/`）。
