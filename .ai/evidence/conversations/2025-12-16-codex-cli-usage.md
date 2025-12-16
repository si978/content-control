# Codex CLI 使用方式（V1）

目标：从需求文档出发，让 Codex CLI 驱动开发/测试/上线，并且在规模扩大（百份文档、十万行代码）后仍保持一致性与可追溯。

## 你要记住的三个概念

1) **长期记忆（Repo-first memory）**：写在仓库里，走 PR
- 位置：`.ai/memory/**`
- 内容：任务（TASK）、约束（CONSTRAINT）、决策（ADR）、操作手册（RUNBOOK）
- 好处：可审计、可回滚、可 review；不依赖单次聊天记录。

2) **上下文包（Context Pack）**：给 AI 的“唯一资料包”
- 由 `memctl build-pack` 生成 `context_pack.json`
- 同一 `commit + task_id`，产物必须可复算且确定（`pack_id` 固定）
- `validate-pack` 可验证：pack 内容与 git 中该 commit 的文件内容一致，且 `pack_id` 可重算。

3) **门禁（GitHub Actions）**：把规则变成“机器能判对错”
- PR 打 `ai` 标签才触发（避免误伤）
- 校验 memory 合法性、stale、pack 可复算、（可选）agent_report 可复算。

## 一条最小工作流（建议：一任务一 PR）

### 0) 建任务（TASK）
在 `.ai/memory/tasks/TASK-.../meta.json` 写清：
- goal / acceptance_criteria
- `pack.include_paths`：本次允许 Codex 看的文件/目录（只放相关的，不要全仓库）
- evidence：指向你的需求文档（建议放 `docs/` 下）

### 1) 生成并验证上下文包
在仓库根目录：
- `python .ai/tools/memctl.py build-pack --commit HEAD --task-id TASK-... --out context_pack.json`
- `python .ai/tools/memctl.py validate-pack --pack context_pack.json --task-id TASK-...`

### 2) 用 Codex CLI 开工（关键：先锁定上下文）
给 Codex 的开场指令要包含：
- Task ID
- `context_pack.json` 路径
- 规则：只依据 pack 内文件工作；需要额外文件时，先给出“需要加入 pack 的路径清单”，不要自行扩张范围。

### 3) 合入：让门禁替你把关
- 提 PR，正文包含 `Task ID: TASK-...`
- PR 打标签 `ai`
- CI 通过后再 merge

## 大规模项目怎么用（核心：切片，而不是一次喂全量）
- 约束（CONSTRAINT）与决策（ADR）保持很小但稳定：每个任务自动带上 active 约束，保证一致性。
- 每个任务只打包“本次要改的组件目录 + 相关文档 + 测试/上线 runbook”。
- 当代码/流程变化导致记忆过期时，用 `watch_paths` + `check-stale` 强制更新记忆或写豁免理由（避免长期漂移）。
