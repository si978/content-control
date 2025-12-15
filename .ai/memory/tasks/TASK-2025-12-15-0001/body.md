# TASK-2025-12-15-0001

本任务把“本次对话”固化为可机器校验的工程规则与产物：

- 记忆条目（Curated Memory）：`.ai/memory/**`
- 确定性上下文包：`memctl build-pack`
- CI 门禁：`ai_memory_validate.yml` + `ai_pr_gate.yml`

交付物：
- `memctl.py`：validate / check-stale / build-pack / validate-report
- GitHub Actions：校验记忆、构建 pack、PR 门禁（仅 label=ai）
