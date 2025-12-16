# CONSTRAINT-0001 AI 记忆与一致性硬约束（V1）

- 记忆只能写入 `.ai/memory/**`，并通过 PR 合并生效
- CI 必须校验：evidence、冲突、陈旧（watch_paths）
- Context Pack 必须包含文件内容与 blob sha，且输出确定性

> 注意：本约束的 `watch_paths` 只覆盖“系统表面”（tools/workflows/config/schemas），避免每新增一个 TASK 就把约束判为 stale。
