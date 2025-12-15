# CONSTRAINT-0001 AI 记忆与一致性硬约束（V1）

- 记忆只能写入 `.ai/memory/**`，并通过 PR 合并生效
- CI 必须校验：evidence、冲突、陈旧（watch_paths）
- Context Pack 必须包含文件内容与 blob sha，且输出确定性
