# Evidence: 2025-12-15 AI-memory design chat

## 摘要
目标：解决 AI 驱动项目开发的“长期记忆/一致性管理”。

关键决策（将被 ADR 固化）：
- 记忆以仓库为真理：`/.ai/memory/**`，通过 PR 更新，CI 门禁校验。
- 多 Agent 一致视角依赖“确定性的 context pack”，而非聊天记忆。
- 陈旧检测：记忆条目声明 `watch_paths`；若 watch_paths 自条目上次修改以来有变更，则条目 stale，需更新或豁免。
- 冲突策略：constraint 用 `key` 唯一；adr 用 `topic` 唯一。

成功标准：见 `TASK-2025-12-15-0001` 的验收标准（可机器校验）。

## 原始对话
（占位）将本次对话全文或关键片段粘贴到这里即可。
