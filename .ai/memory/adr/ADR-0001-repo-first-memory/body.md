# ADR-0001 Repo-first 记忆与确定性 Context Pack

## 决策
1) 长期记忆以仓库为单一事实源：`.ai/memory/**`，只能通过 PR 变更。  
2) 多 Agent 一致视角依赖确定性 `context_pack.json`（包含文件内容与 blob sha），而不是依赖聊天记录。  
3) 陈旧检测：当 `watch_paths` 自该条目上次修改以来发生变化，该条目视为 stale，必须更新或给出豁免理由。  
4) 冲突策略：constraint 以 `key` 唯一；adr 以 `topic` 唯一。

## 影响
- 优点：可审计、可回滚、可重放、可在 CI 中强制执行一致性。
- 代价：需要维护少量结构化 `meta.json`；新增/变更记忆必须走 PR。
