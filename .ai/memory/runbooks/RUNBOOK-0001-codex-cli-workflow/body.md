# RUNBOOK-0001: Codex CLI 的 AI 开发工作流（V1）

适用场景：从一份需求文档出发，用 Codex CLI 驱动开发/测试/上线，并在大规模代码库中保持一致性与可追溯。

## 约定
- 一任务一 PR：每个 `TASK` 对应一个可合并的 PR。
- 上下文包是唯一资料包：Codex 开工前必须读取 `context_pack.json`；缺文件就先提清单，更新 TASK 的 `pack.include_paths` 后重打包。
- 所有“长期有效”的东西写进记忆：约束进 CONSTRAINT，关键决策进 ADR，操作流程进 RUNBOOK。

## 标准流程

### A. 需求 → 任务（TASK）
1) 把需求文档放进仓库（建议 `docs/`）。
2) 新建 `.ai/memory/tasks/TASK-.../meta.json`：
   - 写清 `goal`、`acceptance_criteria`
   - 在 `pack.include_paths` 中放入需求文档与少量必要文件

### B. 生成上下文包（Context Pack）
- `python .ai/tools/memctl.py build-pack --commit <commit> --task-id TASK-... --out context_pack.json`
- `python .ai/tools/memctl.py validate-pack --pack context_pack.json --task-id TASK-...`

### C. Codex CLI 开工（固定开场模板）
把下面内容作为 Codex CLI 的第一段指令（按需替换 TASK/文件名）：

```
Task ID: TASK-...
请读取并遵守 context pack: context_pack.json
规则：
1) 只依据 pack 内的文件做判断与修改；
2) 如果你需要 pack 外的文件，请先输出“需要加入 pack 的路径清单”，等待我更新 TASK 的 pack 后再继续；
3) 完成后给出：变更摘要 + 你运行过的验证命令 + 可用于 PR 的描述（包含 Task ID）。
```

### D. 合入（GitHub PR 门禁）
1) 提 PR，正文包含 `Task ID: TASK-...`
2) 打标签 `ai`
3) CI 通过后 merge

## 大规模仓库建议
- 建 `component_map`（组件→目录索引），让每个 TASK 的 `pack.include_paths` 只打包目标组件目录。
- 测试与上线写成 RUNBOOK，并在相关 TASK 中加入 `include_memory_ids`，避免流程靠“口头记忆”。
