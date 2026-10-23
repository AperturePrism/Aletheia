-- 心智地图初始 schema（modules/M2 §4.1，docs/05 §3）
--
-- 方言：PostgreSQL。本迁移是**部署形态**的产物；I4 的运行时一致性
-- DoD（多源保留/回放/分支）由 core/prism 的 Store 接口 + 内存实现承载
-- （环境未就绪时不假装可用），PostgreSQL 绑定在环境就绪后补
-- （05 §0 C1：契约定死，实现可变）。
--
-- 设计不变量（modules/M2 §4.3/§4.4/§4.5）：
--   · 不覆盖不合并：属性冲突 → 新增版本 + Conflict 记录
--   · 时间版本：旧版本置 valid_to，新版本 valid_from := now
--   · 假设分支：分支内写入带 is_hypothesis + branch_id；回滚 = 分支写入
--     全部置 valid_to（软删除），图状态与分支前一致
--
-- 迁移按文件名序号执行；本文件不可修改 —— 变更走新的前向迁移。

CREATE TABLE entity (
    entity_id      TEXT PRIMARY KEY,
    kind           TEXT NOT NULL,            -- ASSET/SERVICE/IDENTITY/ENDPOINT/DEFECT/PATH/TIMELINE
    attrs          JSONB NOT NULL,           -- 05 §3.2 必填/可选属性
    valid_from     TIMESTAMPTZ NOT NULL,
    valid_to       TIMESTAMPTZ,              -- NULL = 当前有效
    version        INTEGER NOT NULL,         -- 同一实体的第 n 个版本，从 1 起
    confidence     DOUBLE PRECISION NOT NULL DEFAULT 0,
    is_hypothesis  BOOLEAN NOT NULL DEFAULT FALSE,
    branch_id      TEXT NOT NULL DEFAULT 'main'
);

CREATE INDEX idx_entity_current ON entity (entity_id, kind) WHERE valid_to IS NULL;
CREATE INDEX idx_entity_kind    ON entity (kind, valid_from, valid_to);

CREATE TABLE relation (
    relation_id  TEXT PRIMARY KEY,
    from_entity  TEXT NOT NULL REFERENCES entity (entity_id),
    to_entity    TEXT NOT NULL REFERENCES entity (entity_id),
    type         TEXT NOT NULL,              -- RESOLVES_TO/RUNS_ON/... （05 §3.1 枚举）
    attrs        JSONB,
    confidence   DOUBLE PRECISION NOT NULL DEFAULT 0,
    valid_from   TIMESTAMPTZ NOT NULL,
    valid_to     TIMESTAMPTZ
);

CREATE INDEX idx_relation_from ON relation (from_entity, type) WHERE valid_to IS NULL;
CREATE INDEX idx_relation_to   ON relation (to_entity, type)   WHERE valid_to IS NULL;

CREATE TABLE provenance (
    entity_id   TEXT NOT NULL REFERENCES entity (entity_id),
    source_kind TEXT NOT NULL,               -- ACTIVE_SCAN/PASSIVE_TRAFFIC/WHITEBOX_SOURCE/BINARY/HISTORICAL/LLM_INFERRED
    evidence_id TEXT,
    exec_id     TEXT,
    observed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (entity_id, source_kind, evidence_id, exec_id, observed_at)
);

CREATE TABLE branch (
    branch_id     TEXT PRIMARY KEY,
    parent_branch TEXT NOT NULL DEFAULT 'main',
    created_at    TIMESTAMPTZ NOT NULL,
    status        TEXT NOT NULL DEFAULT 'OPEN'  -- OPEN/MERGED/ROLLED_BACK
);
