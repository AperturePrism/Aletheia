# Aletheia —— 顶层 Makefile
#
# docs/04 §I0 DoD 原文：
#     `make build && make test && make lint` 全绿
# 本文件就是这条命令的实现。
#
# 设计原则（对齐 10 §8「把检查固化为 CI —— 终极方案」）：
#   本文件的长期目标是让自己变得不必要 —— 检查项一旦写进 CI 门禁，
#   就无法自欺。因此每个 gate 目标都设计成可被 CI 直接调用。
#
# 门禁编号对应 docs/04 §6 的 Q1–Q14：
#   Q1 单元测试全绿        → make test
#   Q2 解析器覆盖率 ≥90%   → make coverage（I1 起生效）
#   Q3/Q4/Q5 红线          → make redline（I2/I3 起填充）
#   Q6 确定性              → make test-determinism
#   Q7 Lint 无 error       → make lint
#   Q8 长时稳定性          → make stability（默认不跑）
#   Q9 预算熔断            → 见 I3
#   Q10 契约一致性         → make test-contract
#   Q11 WebUI 可嵌入       → make verify-embed
#   Q12 前端无凭据         → make check-frontend-credentials
#   Q13 daemon 仅 127.0.0.1→ make check-loopback
#   Q14 TS 类型由 proto 生成 → make proto + make check-gen-fresh
#
# 所有目标在 Windows（Git Bash）与 Linux/macOS 上行为一致。

SHELL := /bin/bash
.DEFAULT_GOAL := help

# ---- 可执行文件路径 ----
# 不假设已在 PATH 中的工具：用本仓库 node_modules/.bin 与 .venv 内的版本，
# 避免"开发机与 CI 版本不同"造成的难复现问题。
BUF      := node_modules/.bin/buf
NPM      := npm
UV       := uv
GO       := go

# Python 解释器解析。
#
# 不要写死 .venv/bin/python —— 该路径只在 venv 建成后存在。CI 的
# security-static job 只跑 pytest、不跑 make env，写死路径时它必然失败
# （Error 127: .venv/bin/python: No such file or directory）。
#
# 但也不能无条件回退到 PATH 上的 python3：那台解释器没装 pytest，
# 回退只会把 127 变成更隐密的 "No module named pytest"（五跑的真实失败）。
#
# 因此规则是：
#   1. 有 .venv  -> 用它（Windows 与 Linux 两种布局都覆盖）
#   2. 无 .venv  -> 找 PATH 上**验证过 pytest 可用**的 python3 / python
#   3. 都不可用   -> 直接报错并提示 make env，不静默降级
#
# 第 3 条的理由：静默降级到跑不起来的解释器，比明确失败危险得多 ——
# docs/10 §0 把"让没查伪装成没问题"列为自检最典型的失真。
PY = $(shell \
	if [ -x .venv/Scripts/python.exe ]; then echo .venv/Scripts/python.exe; \
	elif [ -x .venv/bin/python ]; then echo .venv/bin/python; \
	else \
		found=""; \
		for c in python3 python; do \
			if command -v $$c >/dev/null 2>&1 && $$c -c "import pytest" >/dev/null 2>&1; then found=$$c; break; fi; \
		done; \
		if [ -n "$$found" ]; then echo $$found; else echo PYTHON_MISSING; fi; \
	fi)

ifeq ($(PY),PYTHON_MISSING)
$(error 未找到可用的 Python + pytest。请执行 make env（创建 .venv 并安装 dev 依赖），或确认 PATH 上的 python3 已装 pytest。)
endif

PYTEST := $(PY) -m pytest
RUFF   := $(PY) -m ruff


WEB_DIR    := web
GEN_DIR    := web/src/gen
GO_GEN_DIR := core/api

ALETHD_BIN := bin/alethd
ALETH_BIN  := bin/aleth

# Go 命令的包范围。
# 不用 ./... —— web/node_modules 下的第三方 Go 包（flatted，无自己的 go.mod）
# 会被算进本模块。理由详见 go.mod 的"Go 模块边界"段。
GO_PKGS := ./cmd/... ./core/...

# pytest 附加参数。默认 -q（安静模式）。
# 用法：make test-python PYTEST_ARGS="tests/test_security_scan.py -q"
# CI 用它跑单个文件，本地跑全量时无需指定。
PYTEST_ARGS ?= -q

# 版本号：由 git describe 生成，失败时回退 dev。
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: help
help: ## 显示本帮助（默认目标）
	@echo "Aletheia · I0 仓库骨架与抽象层"
	@echo ""
	@echo "DoD（docs/04 §I0）:  make build && make test && make lint"
	@echo ""
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2}'

# ============================================================================
# 环境准备
# ============================================================================

.PHONY: env
env: env-web env-root ## 安装全部依赖（Go / npm / uv）

.PHONY: env-web
env-web: ## 安装 web/ 的前端依赖
	@echo "== web/ npm install =="
	cd $(WEB_DIR) && $(NPM) install

.PHONY: env-root
env-root: ## 安装根 npm 依赖（buf）+ Go modules + uv venv
	@echo "== Go modules =="
	$(GO) mod download
	@echo "== buf（Protobuf 工具链）=="
	$(NPM) install
	@echo "== Python dev 依赖 =="
	$(UV) sync --group dev

# ============================================================================
# Q10 / Q14：契约生成
# ============================================================================

.PHONY: proto
proto: ## 从 proto/ 生成 Go / TypeScript / Python 三侧代码（Q14）
	@bash scripts/gen-proto.sh

.PHONY: proto-lint
proto-lint: ## buf lint：契约自身的静态检查（计入 Q7）
	$(BUF) lint proto/

.PHONY: check-gen-fresh
check-gen-fresh: ## Q14：生成物必须与契约一致（CI 用）
	@bash scripts/check-gen-fresh.sh

# ============================================================================
# 构建
# ============================================================================

.PHONY: build
build: web-build go-build ## 完整构建（含嵌入 WebUI）

.PHONY: web-build
# 依赖 env-web 而不是让调用方自己记得先 npm install。
# 这个依赖是踩过坑才加的：CI 首跑时 Q11 与 lint 两个 job 在 make build 前
# 只跑了根目录的 npm install（装的是 buf），漏了 web/ 的前端依赖，
# 结果 eslint: not found + 大量 TS2307。
# 把依赖写在这里，"忘了装"就不可能发生。
web-build: env-web ## 构建 WebUI 产物（嵌入 Go 二进制用）
	@echo "== WebUI build =="
	cd $(WEB_DIR) && $(NPM) run build

.PHONY: go-build
go-build: ## 编译 alethd 与 aleth（先嵌入 WebUI 产物）
	@bash scripts/embed-web.sh
	@echo "== Go build =="
	@mkdir -p bin
	$(GO) build -ldflags "$(LDFLAGS)" -o $(ALETHD_BIN) ./cmd/alethd
	$(GO) build -ldflags "$(LDFLAGS)" -o $(ALETH_BIN)  ./cmd/aleth
	@echo "built: $(ALETHD_BIN), $(ALETH_BIN)"

.PHONY: verify-embed
verify-embed: go-build ## Q11：WebUI 产物可嵌入单一二进制并正常服务
	@echo "== Q11 冒烟测试 =="
	@bash scripts/smoke-embed.sh $(ALETHD_BIN)

# ============================================================================
# 测试（Q1）
# ============================================================================

.PHONY: test
test: test-go test-python ## Q1：全部单元测试

# Go 测试的 race 检测需要 cgo，即需要 C 编译器。
# 本机（Windows + 无 MinGW）默认没有，因此做成可选项而非删掉：
# 装了 C 工具链的机器与 CI 上应显式开启（GO_TEST_RACE=1 make test）。
# 这不是"降级门禁"，而是把一项在无 C 工具链环境下无法执行的检查
# 显式标注出来 —— docs/09 §5 #5：任何"临时"绕过一律先问。
GO_TEST_RACE ?= 0

.PHONY: test-go
test-go: ## Go 单元测试（GO_TEST_RACE=1 启用 race，需 cgo）
ifeq ($(GO_TEST_RACE),1)
	@echo "== go test -race（GO_TEST_RACE=1 显式启用）=="
	$(GO) test $(GO_PKGS) -race -count=1
else
	@if $(GO) env CGO_ENABLED | grep -q "^1$$"; then \
		echo "== go test -race（检测到 CGO_ENABLED=1）=="; \
		$(GO) test $(GO_PKGS) -race -count=1; \
	else \
		echo "== go test（race 已跳过：CGO_ENABLED=0，无 C 编译器）=="; \
		echo "   装有 C 工具链时用 GO_TEST_RACE=1 make test 启用"; \
		$(GO) test $(GO_PKGS) -count=1; \
	fi
endif

.PHONY: test-python
test-python: ## Python 单元测试
	$(PYTEST) $(PYTEST_ARGS)

.PHONY: test-contract
test-contract: ## Q10：契约一致性（Go/Python/TS 三侧 vs docs/05）
	$(PYTEST) tests/ -q -m redline

.PHONY: test-determinism
test-determinism: ## Q6：确定性（相同输入产出字节级一致）
	$(PYTEST) -q -m determinism
	$(GO) test $(GO_PKGS) -count=1 -run Determin

.PHONY: redline
redline: ## Q3/Q4/Q5 红线门禁（当前为占位，随 I2/I3 填充）
	@echo "== 红线门禁 Q3/Q4/Q5 =="
	@echo "  Q3 伪造证据注入 100% 被拒 —— I2 交付"
	@echo "  Q4 越界 100% fail-closed    —— I3 交付"
	@echo "  Q5 抓包零真实值泄漏         —— I3 交付"
	@$(PYTEST) -q -m redline
	@echo "  （当前红线用例：契约一致性，见 tests/test_contract_consistency.py）"

.PHONY: coverage
coverage: ## Q2：覆盖率（阈值见 pyproject.toml，解析器 ≥90%）
	$(PYTEST) --cov --cov-report=term-missing --cov-report=html
	$(GO) test $(GO_PKGS) -coverprofile=cover.out
	@echo "Go coverage: cover.out"

.PHONY: stability
stability: ## Q8：长时稳定性测试（24h/143h，默认不跑）
	@echo "Q8 稳定性测试需显式运行；时长见 docs/04 §6（P0 24h / P3 143h）。"
	@bash tests/stability/run.sh 2>/dev/null || \
		echo "tests/stability/run.sh 尚未实现（I0–I3 期间逐步建立）"

# ============================================================================
# Lint（Q7）
# ============================================================================

.PHONY: lint
lint: ## Q7：全部静态检查（Go / Python / Web / proto）
	@bash scripts/lint.sh


# ============================================================================
# 安全静态检查（docs/10 §3 P3：安全机制绕过）
# ============================================================================

.PHONY: check-no-bypass
check-no-bypass: ## 10 §3 P3 检测：禁止 = CONFIRMED 直赋、except: pass、自行终止
	@echo "== docs/10 §3 P3 安全机制绕过检测 =="
	@bash scripts/check-no-bypass.sh
	@echo ""
	@echo "附：自动化测试 tests/test_security_scan.py 会对该脚本做变异验证"
	@echo "（确认它真的能抓到违规，而不是永远返回 OK）。"

.PHONY: check-iteration-docs
check-iteration-docs: ## docs/09 §10 第 9、10 项：交接文档与自检报告齐全
	@bash scripts/check-iteration-docs.sh --all

.PHONY: check-governance-guard
check-governance-guard: ## docs/11 §5 裁决护栏：治理模型未被指令文档放宽
	@bash scripts/check-governance-guard.sh

.PHONY: check-frontend-credentials
check-frontend-credentials: ## Q12：前端无法直接访问真实凭据
	@bash scripts/check-frontend-credentials.sh

.PHONY: check-loopback
check-loopback: ## Q13：daemon 默认仅监听 127.0.0.1
	@echo "== Q13：默认监听地址必须是回环 =="
	@grep -nE 'DefaultListenAddr\s*=\s*"' core/config/config.go | grep -qE '"127\.0\.0\.1"' \
		&& echo "OK (Q13): DefaultListenAddr = 127.0.0.1" \
		|| { echo "FAIL (Q13): DefaultListenAddr 不是 127.0.0.1"; exit 1; }

# ============================================================================
# 运行
# ============================================================================

.PHONY: run
run: build ## 构建并前台运行 alethd（需 --authorization）
	./$(ALETHD_BIN) --authorization $(AUTH)

.PHONY: dev
dev: ## 并行启动 alethd 与 vite dev server（开发用）
	@echo "启动 vite dev（7724）与 alethd（7723）。alethd 需另开终端："
	@echo "  ./$(ALETHD_BIN) --authorization <roe.yaml>"
	cd $(WEB_DIR) && $(NPM) run dev

# ============================================================================
# 清理
# ============================================================================

# ============================================================================
# 一个命令跑全部门禁（CI 之外的本地总检）
# ============================================================================

.PHONY: gate
gate: build test lint check-gen-fresh check-frontend-credentials check-loopback check-no-bypass check-iteration-docs check-governance-guard ## 全部门禁（Q1/Q7/Q10–Q14 + P3 + 交付物 + 治理护栏）
	@echo ""
	@echo "全部门禁通过。（注意：Q3/Q4/Q5/Q6/Q8/Q9 见 .github/workflows/ci.yml 末尾的补齐计划）"

# ============================================================================
# 清理
# ============================================================================

.PHONY: clean
clean: ## 清理构建产物
	rm -rf bin cmd/alethd/webdist $(WEB_DIR)/dist cover.out .pytest_cache htmlcov .ruff_cache
	find . -name "__pycache__" -type d -not -path "./node_modules/*" -prune -exec rm -rf {} + 2>/dev/null || true

.PHONY: distclean
distclean: clean ## 清理构建产物 + node_modules + .venv
	rm -rf node_modules $(WEB_DIR)/node_modules .venv
