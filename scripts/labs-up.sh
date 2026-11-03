#!/usr/bin/env bash
# 起一个自建/对照靶场（幂等）。
#
# 用法：
#   scripts/labs-up.sh juice-shop
#   scripts/labs-up.sh bizlogic multi-hop antifantasy   # 可一次起多个
#   scripts/labs-up.sh --down juice-shop                # 停止并**清理数据**
#
# # 为什么必须先 down -v 再 up（M9 §8）
#
# M9 §8 要求「每次评测后状态完全重置，污染检测」。靶场若带着上一轮
# 改过的数据继续跑，下一轮的分数就无法归因 —— 看起来变好了可能只是
# 因为 flag 已经被解过、路径已经被创建过。
# 因此本脚本**永远**先 `down -v`，不给"复用上次环境"的选项。
#
# # 为什么要在脚本里做前置校验
#
# `labs/README.md` §3 的六条约束里，有三条可以被机械检查：
#   · 镜像按 digest 固定（07 §T6）  → 查 `@sha256:`
#   · 仅回环可达（07 §T5.1 / Q13）  → 查端口绑定必须有 127.0.0.1 前缀
#   · 无宿主凭据（07 §T3）          → 查 volumes 里无 docker.sock / .ssh
#
# 靠人记得去看 compose 文件是不行的（本项目反复吃过"文档写了但没人执行"
# 的亏）。这三条在这里变成**起靶场前的硬闸门**：不合规就不起。

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

RED=$'\033[31m'; YEL=$'\033[33m'; GRN=$'\033[32m'; NC=$'\033[0m'
fail() { printf '%sFAIL%s %s\n' "$RED" "$NC" "$*" >&2; exit 1; }
warn() { printf '%sWARN%s %s\n' "$YEL" "$NC" "$*"; }
ok()   { printf '%sOK%s   %s\n' "$GRN" "$NC" "$*"; }

DOWN=0
if [ "${1:-}" = "--down" ]; then DOWN=1; shift; fi

LABS=("$@")
if [ ${#LABS[@]} -eq 0 ]; then
  fail "用法：$0 [--down] <lab> [lab...]
可用：juice-shop | bizlogic | multi-hop | antifantasy"
fi

# ---- 前置：docker 可用 ----
if ! command -v docker >/dev/null 2>&1; then
  fail "找不到 docker。
本仓库的 docker 跑在 WSL2(Arch) 里。从 Windows 侧执行：
  wsl -d Arch -- bash scripts/labs-up.sh ${LABS[*]}"
fi
if ! docker info >/dev/null 2>&1; then
  fail "docker daemon 未运行。
在 WSL 内启动：
  nohup dockerd > /tmp/dockerd.log 2>&1 &
  或（若启用了 systemd）systemctl start docker"
fi
DC="$(command -v docker-compose || true)"
if [ -z "$DC" ]; then
  if docker compose version >/dev/null 2>&1; then DC="docker compose"; else
    fail "找不到 docker-compose / docker compose —— 在 WSL 内执行：pacman -S docker-compose"
  fi
fi

# ---- 约束校验（机械可查的三条）----
check_compose() {
  local lab="$1" f="labs/$1/compose.yml"
  [ -f "$f" ] || fail "缺少 $f"

  # ★ 校验前先剥掉注释行。
  #
  # 否则注释里写"不挂 docker.sock"会被下面的凭据检查命中 —— 我第一次
  # 跑就被自己写的说明文字拦下了（假阳性）。校验必须只看**实际生效的
  # 配置**，而不是文件里的任何字样。
  local body
  body=$(grep -vE '^[[:space:]]*#' "$f")

  # 1) digest 固定
  local imgs unpinned
  imgs=$(printf '%s\n' "$body" | grep -E '^[[:space:]]*image:' || true)
  [ -n "$imgs" ] || fail "$f 没有任何 image 行"
  unpinned=$(printf '%s\n' "$imgs" | grep -vE '@sha256:[0-9a-f]{64}' || true)
  if [ -n "$unpinned" ]; then
    fail "$f 存在未按 digest 固定的镜像（07 §T6）：
$unpinned
取 digest：docker pull <tag> && docker inspect --format='{{index .RepoDigests 0}}' <tag>"
  fi
  ok "$lab 镜像均按 digest 固定"

  # 2) 仅回环发布：所有端口映射的宿主侧必须是 127.0.0.1
  local badports
  badports=$(printf '%s\n' "$body" \
             | grep -oE '"[0-9.]+:[0-9]+:[0-9]+"|"[0-9]+:[0-9]+"' \
             | grep -vE '"127\.0\.0\.1:' || true)
  if [ -n "$badports" ]; then
    fail "$f 存在非回环端口绑定（07 §T5.1 / Q13）：
$badports
必须写成 \"127.0.0.1:<宿主端口>:<容器端口>\"
（裸 \"<宿主端口>:<容器端口>\" 会绑 0.0.0.0，暴露到局域网）"
  fi
  ok "$lab 端口均仅绑定回环"

  # 3) 无宿主凭据
  if printf '%s\n' "$body" | grep -qE 'docker\.sock|/\.ssh|\.aws|\.kube|\.docker/config\.json'; then
    fail "$f 挂载了宿主凭据（07 §T3）：$(printf '%s\n' "$body" | grep -nE 'docker\.sock|/\.ssh|\.aws|\.kube')"
  fi
  ok "$lab 未挂载宿主凭据"
}

# 等待某个宿主端口可连接。
#
# 为什么在**宿主侧**探测，而不是用 compose healthcheck：
# 部分靶场镜像是 distroless 风格（juice-shop 实测连 `sh` 都没有），
# 容器内健康检查无从执行，会永远 unhealthy，而服务其实是好的 ——
# 那种假警报比没有健康检查更糟。
#
# 而且"宿主侧能否连上"才是真正需要的语义：扫描器就从这里发起。
wait_port() {
  local host="$1" port="$2" timeout_s="${3:-120}"
  local deadline=$((SECONDS + timeout_s))
  while [ $SECONDS -lt $deadline ]; do
    if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then
      exec 3>&- 2>/dev/null || true
      return 0
    fi
    sleep 1
  done
  return 1
}

# 从 compose 里抽取已发布的端口，输出两列："<宿主端口> <容器端口>"。
#
# ★ 注意输出是**空格分隔的两列**（不是 "H:C"）：调用方用
# `read -r hp cp` 解析。我最初写成 `cut -d: -f2,3`，输出 "3000:3000"，
# 于是 `hp` 变成 "3000:3000"、`cp` 为空，探测用了非法端口并误报
# "120s 内不可达" —— 而 curl 明明是 200。抽取格式与消费格式必须对齐。
published_ports() {
  grep -vE '^[[:space:]]*#' "labs/$1/compose.yml" \
    | grep -oE '"127\.0\.0\.1:[0-9]+:[0-9]+"' \
    | tr -d '"' \
    | sed -E 's/^127\.0\.0\.1:([0-9]+):([0-9]+)$/\1 \2/'
}

# ---- 主流程 ----
for lab in "${LABS[@]}"; do
  f="labs/$lab/compose.yml"
  [ -f "$f" ] || fail "未知靶场 $lab（期望 $f）"

  printf '\n== %s ==\n' "$lab"

  if [ "$DOWN" -eq 1 ]; then
    $DC -f "$f" down -v --remove-orphans >/dev/null 2>&1 || true
    ok "$lab 已停止并清理数据（down -v）"
    continue
  fi

  check_compose "$lab"

  # ★ 状态重置：永远先 down -v（M9 §8）。
  $DC -f "$f" down -v --remove-orphans >/dev/null 2>&1 || true
  ok "$lab 已清理旧状态"

  if ! $DC -f "$f" up -d 2>&1 | tail -5; then
    warn "$lab 启动失败，最近日志："
    $DC -f "$f" logs --tail=20 2>&1 | tail -20
    exit 1
  fi

  # 就绪判定在宿主侧（见 wait_port 的说明）。
  # 注意：这里是**主流程**，不能用 `local`（会报
  # "local: can only be used in a function" 并让脚本以 1 退出）。
  ports=""
  hp=""
  cp=""
  ready=1
  ports=$(published_ports "$lab")
  [ -n "$ports" ] || fail "$lab 未声明任何 127.0.0.1 发布端口 —— 靶场无法被访问"
  while read -r hp cp; do
    [ -n "${hp:-}" ] || continue
    if wait_port 127.0.0.1 "$hp" 120; then
      ok "$lab 就绪：127.0.0.1:${hp} → 容器 ${cp}"
    else
      warn "$lab 端口 ${hp} 在 120s 内不可达"
      $DC -f "$f" logs --tail=20 2>&1 | tail -20
      ready=0
    fi
  done <<< "$ports"
  [ "$ready" -eq 1 ] || exit 1

  # 记录**实际运行的镜像 digest** —— 分数必须能追溯到具体镜像。
  $DC -f "$f" ps --format '{{.Service}} {{.Image}}' 2>/dev/null | sed 's/^/     /'
done

printf '\n'
ok "完成。健康端点见各 compose.yml 的 ports；抓包/扫描请只针对 127.0.0.1。"
