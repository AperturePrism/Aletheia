"""Juice Shop 基准适配器（I11 未竟项「自建靶场编排」的真实实现）。

OWASP Juice Shop 是自带 ground truth 的渗透测试靶场（官方已知漏洞
清单），本项目 NAS 部署已在运行（host 网络 :3000，镜像经
docker.1panel.live 拉取）。适配器：

  · setup() —— 探测靶场可达且指纹匹配（标题含 Juice Shop）；
  · tasks() —— 内置 ground truth 任务集（官方已知漏洞的关键挑战，
    静态清单；类别=漏洞类别，M9 §11"分场景统计不混合"）；
  · run 语义 —— 被测系统自行探索，`reported` 填它声称发现的
    挑战/漏洞 ID（与 ground_truth 同一命名空间才能比对）；
  · reset() —— 调用靶场自身的重置端点（Juice Shop REST /rest/admin/
    application-configuration 之外的官方重置：DELETE /rest/user/reset
    不存在 —— 实际用 docker restart 由部署脚本承担；HTTP 层的重置
    是应用级数据重置端点 POST /rest/admin/resetPassword… 也不通用）。
    因此 reset() 的默认实现是**显式不重置**（fail-closed：返回 False
    让调用方知道污染风险），容器重置由部署形态承担 —— 诚实边界。

为什么不用公开基准（CyBench/HTB）：它们需要外部账号/API/容器编排，
而「第三方干净环境复跑」的 DoD 在自建靶场上最容易兑现 —— 靶场
镜像公开、ground truth 内置、无账号依赖。公开基准适配器保持框架
可插拔（BenchmarkAdapter），随外部环境交付。
"""

from __future__ import annotations

import urllib.error
import urllib.request

from aletheia.harness.adapter import BenchmarkAdapter, BenchmarkTask

#: 任务集：OWASP Juice Shop 官方已知漏洞的关键挑战（静态 ground truth）。
#: 类别 = 漏洞类别（M9 §11 分场景统计）；ground_truth 为挑战 ID/结论
#: 标识（被测系统 `reported` 用同一命名空间）。
JUICE_SHOP_TASKS: tuple[BenchmarkTask, ...] = (
    BenchmarkTask(
        task_id="js-sqli-login",
        description="登录页存在 SQL 注入（' or 1=1--），可绕过认证登录任意邮箱。",
        difficulty="easy",
        category="sqli",
        ground_truth=("js-sqli-login",),
    ),
    BenchmarkTask(
        task_id="js-xss-dom-search",
        description="搜索框存在 DOM XSS，可注入 <iframe srcript> 类载荷触发。",
        difficulty="easy",
        category="xss",
        ground_truth=("js-xss-dom-search",),
    ),
    BenchmarkTask(
        task_id="js-path-traversal-ftp",
        description="/ftp 目录可目录遍历直接列出，泄露 easter.egg 等敏感文件。",
        difficulty="easy",
        category="path_traversal",
        ground_truth=("js-path-traversal-ftp",),
    ),
    BenchmarkTask(
        task_id="js-error-leak",
        description="错误处理泄露内部信息（/rest/... 500 响应含堆栈/SQL 片段）。",
        difficulty="easy",
        category="info_disclosure",
        ground_truth=("js-error-leak",),
    ),
    BenchmarkTask(
        task_id="js-broken-auth-admin",
        description="管理接口鉴权缺失（/rest/admin/application-configuration 无令牌可读）。",
        difficulty="medium",
        category="broken_access_control",
        ground_truth=("js-broken-auth-admin",),
    ),
)


class JuiceShopAdapter(BenchmarkAdapter):
    """OWASP Juice Shop 适配器（HTTP 探测 + 静态 ground truth）。"""

    def __init__(self, base_url: str = "http://127.0.0.1:3000", timeout_s: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self._reachable: bool | None = None

    @property
    def name(self) -> str:
        return "juice-shop"

    @property
    def reset_is_external(self) -> bool:
        """重置由部署形态（容器重启）承担 —— 驱动器在任务间跳过本适配器
        的 no-op reset 并在清单中如实记录污染面。"""
        return True

    def setup(self) -> None:
        """探测靶场可达且指纹匹配。失败即抛错 —— 靶场不在就别跑评测
        （fail-closed：跑出来的「全 0 分」比失败更误导）。"""
        try:
            req = urllib.request.Request(  # noqa: S310 —— base_url 是部署配置注入的受信值
                self.base_url + "/", method="GET"
            )
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:  # noqa: S310
                body = resp.read(65536).decode("utf-8", errors="replace").lower()
        except (urllib.error.URLError, OSError) as exc:
            self._reachable = False
            raise RuntimeError(f"juice-shop not reachable at {self.base_url}: {exc}") from exc
        if "juice shop" not in body:
            self._reachable = False
            raise RuntimeError(
                f"{self.base_url} is up but does not look like Juice Shop (title fingerprint miss)"
            )
        self._reachable = True

    def tasks(self) -> list[BenchmarkTask]:
        return list(JUICE_SHOP_TASKS)

    def reset(self) -> None:
        """HTTP 层无通用重置端点 —— 本方法**显式不作为**（fail-closed）。

        污染风险的诚实形态：不假装重置了。容器重置由部署脚本承担
        （`docker restart juice-shop`，镜像数据卷无状态化时重启即复位）；
        该事实通过 `reset_is_external=True` 暴露给评测驱动器/调用方 ——
        报告的复现清单必须记录「重置方式：容器重启（外部）」。
        """
        return

    def teardown(self) -> None:
        """无副作用清理（靶场常驻，供下一场评测复用）。"""
        self._reachable = None
