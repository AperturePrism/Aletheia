import js from "@eslint/js";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";

// Aletheia WebUI 的 ESLint 配置（flat config，ESLint 9）。
//
// 两个本项目特有的规则（不是常规风格偏好）：
//
// 1. no-restricted-syntax 禁止在组件里手工声明"契约镜像类型"。
//    Q14 门禁：前端 TS 类型由 Protobuf 生成（web/src/gen/）。
//    手工另写一份 interface Finding {...} 就是该禁止的行为 ——
//    它会在契约变更时静默失同步（10 §3 P1 契约漂移）。
//
// 2. 禁止 dangerouslySetInnerHTML（docs/07 §T5.2）。
//    目标返回的内容渲染到界面时若执行脚本 = XSS。缓解措施之一是
//    "前端不渲染原始 HTML（一律转义）"，本规则从构建期强制它。
export default tseslint.config(
  { ignores: ["dist/**", "src/gen/**"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["src/**/*.{ts,tsx}"],
    languageOptions: {
      globals: {
        window: "readonly",
        document: "readonly",
        fetch: "readonly",
        WebSocket: "readonly",
        console: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
        setInterval: "readonly",
        clearInterval: "readonly",
        EventSource: "readonly",
        URL: "readonly",
        URLSearchParams: "readonly",
        AbortController: "readonly",
        localStorage: "readonly",
        location: "readonly",
        navigator: "readonly",
        crypto: "readonly",
        TextEncoder: "readonly",
      },
    },
    plugins: {
      "react-hooks": reactHooks,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
      "@typescript-eslint/no-explicit-any": "error",
      "no-restricted-syntax": [
        "error",
        {
          // Q14：契约类型只能来自 src/gen。
          selector: "TSInterfaceDeclaration[id.name=/^(EvidenceEntry|Assertion|Finding|ContextBundle|ScopeCheckResult|EvidenceSpectrum|ToolInvocation|RawOutputRef|SpectrumLine|EntityDraft|ParseQuality|Entity|Relation|Provenance|SideEffectObservation|ReproSpec|GateResult|TerminationRequest|TerminationDecision|Task|TaskGraph|Report|BudgetState|SignedExecId|LeakHit|TokenMapping|Error)$/]",
          message:
            "Q14 门禁：契约类型必须从 web/src/gen（Protobuf 生成物）import，禁止手工重复声明。重复类型会在 05 契约变更时静默失同步（docs/09 R1 / docs/10 P1）。",
        },
        {
          // 07 §T5.2：前端不渲染原始 HTML。
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message:
            "docs/07 §T5.2：目标返回的内容不得作为 HTML 渲染（XSS 攻击面）。请以文本渲染并转义。",
        },
      ],
    },
  },
);
