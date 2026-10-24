// 主题切换（深色默认 / 浅色 / 跟随系统）。
//
// 持久化到 localStorage；首帧之前 index.html 里的内联脚本已把
// data-theme 设好，这里只负责用户切换时的应用与记录。

export type ThemeChoice = "dark" | "light" | "system";

const STORAGE_KEY = "aletheia-theme";

export function readThemeChoice(): ThemeChoice {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === "dark" || v === "light" || v === "system") return v;
  } catch {
    // localStorage 不可用（隐私模式等）—— 用默认值，不抛错。
  }
  return "dark"; // 深色是本项目主场景（长时观察，app.css 设计取向）
}

export function applyThemeChoice(choice: ThemeChoice) {
  const resolved =
    choice === "system"
      ? window.matchMedia("(prefers-color-scheme: light)").matches
        ? "light"
        : "dark"
      : choice;
  document.documentElement.dataset.theme = resolved;
  try {
    localStorage.setItem(STORAGE_KEY, choice);
  } catch {
    // 同上：存储失败不影响本次会话的主题生效。
  }
}

/** 主题变化（含系统偏好变化）时的监听注册，返回取消函数。 */
export function watchThemeChange(onChange: () => void): () => void {
  const mq = window.matchMedia("(prefers-color-scheme: light)");
  mq.addEventListener("change", onChange);
  return () => mq.removeEventListener("change", onChange);
}
