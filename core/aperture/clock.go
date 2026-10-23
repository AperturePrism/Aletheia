package aperture

import "time"

// timeNow 是默认时钟的可注入点。
//
// 单独一个函数而不是直接调 time.Now：测试要固定 recency 打分的输入，
// 而 recency 直接影响排序结果（因此影响"装进哪些实体"）。用真实时钟
// 会让排序测试不可复现（P-5）。
func timeNow() int64 { return time.Now().UnixNano() }
