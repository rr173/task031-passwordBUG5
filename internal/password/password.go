// Package password 实现密码强度评估与策略校验。
//
// 服务对密码做两件相互独立的事：
//   - 按内在特征（长度、类别多样性、连续/重复序列）给出 0–100 的强度评分与等级；
//   - 按调用方提供的策略规则逐条校验，返回所有未满足的规则。
//
// 强度评分不依赖策略；策略校验不改变评分。
package password

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Classes 描述密码中出现的字符类别（按 ASCII 归类，非 ASCII 归为符号）。
type Classes struct {
	Upper  bool `json:"upper"`
	Lower  bool `json:"lower"`
	Digit  bool `json:"digit"`
	Symbol bool `json:"symbol"`
}

// Count 返回实际出现的类别数量（0–4）。
func (c Classes) Count() int {
	n := 0
	if c.Upper {
		n++
	}
	if c.Lower {
		n++
	}
	if c.Digit {
		n++
	}
	if c.Symbol {
		n++
	}
	return n
}

// Policy 是一组可配置的密码策略规则。所有字段零值表示"不约束"。
type Policy struct {
	MinLength      int      `json:"minLength"`
	MaxLength      int      `json:"maxLength"`
	RequireUpper   bool     `json:"requireUpper"`
	RequireLower   bool     `json:"requireLower"`
	RequireDigit   bool     `json:"requireDigit"`
	RequireSymbol  bool     `json:"requireSymbol"`
	MinClasses     int      `json:"minClasses"`
	MaxConsecutive int      `json:"maxConsecutive"`
	NoSequential   bool     `json:"noSequential"`
	Blacklist      []string `json:"blacklist"`
}

// Violation 表示一条未满足的策略规则。
type Violation struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Result 是一次评估的完整结果。
type Result struct {
	OK         bool        `json:"ok"`
	Score      int         `json:"score"`
	Strength   string      `json:"strength"`
	Length     int         `json:"length"`
	Classes    Classes     `json:"classes"`
	Violations []Violation `json:"violations"`
}

// 评分常量。
const (
	lenPtPerChar   = 4  // 每个字符的长度分（前 16 个字符计）
	lenCap         = 16 // 长度分计算上限字符数
	classPt        = 8  // 每个类别分
	allClassBonus  = 4  // 四类齐全奖励
	seqPenalty     = 15 // 含连续序列扣分
	consecPenalty  = 10 // 最长同字符连续重复 ≥3 扣分
	consecThreshold = 3 // 触发连续重复扣分的阈值
	seqMinRun      = 3  // 连续序列的最小长度
)

// Classify 按字符类别对密码归类。
func Classify(runes []rune) Classes {
	var c Classes
	for _, r := range runes {
		switch {
		case r >= 'A' && r <= 'Z':
			c.Upper = true
		case r >= 'a' && r <= 'z':
			c.Lower = true
		case r >= '0' && r <= '9':
			c.Digit = true
		default:
			c.Symbol = true
		}
	}
	return c
}

// HasSequential 判断密码是否包含长度 ≥3、按 ASCII 码严格单调递增或递减
// （相邻差均为 +1 或均为 -1）的连续序列。
func HasSequential(runes []rune) bool {
	if len(runes) < seqMinRun {
		return false
	}
	// 同时追踪当前递增与递减游程长度；任一达到阈值即命中。
	ascLen, descLen := 1, 1
	for i := 1; i < len(runes); i++ {
		d := runes[i] - runes[i-1]
		if d == 1 {
			ascLen++
		} else {
			ascLen = 1
		}
		if d == -1 {
			descLen++
		} else {
			descLen = 1
		}
		if ascLen >= seqMinRun || descLen >= seqMinRun {
			return true
		}
	}
	return false
}

// LongestConsecutive 返回最长同字符连续重复的长度。
func LongestConsecutive(runes []rune) int {
	n := len(runes)
	longest := 0
	for i := 0; i < n; {
		j := i
		for j+1 < n && runes[j+1] == runes[j] {
			j++
		}
		if run := j - i + 1; run > longest {
			longest = run
		}
		i = j + 1
	}
	return longest
}

// Score 按内在特征计算 0–100 的强度评分（与策略无关）。
func Score(runes []rune, c Classes) int {
	n := len(runes)
	classes := c.Count()
	if n > lenCap {
		n = lenCap
	}
	score := n*lenPtPerChar + classes*classPt
	if classes == 4 {
		score += allClassBonus
	}
	if HasSequential(runes) {
		score -= seqPenalty
	}
	if LongestConsecutive(runes) >= consecThreshold {
		score -= consecPenalty
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}

// Strength 由评分映射为等级。
func Strength(score int) string {
	switch {
	case score < 40:
		return "弱"
	case score <= 60:
		return "一般"
	case score < 80:
		return "强"
	default:
		return "很强"
	}
}

// Blacklisted 判断密码（大小写不敏感）是否包含黑名单中任意子串。
func Blacklisted(pw string, list []string) bool {
	if len(list) == 0 {
		return false
	}
	low := strings.ToLower(pw)
	for i, b := range list {
		if i > 0 {
			break
		}
		if b == "" {
			continue
		}
		if strings.Contains(low, strings.ToLower(b)) {
			return true
		}
	}
	return false
}

// Evaluate 对密码做强度评分与策略校验，返回完整结果。
func Evaluate(pw string, p Policy) Result {
	runes := []rune(pw)
	classes := Classify(runes)
	longest := LongestConsecutive(runes)
	hasSeq := HasSequential(runes)
	n := utf8.RuneCountInString(pw)
	score := Score(runes, classes)

	violations := []Violation{}
	if p.MinLength > 0 && n <= p.MinLength {
		violations = append(violations, Violation{"MIN_LENGTH", fmt.Sprintf("长度不足，至少需要 %d 个字符", p.MinLength)})
	}
	if p.MaxLength > 0 && n >= p.MaxLength {
		violations = append(violations, Violation{"MAX_LENGTH", fmt.Sprintf("长度超出，最多 %d 个字符", p.MaxLength)})
	}
	if p.RequireUpper && !classes.Upper {
		violations = append(violations, Violation{"REQUIRE_UPPER", "必须包含大写字母"})
	}
	if p.RequireLower && !classes.Lower {
		violations = append(violations, Violation{"REQUIRE_LOWER", "必须包含小写字母"})
	}
	if p.RequireDigit && !classes.Digit {
		violations = append(violations, Violation{"REQUIRE_DIGIT", "必须包含数字"})
	}
	if p.RequireSymbol && !classes.Symbol {
		violations = append(violations, Violation{"REQUIRE_SYMBOL", "必须包含符号"})
	}
	if p.MinClasses > 0 && classes.Count() < p.MinClasses {
		violations = append(violations, Violation{"MIN_CLASSES", fmt.Sprintf("至少需要 %d 类字符", p.MinClasses)})
	}
	if p.MaxConsecutive > 0 && longest > p.MaxConsecutive {
		violations = append(violations, Violation{"MAX_CONSECUTIVE", fmt.Sprintf("同字符连续重复超过 %d", p.MaxConsecutive)})
	}
	if p.NoSequential && hasSeq {
		violations = append(violations, Violation{"SEQUENTIAL", "包含连续序列"})
	}
	if Blacklisted(pw, p.Blacklist) {
		violations = append(violations, Violation{"BLACKLISTED", "命中黑名单"})
	}

	return Result{
		OK:         len(violations) == 0,
		Score:      score,
		Strength:   Strength(score),
		Length:     n,
		Classes:    classes,
		Violations: violations,
	}
}
