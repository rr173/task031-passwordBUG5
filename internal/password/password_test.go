package password

import (
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		pw   string
		want Classes
	}{
		{"abc", Classes{Lower: true}},
		{"ABC", Classes{Upper: true}},
		{"123", Classes{Digit: true}},
		{"!@#", Classes{Symbol: true}},
		{"Ab1!", Classes{Upper: true, Lower: true, Digit: true, Symbol: true}},
		{"café", Classes{Lower: true, Symbol: true}}, // é 归为符号
		{"", Classes{}},
	}
	for _, c := range cases {
		got := Classify([]rune(c.pw))
		if got != c.want {
			t.Errorf("Classify(%q) = %+v, want %+v", c.pw, got, c.want)
		}
	}
}

func TestHasSequential(t *testing.T) {
	yes := []string{"abc", "ABC", "123", "cba", "321", "xyz", "abcdef", "bcba", "x123y", "ab123"}
	no := []string{"a1b2c3", "Abc", "ab12", "password", "a1b2c3", "Ab1!", "CorrectHorse"}
	for _, s := range yes {
		if !HasSequential([]rune(s)) {
			t.Errorf("HasSequential(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if HasSequential([]rune(s)) {
			t.Errorf("HasSequential(%q) = true, want false", s)
		}
	}
}

func TestLongestConsecutive(t *testing.T) {
	cases := []struct {
		pw   string
		want int
	}{
		{"", 0},
		{"abc", 1},
		{"aabbb", 3},
		{"aabb", 2},
		{"aaaaaaaa", 8},
		{"aaabbbccc", 3},
	}
	for _, c := range cases {
		if got := LongestConsecutive([]rune(c.pw)); got != c.want {
			t.Errorf("LongestConsecutive(%q) = %d, want %d", c.pw, got, c.want)
		}
	}
}

func TestScore(t *testing.T) {
	cases := []struct {
		pw        string
		wantScore int
		wantStr   string
	}{
		{"a", 12, "弱"},
		{"Ab1!", 52, "一般"},
		{"Ab1!Ab1!Ab1!Ab1!", 100, "很强"},
		{"abcdefgh", 25, "弱"},       // 含 abc 序列 -15
		{"aaaaaaaa", 30, "弱"},       // 连续重复 8 -10
		{"password", 40, "一般"},
		{"abc", 5, "弱"},             // 12+8-15
		{"123", 5, "弱"},
		{"cba", 5, "弱"},
		{"321", 5, "弱"},
		{"a1b2c3", 40, "一般"},
		{"Abc", 28, "弱"},
		{"CorrectHorseBatteryStaple", 80, "很强"},
	}
	for _, c := range cases {
		runes := []rune(c.pw)
		got := Score(runes, Classify(runes))
		if got != c.wantScore {
			t.Errorf("Score(%q) = %d, want %d", c.pw, got, c.wantScore)
		}
		if s := Strength(got); s != c.wantStr {
			t.Errorf("Strength(%q) = %q, want %q", c.pw, s, c.wantStr)
		}
	}
}

func TestEvaluateViolations(t *testing.T) {
	hasCode := func(v []Violation, code string) bool {
		for _, x := range v {
			if x.Code == code {
				return true
			}
		}
		return false
	}

	type tc struct {
		name string
		pw   string
		p    Policy
		codes []string
		ok    bool
	}
	cases := []tc{
		{"minLength 命中", "ab", Policy{MinLength: 4}, []string{"MIN_LENGTH"}, false},
		{"maxLength 命中", "abcd", Policy{MaxLength: 3}, []string{"MAX_LENGTH"}, false},
		{"requireUpper 命中", "abc", Policy{RequireUpper: true}, []string{"REQUIRE_UPPER"}, false},
		{"requireLower 命中", "ABC", Policy{RequireLower: true}, []string{"REQUIRE_LOWER"}, false},
		{"requireDigit 命中", "abc", Policy{RequireDigit: true}, []string{"REQUIRE_DIGIT"}, false},
		{"requireSymbol 命中", "abc", Policy{RequireSymbol: true}, []string{"REQUIRE_SYMBOL"}, false},
		{"minClasses 不满足", "Abcdefg", Policy{MinClasses: 3}, []string{"MIN_CLASSES"}, false},
		{"minClasses 满足", "Abcdefg1", Policy{MinClasses: 3}, nil, true},
		{"maxConsecutive 命中", "aabbb", Policy{MaxConsecutive: 2}, []string{"MAX_CONSECUTIVE"}, false},
		{"maxConsecutive 不命中", "aabb", Policy{MaxConsecutive: 2}, nil, true},
		{"noSequential 命中", "abc", Policy{NoSequential: true}, []string{"SEQUENTIAL"}, false},
		{"noSequential 不命中", "a1b2c3", Policy{NoSequential: true}, nil, true},
		{"blacklist 命中大小写不敏感", "xAdMiN123", Policy{Blacklist: []string{"admin"}}, []string{"BLACKLISTED"}, false},
		{"blacklist 不命中", "xyz", Policy{Blacklist: []string{"admin"}}, nil, true},
		{"全通过", "Abcdefg1!", Policy{MinLength: 8, RequireUpper: true, RequireLower: true, RequireDigit: true, RequireSymbol: true, MinClasses: 4}, nil, true},
		{"空策略仅评分", "password", Policy{}, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Evaluate(c.pw, c.p)
			if r.OK != c.ok {
				t.Errorf("OK = %v, want %v (violations=%v)", r.OK, c.ok, r.Violations)
			}
			if c.codes == nil {
				if len(r.Violations) != 0 {
					t.Errorf("期望无违规, got %v", r.Violations)
				}
				return
			}
			for _, code := range c.codes {
				if !hasCode(r.Violations, code) {
					t.Errorf("期望违规 %s, got %v", code, r.Violations)
				}
			}
		})
	}
}

func TestScorePolicyIndependent(t *testing.T) {
	// 同一密码，策略是否含 blacklist 不影响评分。
	pw := "password"
	r1 := Evaluate(pw, Policy{})
	r2 := Evaluate(pw, Policy{Blacklist: []string{"password"}})
	if r1.Score != r2.Score || r1.Strength != r2.Strength {
		t.Errorf("评分应与策略无关: r1=%+v r2=%+v", r1, r2)
	}
	if len(r2.Violations) != 1 || r2.Violations[0].Code != "BLACKLISTED" {
		t.Errorf("blacklist 应产生 BLACKLISTED, got %v", r2.Violations)
	}
	if len(r1.Violations) != 0 {
		t.Errorf("空策略应无违规, got %v", r1.Violations)
	}
}

func TestBlacklistEmptyString(t *testing.T) {
	// 黑名单中的空串不应匹配（避免空串子串恒真）。
	if Blacklisted("anything", []string{""}) {
		t.Error("空串不应算命中黑名单")
	}
	if !Blacklisted("xadmin", []string{"admin"}) {
		t.Error("应命中 admin")
	}
}

func TestViolationMessages(t *testing.T) {
	r := Evaluate("a", Policy{MinLength: 4})
	if len(r.Violations) != 1 || !strings.Contains(r.Violations[0].Message, "4") {
		t.Errorf("违规信息应含长度 4, got %+v", r.Violations)
	}
}
