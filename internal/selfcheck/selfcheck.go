// Package selfcheck 执行无需外部依赖的内置自检：通过 httptest 启动真实 HTTP 服务，
// 覆盖密码强度评分、四类别识别、各类策略规则、强度与策略独立性及 HTTP 边界。
// 成功返回 0，任一失败返回 1。
package selfcheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	"task031-password/internal/httpapi"
	"task031-password/internal/password"
)

// Run 执行自检，返回退出码。
func Run() int {
	passed, failed := 0, 0
	check := func(name string, fn func() error) {
		if err := fn(); err != nil {
			failed++
			fmt.Printf("FAIL %-36s %v\n", name, err)
		} else {
			passed++
			fmt.Printf("PASS %s\n", name)
		}
	}

	api := httpapi.New()
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	do := func(method, path, body string) (*http.Response, []byte, error) {
		var r io.Reader
		if body != "" {
			r = bytes.NewReader([]byte(body))
		}
		req, err := http.NewRequest(method, srv.URL+path, r)
		if err != nil {
			return nil, nil, err
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, nil, err
		}
		data, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, data, readErr
	}

	postJSON := func(path string, v any) (int, []byte, error) {
		b, _ := json.Marshal(v)
		resp, body, err := do(http.MethodPost, path, string(b))
		if err != nil {
			return 0, nil, err
		}
		return resp.StatusCode, body, nil
	}

	postRaw := func(path, raw string) (int, []byte, error) {
		resp, b, err := do(http.MethodPost, path, raw)
		if err != nil {
			return 0, nil, err
		}
		return resp.StatusCode, b, nil
	}

	type classesOut struct {
		Upper  bool `json:"upper"`
		Lower  bool `json:"lower"`
		Digit  bool `json:"digit"`
		Symbol bool `json:"symbol"`
	}
	type violationOut struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	type resultOut struct {
		OK         bool           `json:"ok"`
		Score      int            `json:"score"`
		Strength   string         `json:"strength"`
		Length     int            `json:"length"`
		Classes    classesOut     `json:"classes"`
		Violations []violationOut `json:"violations"`
	}

	hasCode := func(v []violationOut, code string) bool {
		for _, x := range v {
			if x.Code == code {
				return true
			}
		}
		return false
	}

	evaluate := func(pw string, p password.Policy) (resultOut, int, error) {
		status, body, err := postJSON("/evaluate", map[string]any{"password": pw, "policy": p})
		if err != nil {
			return resultOut{}, status, err
		}
		var out resultOut
		if status == http.StatusOK {
			if err := json.Unmarshal(body, &out); err != nil {
				return resultOut{}, status, fmt.Errorf("解码失败: %v body=%s", err, body)
			}
		}
		return out, status, nil
	}

	check("健康检查", func() error {
		resp, _, err := do(http.MethodGet, "/healthz", "")
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("status=%d", resp.StatusCode)
		}
		return nil
	})

	check("基础评分与四类别识别", func() error {
		out, status, err := evaluate("Ab1!", password.Policy{})
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("status=%d", status)
		}
		if out.Score != 52 || out.Strength != "一般" || out.Length != 4 {
			return fmt.Errorf("out=%+v", out)
		}
		if !out.Classes.Upper || !out.Classes.Lower || !out.Classes.Digit || !out.Classes.Symbol {
			return fmt.Errorf("classes=%+v 应四类齐全", out.Classes)
		}
		if !out.OK || len(out.Violations) != 0 {
			return fmt.Errorf("空策略应无违规, violations=%v", out.Violations)
		}
		return nil
	})

	check("满分密码很强", func() error {
		out, _, err := evaluate("Ab1!Ab1!Ab1!Ab1!", password.Policy{})
		if err != nil {
			return err
		}
		if out.Score != 100 || out.Strength != "很强" {
			return fmt.Errorf("score=%d strength=%q", out.Score, out.Strength)
		}
		return nil
	})

	check("序列扣分 abc", func() error {
		out, _, err := evaluate("abc", password.Policy{})
		if err != nil {
			return err
		}
		if out.Score != 5 || out.Strength != "弱" {
			return fmt.Errorf("score=%d strength=%q", out.Score, out.Strength)
		}
		return nil
	})

	check("连续重复扣分 aaaaaaaa", func() error {
		out, _, err := evaluate("aaaaaaaa", password.Policy{})
		if err != nil {
			return err
		}
		if out.Score != 30 {
			return fmt.Errorf("score=%d want 30", out.Score)
		}
		return nil
	})

	check("minLength 命中", func() error {
		out, _, err := evaluate("ab", password.Policy{MinLength: 4})
		if err != nil {
			return err
		}
		if out.OK || !hasCode(out.Violations, "MIN_LENGTH") {
			return fmt.Errorf("应触发 MIN_LENGTH, ok=%v v=%v", out.OK, out.Violations)
		}
		return nil
	})

	check("maxLength 命中", func() error {
		out, _, err := evaluate("abcd", password.Policy{MaxLength: 3})
		if err != nil {
			return err
		}
		if out.OK || !hasCode(out.Violations, "MAX_LENGTH") {
			return fmt.Errorf("应触发 MAX_LENGTH, v=%v", out.Violations)
		}
		return nil
	})

	check("requireUpper 命中", func() error {
		out, _, err := evaluate("abc", password.Policy{RequireUpper: true})
		if err != nil {
			return err
		}
		if out.OK || !hasCode(out.Violations, "REQUIRE_UPPER") {
			return fmt.Errorf("应触发 REQUIRE_UPPER, v=%v", out.Violations)
		}
		return nil
	})

	check("requireLower 命中", func() error {
		out, _, err := evaluate("ABC", password.Policy{RequireLower: true})
		if err != nil {
			return err
		}
		if out.OK || !hasCode(out.Violations, "REQUIRE_LOWER") {
			return fmt.Errorf("应触发 REQUIRE_LOWER, v=%v", out.Violations)
		}
		return nil
	})

	check("requireDigit 命中", func() error {
		out, _, err := evaluate("abc", password.Policy{RequireDigit: true})
		if err != nil {
			return err
		}
		if out.OK || !hasCode(out.Violations, "REQUIRE_DIGIT") {
			return fmt.Errorf("应触发 REQUIRE_DIGIT, v=%v", out.Violations)
		}
		return nil
	})

	check("requireSymbol 命中", func() error {
		out, _, err := evaluate("abc", password.Policy{RequireSymbol: true})
		if err != nil {
			return err
		}
		if out.OK || !hasCode(out.Violations, "REQUIRE_SYMBOL") {
			return fmt.Errorf("应触发 REQUIRE_SYMBOL, v=%v", out.Violations)
		}
		return nil
	})

	check("minClasses 满足", func() error {
		out, _, err := evaluate("Abcdefg1", password.Policy{MinClasses: 3})
		if err != nil {
			return err
		}
		if !out.OK {
			return fmt.Errorf("应通过, v=%v", out.Violations)
		}
		return nil
	})

	check("minClasses 不满足", func() error {
		out, _, err := evaluate("Abcdefg", password.Policy{MinClasses: 3})
		if err != nil {
			return err
		}
		if out.OK || !hasCode(out.Violations, "MIN_CLASSES") {
			return fmt.Errorf("应触发 MIN_CLASSES, v=%v", out.Violations)
		}
		return nil
	})

	check("maxConsecutive 命中", func() error {
		out, _, err := evaluate("aabbb", password.Policy{MaxConsecutive: 2})
		if err != nil {
			return err
		}
		if out.OK || !hasCode(out.Violations, "MAX_CONSECUTIVE") {
			return fmt.Errorf("应触发 MAX_CONSECUTIVE, v=%v", out.Violations)
		}
		return nil
	})

	check("maxConsecutive 不命中", func() error {
		out, _, err := evaluate("aabb", password.Policy{MaxConsecutive: 2})
		if err != nil {
			return err
		}
		if !out.OK {
			return fmt.Errorf("应通过, v=%v", out.Violations)
		}
		return nil
	})

	check("noSequential 命中 abc", func() error {
		out, _, err := evaluate("abc", password.Policy{NoSequential: true})
		if err != nil {
			return err
		}
		if out.OK || !hasCode(out.Violations, "SEQUENTIAL") {
			return fmt.Errorf("应触发 SEQUENTIAL, v=%v", out.Violations)
		}
		return nil
	})

	check("noSequential 命中 cba", func() error {
		out, _, err := evaluate("cba", password.Policy{NoSequential: true})
		if err != nil {
			return err
		}
		if out.OK || !hasCode(out.Violations, "SEQUENTIAL") {
			return fmt.Errorf("应触发 SEQUENTIAL, v=%v", out.Violations)
		}
		return nil
	})

	check("noSequential 不命中 a1b2c3", func() error {
		out, _, err := evaluate("a1b2c3", password.Policy{NoSequential: true})
		if err != nil {
			return err
		}
		if !out.OK {
			return fmt.Errorf("应通过, v=%v", out.Violations)
		}
		if hasCode(out.Violations, "SEQUENTIAL") {
			return fmt.Errorf("a1b2c3 不应触发 SEQUENTIAL")
		}
		return nil
	})

	check("noSequential 不命中 Abc", func() error {
		out, _, err := evaluate("Abc", password.Policy{NoSequential: true})
		if err != nil {
			return err
		}
		if hasCode(out.Violations, "SEQUENTIAL") {
			return fmt.Errorf("Abc 不应触发 SEQUENTIAL, v=%v", out.Violations)
		}
		return nil
	})

	check("blacklist 大小写不敏感", func() error {
		out, _, err := evaluate("xAdMiN123", password.Policy{Blacklist: []string{"admin"}})
		if err != nil {
			return err
		}
		if out.OK || !hasCode(out.Violations, "BLACKLISTED") {
			return fmt.Errorf("应触发 BLACKLISTED, v=%v", out.Violations)
		}
		return nil
	})

	check("blacklist 不命中", func() error {
		out, _, err := evaluate("xyz", password.Policy{Blacklist: []string{"admin"}})
		if err != nil {
			return err
		}
		if !out.OK {
			return fmt.Errorf("应通过, v=%v", out.Violations)
		}
		return nil
	})

	check("强度与策略独立", func() error {
		r1, _, err := evaluate("password", password.Policy{})
		if err != nil {
			return err
		}
		r2, _, err := evaluate("password", password.Policy{Blacklist: []string{"password"}})
		if err != nil {
			return err
		}
		if r1.Score != r2.Score || r1.Strength != r2.Strength {
			return fmt.Errorf("评分应相同: %d/%q vs %d/%q", r1.Score, r1.Strength, r2.Score, r2.Strength)
		}
		if len(r1.Violations) != 0 {
			return fmt.Errorf("空策略应无违规, v=%v", r1.Violations)
		}
		if !hasCode(r2.Violations, "BLACKLISTED") {
			return fmt.Errorf("blacklist 应触发 BLACKLISTED, v=%v", r2.Violations)
		}
		return nil
	})

	check("policy 缺省仅评分", func() error {
		status, body, err := postJSON("/evaluate", map[string]any{"password": "abc"})
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("status=%d body=%s", status, body)
		}
		var out resultOut
		if err := json.Unmarshal(body, &out); err != nil {
			return err
		}
		if !out.OK || len(out.Violations) != 0 {
			return fmt.Errorf("缺省策略应无违规, v=%v", out.Violations)
		}
		if out.Score != 5 {
			return fmt.Errorf("score=%d want 5", out.Score)
		}
		return nil
	})

	check("空串密码可评估", func() error {
		out, status, err := evaluate("", password.Policy{})
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("status=%d", status)
		}
		if out.Length != 0 || out.Score != 0 || out.Strength != "弱" {
			return fmt.Errorf("out=%+v", out)
		}
		return nil
	})

	check("全策略通过", func() error {
		out, _, err := evaluate("Abcdefg1!", password.Policy{
			MinLength: 8, RequireUpper: true, RequireLower: true,
			RequireDigit: true, RequireSymbol: true, MinClasses: 4,
		})
		if err != nil {
			return err
		}
		if !out.OK {
			return fmt.Errorf("应通过, v=%v", out.Violations)
		}
		return nil
	})

	check("缺少 password 被拒绝", func() error {
		status, body, err := postJSON("/evaluate", map[string]any{"policy": password.Policy{}})
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400 body=%s", status, body)
		}
		return nil
	})

	check("password 非字符串被拒绝", func() error {
		status, _, err := postRaw("/evaluate", `{"password": 123}`)
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400", status)
		}
		return nil
	})

	check("非法 JSON 被拒绝", func() error {
		status, _, err := postRaw("/evaluate", "{not json")
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400", status)
		}
		return nil
	})

	check("多段 JSON 被拒绝", func() error {
		status, _, err := postRaw("/evaluate", `{"password":"a"}{"password":"b"}`)
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400", status)
		}
		return nil
	})

	check("未知字段被拒绝", func() error {
		status, _, err := postRaw("/evaluate", `{"password":"a","extra":1}`)
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400", status)
		}
		return nil
	})

	check("未知策略字段被拒绝", func() error {
		status, _, err := postRaw("/evaluate", `{"password":"a","policy":{"min_length":8}}`)
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400 (snake_case 应被拒)", status)
		}
		return nil
	})

	check("未知路由返回 404", func() error {
		resp, _, err := do(http.MethodGet, "/nope", "")
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusNotFound {
			return fmt.Errorf("status=%d want 404", resp.StatusCode)
		}
		return nil
	})

	fmt.Printf("\n%d passed, %d failed\n", passed, failed)
	if failed > 0 {
		return 1
	}
	return 0
}
