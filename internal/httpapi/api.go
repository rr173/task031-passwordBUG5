// Package httpapi 提供密码强度评估与策略校验服务的 HTTP 接口。
package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"task031-password/internal/password"
)

// ErrBadJSON 表示请求体不是单个合法 JSON 对象。
var ErrBadJSON = errors.New("请求体不是合法的单个 JSON 对象")

// API 是密码评估服务的 HTTP 接口实现。服务无状态：每个请求自带密码与策略。
type API struct{}

// New 创建服务实例。
func New() *API { return &API{} }

// Handler 返回 HTTP 路由。
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("POST /evaluate", a.evaluate)
	return mux
}

// decodeJSON 解码单个 JSON 对象，拒绝多段 JSON 与未知字段。
func decodeJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return ErrBadJSON
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrBadJSON, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return ErrBadJSON
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// evaluateReq 评估请求。Password 用指针以区分缺省与空串。
type evaluateReq struct {
	Password *string          `json:"password"`
	Policy   password.Policy `json:"policy"`
}

func (a *API) evaluate(w http.ResponseWriter, r *http.Request) {
	var req evaluateReq
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Password == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 password 字段"})
		return
	}
	result := password.Evaluate(*req.Password, req.Policy)
	writeJSON(w, http.StatusOK, result)
}
