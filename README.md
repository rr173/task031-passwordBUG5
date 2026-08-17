# task031-password

密码强度评估与策略校验服务。纯标准库实现，无外部依赖。

## 接口

- `POST /evaluate`：请求体 `{"password": string, "policy": 对象}`，policy 可缺省。返回强度评分、等级、类别构成与违规列表。
- `GET /healthz`：健康检查。

## 运行

```bash
# 启动 HTTP 服务
go run . server --addr :8080

# 内置自检（自行退出，退出码 0 表示通过）
go run . --smoke-test
```

## 策略字段

`minLength`、`maxLength`、`requireUpper/Lower/Digit/Symbol`、`minClasses`、`maxConsecutive`、`noSequential`、`blacklist`，均可选，零值表示不约束。
