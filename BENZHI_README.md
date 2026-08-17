# task031-password

这是一个纯 Go 的密码强度评估与策略校验 HTTP 服务，提供密码评分、字符类别识别、策略违规检测和健康检查能力，不依赖数据库或外部服务。

## 标准命令

```bash
GOTOOLCHAIN=local go test -count=1 ./...
GOTOOLCHAIN=local go vet ./...
GOTOOLCHAIN=local go build ./...
GOTOOLCHAIN=local go run . --smoke-test
GOTOOLCHAIN=local go run . server --addr :8080
```

`--smoke-test` 使用 httptest 覆盖核心 HTTP 行为并自行退出；服务模式启动后监听 HTTP。

## Benzhi Docker

`build_benzhi_docker.sh` 使用 `benzhi.Dockerfile` 构建镜像，参数依次为镜像名和平台，默认值为 `my-project` 与 `linux/amd64`。例如：

```bash
bash build_benzhi_docker.sh task031-password linux/amd64
docker run --rm -it task031-password:latest
```

容器启动后进入 Bash shell；项目构建步骤在镜像构建阶段执行。
