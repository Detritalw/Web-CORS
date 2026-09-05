# Web-CORS

一个基于 Python `aiohttp` 的本地 CORS 反向代理，支持密码认证、目标白名单、重定向校验、请求限流和内网地址拦截。

## 运行

```bash
python3 -m venv venv
venv/bin/pip install aiohttp
cp config.example.ini config.ini
# 编辑 config.ini，设置随机 token
venv/bin/python proxy.py
```

代理支持两种目标地址格式：

```text
/https://example.com/path
/?url=https%3A%2F%2Fexample.com%2Fpath
```

标准认证方式是请求头：

```http
Authorization: Bearer <token>
```

为了兼容无法自定义请求头的 iframe 导航，也支持 `?key=<token>` 查询参数。代理会转发浏览器发送的 `Cookie`，并将上游 `Set-Cookie` 的域名改为当前代理域名后返回，以便后续请求继续携带会话。生产环境建议优先使用请求头认证，因为 URL 可能被访问日志、浏览器历史或监控系统记录。

## systemd

服务文件示例见 `cors-proxy.service.example`。默认监听 `127.0.0.1:8123`。

## 协议

本项目采用 GNU GPL v3.0，详见 `LICENSE`。
