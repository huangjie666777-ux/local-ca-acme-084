# Local Test CA

本机联调用的证书签发与吊销后端（Python 3.10 + FastAPI + cryptography）。
服务只绑定 `127.0.0.1`，无前端，数据与私钥均保存在本机数据目录。

除原有签发/吊销/CRL 接口外，另实现了一个 **RFC 8555 ACME 子集**，
支持自动申领域名证书（HTTP-01 验证）。

## 启动

```sh
.venv/bin/python -m pip install -r requirements.lock.txt

# 默认数据目录为 ./data，可用 LOCAL_CA_DATA_DIR 覆盖
# ACME_CHALLENGE_PORT 指定本机 HTTP-01 应答服务端口（默认 80）
LOCAL_CA_DATA_DIR=./data ACME_CHALLENGE_PORT=8099 \
  .venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

- 数据目录为空时，启动会自动生成 4096 位 RSA 自签根 CA（有效期 10 年）。
- 重启时复用同一 CA 与 SQLite 记录。
- 已有数据库但 CA 私钥/证书缺失、只存在其一、密钥与证书不匹配，或证书与
  数据库绑定的指纹不一致时，服务拒绝启动（`app.ca.CAError`），不会静默换 CA。

## 密钥与数据存放

默认 `./data/`（已在 `.gitignore` 中忽略）：

- `ca_key.pem`：CA 私钥，PKCS#8 PEM、**无口令加密**，文件权限 `0600`，
  仅存本机，不提供任何下载接口；请只在隔离的本机联调环境使用。
- `ca_cert.pem`：CA 证书，权限 `0644`，可通过接口下载。
- `ca.sqlite3`：证书记录、幂等键、吊销状态、CRL 编号，以及 ACME 账号、
  申领、授权记录（WAL 模式）。

## 签发策略

- CSR 必须是合法 PEM 且签名自洽；公钥只接受 RSA，且至少 2048 位。
- 必须携带非空 `subjectAltName`；只允许 DNSName，不允许 IP/URI/邮件等；
  CN 不能代替 SAN。
- DNS 名称按标签匹配，仅接受 `lab.test` 与其任意层级子域
  （如 `api.lab.test`、`a.b.lab.test`）；拒绝通配符，大小写归一。
- `days` 为 1–30 的整数；布尔值（`true`/`false`）与字符串天数一律拒绝。
- 证书有效期不会越过 CA 自身到期时间。
- 签发证书：CA=false、KeyUsage=`digitalSignature,keyEncipherment`、
  EKU 仅 `serverAuth`，并设置规范化后的 SAN、SKI/AKI；不照搬 CSR 中其他扩展。

## 原有接口

| 方法/路径 | 说明 |
| --- | --- |
| `GET /health` | 健康检查 |
| `GET /ca/certificate` | 下载 CA 证书 PEM |
| `POST /certificates` | 提交 `{csr, days, idempotency_key}` 签发 |
| `GET /certificates/{hex_serial}` | 查询证书与吊销状态（JSON） |
| `GET /certificates/{hex_serial}/pem` | 下载证书 PEM |
| `POST /certificates/{hex_serial}/revoke` | 吊销，body 为 `{reason}` |
| `POST /crl/publish` | 发布下一版 CRL（编号原子递增） |
| `GET /crl/current` / `/crl/current.pem` | 查看/下载当前 CRL |

序列号为十六进制正整数。签发接口幂等：同幂等键 + 同 CSR(DER) + 同天数
返回原证书；同键不同内容返回 `409`。并发重试只产生一条记录，签发失败无半成品。

吊销保留首次吊销时间与原因（RFC 5280 原因：`unspecified`、
`key_compromise`、`ca_compromise`、`affiliation_changed`、`superseded`、
`cessation_of_operation`、`certificate_hold`、`privilege_withdrawn`、
`aa_compromise`）。同原因重复调用幂等，不同原因 `409`，未知序列号 `404`，
吊销不可撤回。CRL 由 CA 签名，包含全部吊销记录，`CRLNumber` 持久化递增，
启动时即发布首份空 CRL。

## ACME（RFC 8555 子集）

### 范围

实现：`directory`、`newNonce`、`newAccount`、`newOrder`、授权（authz）与
`http-01` 挑战、`finalize`、证书下载；查询类操作（账号、申领、授权、证书）
一律 POST-as-GET。

不含：密钥更换（key rollover）、账号停用、ACME 协议吊销（吊销仍走原有
`POST /certificates/{serial}/revoke` 接口）。

### 账号与 JWS

- 账号仅接受 RSA ≥ 2048 位、签名算法仅 `RS256`（RSA PKCS#1 v1.5 + SHA-256）。
- 注册用 JWK（`protected.jwk`），其余请求用 kid（`protected.kid`）；
  校验 JWS 签名、`protected.url` 与请求路径一致、nonce 有效。
- 重复公钥注册复用同一账号；资源（申领、授权、证书）仅限本账号访问。
- nonce 有效期 5 分钟，一次性使用；并发重放最多一次成功，其余返回
  `badNonce` 并附带新的 `Replay-Nonce`。

### 申领与验证

- 每次申领一个 `lab.test` 或其子域，拒绝通配符与多标识符；申领 10 分钟过期。
- 仅支持 `http-01`：服务端只连接本机 `127.0.0.1`（端口由
  `ACME_CHALLENGE_PORT` 配置，默认 80），HTTP `Host` 头为目标域名，
  路径沿用协议（`/.well-known/acme-challenge/<token>`）；禁止重定向，
  限制超时（5 秒）与响应大小（64 KiB）。
- 按账号 JWK 指纹校验 `keyAuthorization`（`<token>.<jwk-thumbprint>`）。
- 未验证或已过期不得签发。`finalize` 接收 base64url 编码的 DER CSR，
  其 SAN 必须等于申领域名；复用原有策略与 CA 签发 **7 天**证书。
- 同一申领并发提交相同 CSR 只签一张；不同 CSR 返回 `409 badCSR`。
- 账号、授权、申领、证书关联入 SQLite，重启可继续；签发失败不留孤立证书。

### ACME 接口

| 方法/路径 | 说明 |
| --- | --- |
| `GET /acme/directory` | 目录 |
| `GET|HEAD /acme/new-nonce` | 获取 `Replay-Nonce`（204） |
| `POST /acme/new-account` | 注册/复用账号（JWK），201/200 + `Location` |
| `POST /acme/new-order` | 新建申领，201 + `Location` |
| `POST /acme/order/{id}` | 查询申领（POST-as-GET） |
| `POST /acme/order/{id}/finalize` | 提交 CSR（`{"csr": "<base64url DER>"}`） |
| `POST /acme/order/{id}/cert` | 下载证书链（POST-as-GET） |
| `POST /acme/authz/{id}` | 查询授权（POST-as-GET） |
| `POST /acme/authz/{id}/chall/http-01` | 触发 HTTP-01 验证 |

错误返回 RFC 7807 problem 文档（`application/problem+json`），
类型为 `urn:ietf:params:acme:error:*`。

## curl 演示

### 原有接口

```sh
# 下载 CA 证书
curl -s http://127.0.0.1:8000/ca/certificate -o ca_cert.pem

# 生成带 SAN 的 CSR
openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj '/CN=api.lab.test' \
  -addext 'subjectAltName=DNS:api.lab.test,DNS:lab.test'

# 签发（用 Python 把 PEM 安全编码进 JSON）
python - <<'PY'
import json, urllib.request
payload = {
    "csr": open("server.csr").read(),
    "days": 7,
    "idempotency_key": "demo-1",
}
req = urllib.request.Request(
    "http://127.0.0.1:8000/certificates",
    data=json.dumps(payload).encode(),
    headers={"Content-Type": "application/json"},
)
body = json.load(urllib.request.urlopen(req))
open("server.pem", "w").write(body["certificate"])
print(body["serial"], body["replayed"])
PY

openssl verify -CAfile ca_cert.pem server.pem

# 查询 / 吊销 / CRL
curl -s http://127.0.0.1:8000/certificates/<serial>
curl -s -X POST http://127.0.0.1:8000/certificates/<serial>/revoke \
  -H 'Content-Type: application/json' -d '{"reason":"key_compromise"}'
curl -s -X POST http://127.0.0.1:8000/crl/publish
curl -s http://127.0.0.1:8000/crl/current.pem -o crl.pem
openssl crl -in crl.pem -noout -CAfile ca_cert.pem -text
```

### ACME 自动申领

先启动 CA 与本机 HTTP-01 应答服务，再用演示客户端完成申领：

```sh
# 1. 启动 CA（挑战端口与应答服务一致）
ACME_CHALLENGE_PORT=8099 .venv/bin/python -m uvicorn app.main:app \
  --host 127.0.0.1 --port 8000

# 2. 启动 HTTP-01 应答服务（应答 webroot/.well-known/acme-challenge/）
.venv/bin/python scripts/http01_responder.py --port 8099 --webroot ./webroot

# 3. 运行 ACME 演示客户端（注册账号 -> 新建申领 -> 写挑战应答 -> 验证 -> 签发 -> 下载）
.venv/bin/python scripts/acme_demo.py --server http://127.0.0.1:8000 \
  --domain api.lab.test --webroot ./webroot --out ./issued

# 4. 验证证书链
curl -s http://127.0.0.1:8000/ca/certificate -o ca_cert.pem
openssl verify -CAfile ca_cert.pem ./issued/api.lab.test.pem
```

目录与 nonce 也可直接用 curl 查看：

```sh
curl -s http://127.0.0.1:8000/acme/directory
curl -sI http://127.0.0.1:8000/acme/new-nonce | grep -i replay-nonce
```

## 测试

```sh
.venv/bin/python -m pytest -q
```

测试覆盖：CSR/域名/密钥策略、证书扩展与链验证、幂等与并发去重、
吊销原因冲突、CRL 编号并发一致、重启复用、CA 缺失/不匹配拒绝启动，
以及 ACME 全流程（目录/nonce、账号注册与复用、JWS 签名/URL/nonce 校验、
HTTP-01 成功与失败、finalize 与 SAN 校验、并发同 CSR 去重、账号隔离、
过期拒绝、重启继续）。
