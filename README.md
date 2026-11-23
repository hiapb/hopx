# HopX

HopX 是 Go + SQLite 的自托管转发面板。Web 页面、规则控制、账户与账务运行在一个容器里。Linux 节点在一个 Go 进程里处理转发和实时探针，入口、中转和出口使用 TLS 或 WSS 上的 GOST Relay。

节点内核锁定 GOST v3.3.3 发行版使用的 `core v0.6.1` 和 `x v0.28.1`，HopX 提供多跳、热更新、配额和自动升级。 [GOST v3.3.3](https://github.com/go-gost/gost/releases/tag/v3.3.3)

## 部署与升级

在已安装 Docker 和 Docker Compose 的服务器上运行下面的命令。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/hiapb/hopx/main/install.sh)
```

首次选 `1) 一键部署`，按提示输入路径、端口和面板 URL。默认安装路径为 `/opt/hopx`。脚本使用 Docker Compose，构建面板镜像以及 Linux amd64、arm64 节点产物。节点从填写的面板 URL 注册和取包，远程安装时该地址须可从节点访问。

安装时设置管理员账号。密码留空会随机生成 32 位，包含大小写字母、数字和特殊字符。脚本在初始化后显示密码，数据库保存密码哈希。面板默认仅监听本机。公网访问使用 HTTPS 反向代理，反向代理需要从不同主机接入时，用 `HOPX_HOST` 指定受信任的监听地址。

升级时运行部署目录里的 `manage.sh`，选择 `2) 升级服务`。在线安装的实例会从 GitHub 获取最新源码。从本地源码安装时，先更新该目录里的代码，再执行升级。面板先备份，待新版通过就绪检查再发布节点版本。节点逐台下载并验证签名。候选版本通过心跳、配置和代表性链路检查后才继续下一台。失败时节点恢复上一版本，面板暂停本次发布并显示原因。管理员可在「节点状态」跳过失败节点后继续，或部署修正后的版本。通常只需在节点机执行首次安装。

主菜单按 nurows 的 1–10 项及 0 退出。第 9、10 项使用本机 curl 或 AWS CLI 进行 FTP/SFTP、S3 备份传输。备份包带加密与完整性校验，恢复需备份对应的 `keys/backup.key`。

## 接入节点和规则

1. 在设备组管理创建入口。直出规则到这一步即可接入入口节点。
2. 链路需要中转或出口时，在设备组设置节点间传输。支持 TLS、首跳 TLS 复用、WS、WSS、HTTP CONNECT 和 HTTPS CONNECT。节点接入时可覆盖设备组默认值。中转地址采用 `host:port`。WS 和 HTTP CONNECT 以明文传输，WSS 和 HTTPS CONNECT 使用 TLS。
3. 在设备组点击「接入节点」，在目标 Linux 服务器执行生成的命令。同一设备组可用同一条命令接入多台机器，每台机器注册为独立节点。直连出口将连接地址留空即可复制通用命令，安装时填入本机的连接地址。「撤销安装命令」使旧命令失效，已注册节点继续运行。
4. 在转发规则页选择入口、监听端口和目标地址。新规则继承入口设备组的 TCP、UDP 或双协议设置，可在高级设置单独覆盖。常用链路可在设备组管理保存为「链式出口」，再由规则选择。授权和扣量按虚拟出口组计算。备用链路在高级设置里配置。普通用户经站点节点转发时，节点只连接公网目标。提供私网专线时，可在对应入口组开启「允许普通用户转发到私网」。
5. 在「节点状态」查看版本、监听数、TCP/UDP 连接数、资源指标和下发结果。

同一台 Linux 机器接入多个节点时，在「接入节点 → 接入选项」分别填写实例名，生成带 `--instance` 的命令。每个实例有独立的 systemd 服务、配置与更新目录。留空使用原有的 `hopx-node.service`。

节点接入时，脚本分别显示注册、面板心跳和配置应用结果。运行 `sudo hopx-node-manage list` 查看本机实例，运行 `sudo hopx-node-manage uninstall` 选择并卸载一个实例。此前已接入的机器可在同一实例重跑接入命令，安装管理入口并检查服务状态。卸载后的节点记录可在面板设备组里移除。

同一入口组保存规则时检查端口池和已分配端口。多个入口实例若绑定同一 IP，请给各入口组配置互不重叠的端口池。出口监听和反向入口监听也需错开占用的端口。节点应用规则时通过实际绑定检查系统端口，管理员可在规则诊断查看失败详情。

规则编辑器的「检查端口」可预览端口分配和监听容量。管理员和设备组所有者还可以查看各入口节点的 TCP、UDP 监听地址及占用状态。该检查反映当时的端口状态，正式保存时会重新校验面板配置。

入口端口池支持单个端口和多个范围，例如 `443,12000-12999`。管理员可创建带证书的共享 TLS 入口，按域名和用户授权子规则。子规则按 SNI 分流，可各自设置目标、ALPN 和回源 TLS，并共用母规则的监听。入口组还支持 UDP 开关、TLS 入站策略、空 SNI 拒绝、域名、HTTP 路径和协议筛选。

面板通过版本化配置管理监听器，复用相同链路的下发数据。修改目标优先复用监听。新端口预检失败时该节点继续运行上一份有效配置。单节点的二进制升级可能影响存量连接。

转发规则行的「生成 HAProxy 配置」可填写多个入口节点并下载配置。将配置加载到独立运行的 HAProxy 后，HAProxy 在健康入口之间分配 TCP 连接。配置按规则的要求发送 Proxy Protocol，UDP 仍通过 HopX 入口。

管理员也可以在转发规则的「转发方式」中选择由节点托管的 **HAProxy TCP** 或 **HAProxy TCP + GOST UDP**。入口节点须能在 `PATH` 中找到 HAProxy 二进制，节点状态的详情页可查看是否就绪。每个节点用一个 HAProxy 进程托管全部 TCP 规则。配置更新时最多并存一个排空连接的旧进程，排空期限为 15 秒。两代进程的连接容量都计入节点的总连接预算。

两种模式的 TCP 均由 HAProxy 从入口直连目标。混合模式的 UDP 可由入口直出，也可通过所选的 GOST 出口路径。需要 TCP 链式出口、TLS 终止或规则限额时，请使用 HopX 内置转发。从内置转发切换到 HAProxy，或切换回来时，先暂停规则并等待入口节点释放监听端口。

## 从 nyanpass 迁移

在 HopX 管理脚本选择 **11) 从 nyanpass 迁移**，也可以直接运行 `bash install.sh migrate`。有两种来源。

- 在线 MySQL 或 MariaDB。填写数据库地址、库名和只读账号，默认验证数据库 TLS。从只读事务读取一致性快照。
- `.sql.gz` 下载链接。粘贴 HTTP 或 HTTPS 链接。脚本下载并还原到临时 MariaDB，再把数据导入 HopX。

迁移目标应为仅有初始管理员的 HopX 实例。脚本会先备份 HopX，导入后保留原 HopX 管理员登录凭据，并在部署目录的 `backups/` 下生成含待核对规则、订单和原节点地址的 JSON 报告。导入的规则处于暂停状态，节点通过 HopX 重新接入。

从一致性备份取得 nyanpass `20261022` 的 SQLite 文件，在独立空库预演。内置映射读取用户、设备组、入口策略、规则与链式出口、套餐、订单、兑换码、佣金记录和站点设置。预演报告列出记录数量、钱包和佣金余额、已计量流量和待发布规则数。

```bash
./bin/hopx-panel --db ./data/rehearsal.db --legacy-db ./nyanpass-copy.db --dry-run
```

可直接在菜单 1 一键安装时导入。以下命令读取独立 SQLite 备份，在安装提示中填写源库已有的管理员账号和新密码。

```bash
HOPX_NYANPASS_DB=/path/to/nyanpass-copy.db bash install.sh
```

用 SQLite `.backup` 生成独立快照。命令行正式导入也可使用预演命令去掉 `--dry-run`，通过 `HOPX_ADMIN` 和 `HOPX_MIGRATION_ADMIN_PASSWORD` 指定管理员和新密码。原库的 64 字符旧哈希还需验证，其余使用旧哈希的账户由管理员重置密码。规则保留原端口，导入后处于暂停状态。节点运行身份通过首次接入建立，反向链路的入口和出口按原拓扑接入后再启用相关规则。

SQLite 源文件可用 `--legacy-schema` 只读导出表结构。MySQL 可通过菜单迁移，或使用 CLI 的 `--legacy-mysql` 和环境变量 `HOPX_LEGACY_MYSQL_DSN`。其他版本可传入 `--legacy-map` 指定字段映射，也可以用 `--import-snapshot` 导入归一化 JSON。PostgreSQL 可在备份副本上使用 nyanpass 官方 `-copy-database` 转为 SQLite。 [导入实现](internal/panel/nyanpass.go) · [官方数据库命令](https://nyanpass.pages.dev/reference/be_command/)

## 本地构建与测试

```bash
npm --prefix web ci
npm --prefix web run build
go test ./...
go build -tags webdist -o bin/hopx-panel ./cmd/hopx-panel
go build -o bin/hopx-node ./cmd/hopx-node
```

本地测试覆盖两跳 TCP 和 UDP、连接存续时修改目标、监听冲突回退、同组多节点注册、流量和支付回调去重。还通过 Docker 实测了面板安装、加密备份恢复、Linux ARM64 节点随面板自动更新和失败回退。容量测试在 1 vCPU、512 MiB 容器中加载 1,000 个监听，完成 400 条 TCP 连接及分批建立的 600 个 UDP 会话。

## 本地验收结果

| 场景 | 结果 |
| --- | --- |
| 单节点预检 | 1,000 个 TCP 监听约 17 MiB RSS。提交 1,025 个监听时保留上一份可用配置。 |
| 会话并发 | 1 vCPU、512 MiB 的 Linux ARM64 隔离容器，加载 1,000 个监听、保持 400 个 TCP 和分批建立的 600 个 UDP 会话，约 60 MiB RSS。 |
| 双跳并发 | HopX 0.1.30，入口、中转、出口各限制为 1 vCPU、512 MiB。入口加载 1,000 条规则，通过反向首跳和 WSS 第二跳，分别完成 400 个 TCP 和 600 个 UDP 会话的回环。 |
| 面板并发 | 50 个模拟节点、1,000 条规则，288 次列表请求 P95 约 25 ms。 |
| 多跳配置 | 1,000 条规则共用反向首跳和 WSS 第二跳，配置从 1,144,838 字节降至 307,695 字节。增量更新后原端口继续转发。 |
| 设备组协议 | Linux ARM64 验证 WS、WSS、HTTP CONNECT 和 HTTPS CONNECT 组合的双跳 TCP、UDP。面板下发继承规则并随入口组切换 TCP 和 UDP。 |
| HAProxy | 3.1 容器校验生成的配置，并通过实际 HAProxy 实例访问双跳 TCP 规则，覆盖 PROXY v2。 |
| 首跳复用 | 两跳链路并发 50 条 TCP 会话，中转节点新增文件描述符从 100 个降到 51 个。 |
| TLS 分流 | 两条 SNI 子规则共用一个监听，拒绝重复及未授权域名。热更后的新连接切换目标，存量连接使用原目标。 |
| 运维 | 四个 Linux ARM64 实例完成签名版本升级、失败回滚、面板重启后保留发布暂停和修正版继续升级。另验证面板重启期间的 TCP 转发、主出口停止后的备用链路、批量新增 20 条规则、加密备份恢复、定时备份菜单以及 FTP、SFTP 与 S3 测试端点传输。 |
| 反向节点心跳 | 1,000 条规则、20 并发请求。50 台模拟节点的请求 P95 从约 53 ms 降至 7 ms，200 台从约 69 ms 降至 9 ms。 |
| 迁移 | 官方 20261022 SQLite 样例库和独立 MariaDB 备份均通过预演与导入。MariaDB 备份含 1,299 条规则，879 条导入后暂停，420 条归档待核对。SQLite 完整性及外键检查通过。 |
| 支付 | 易支付 submit/mapi、EPUSDT、TokenPay、Cryptomus 使用模拟商户回调验证签名、金额和幂等。 |

复现节点长时间压测可在 Linux 上运行以下命令。

```bash
HOPX_LOADTEST=1 HOPX_LOADTEST_DURATION=24h go test -count=1 -v ./internal/node -run '^TestListenerDensityUnderLoad$' -timeout 25h
```

较早构建已通过 24 小时压测，采样 RSS 峰值约 87 MiB。0.1.120 用相同的 1 核、512 MiB 和 1,000 个监听场景复测 5 分钟，维持 400 个 TCP 连接及 600 个 UDP 会话，采样 RSS 峰值约 69.5 MiB。两轮 UDP 队列丢包计数均为 0。现网数据、真实支付和 nyanpass 同规格压测仍需相应测试环境。当前实现使用标准 GOST Relay，旧 `ws2`、`tls_simple`、`http` 私有隧道及旧节点控制协议的互通待验证。原版 `fet` 分类和私有隧道格式仍有差异。HopX 的单跳原生 UDP 使用带预共享密钥的 DTLS，可在出口设备组高级设置中开启。出口需放行与中转 TCP 相同端口的 UDP，支持不超过 8000 字节的单个数据报。链式和反向路径沿用 UDP over TCP。
