[English](README.md) | 简体中文

# go-reliability-patterns

用 Go 实现的三个后端可靠性模式，每个都配有表驱动测试、race detector 运行、基准测试，
以及（针对 redactor 的）模糊测试。每个包都是对我在生产 Go 服务中做过的某个模式的从零
重新实现，用来展示设计本身、它的失效模式和取舍。未使用任何雇主的代码、名称或数据。

| 包 | 模式 | 看点 |
|---|---|---|
| [`redact`](redact) | 以 `io.Writer` 装饰器实现日志脱敏 | 零分配的关键字快速路径、合并后的正则、感知 JSON 的遍历器、经模糊测试验证的不变量 |
| [`rules`](rules) | 按租户的允许/拒绝引擎 | fail-closed 决策、singleflight 填充缓存、缓存空结果、失效竞态 |
| [`idempotent`](idempotent) | 至少一次投递、效果幂等的消费者 | 确定性的键、键与效果在同一事务中提交、重试/退避/死信、按键保序 |

Go 1.22+，优先使用标准库。主模块唯一的依赖是 `golang.org/x/sync`（singleflight）。
SQLite 示例放在独立模块中（[`examples/sqlite`](examples/sqlite)），这样它的驱动不会
进入主 `go.mod`。

```bash
make lint      # gofmt + go vet（两个模块）
make test      # 单元测试，外加 SQLite 集成测试
make race      # 同上，开启 -race
make bench     # 基准测试
make fuzz      # 运行 FuzzRedact 60 秒（FUZZTIME=5m 可跑更久）
make example   # 运行 SQLite 消费者演示
```

---

## redact：在日志中屏蔽敏感信息

`redact.NewWriter(w, nil)` 可以包装任意 `io.Writer`。把它放在 `log/slog`、zap 或
zerolog 的 handler 下面，敏感信息会在日志行离开进程之前被屏蔽：

```go
log := slog.New(slog.NewJSONHandler(redact.NewWriter(os.Stdout, nil), nil))
log.Info("login failed", "user", "bob", "password", "hunter2", "phone", "+65 9123 4567")
// {"time":"...","level":"INFO","msg":"login failed","user":"bob","password":"[REDACTED]","phone":"+65 9*** *567"}
```

它会屏蔽：

- 敏感键的值：`password`、`token`、`secret`、`api_key`、`authorization` 等，覆盖 `key=value`、`key: value`、带引号的值、JSON 字段以及嵌在字符串里的 JSON；
- `Authorization` 头和裸露的 `Bearer` token，保留认证方案（`Bearer [REDACTED]`）；
- URL 中的密码（`postgres://app:[REDACTED]@db/main`）；
- 敏感的查询参数（`?access_token=[REDACTED]&page=2`）；
- 位于电话类键下、或以 `+` 开头书写的电话号码，保留可见的前缀和后缀（`+65 9*** *567`）。始终至少屏蔽四位数字。

### 工作原理

```
一行 ──► 快速路径：小写化写入栈上缓冲区，查找触发关键字
           │ 没有（大多数行）──► 原样写出，0 次分配
           ▼ 有
         合法 JSON？──是──► 遍历器：按键屏蔽值；其余字符串值走自由文本规则
           │ 否
           ▼
         一个合并后的正则（5 条规则合为一个 alternation）──► 改写匹配到的分组
```

- **快速路径。** 每条规则都声明了它匹配时必不可少的字面量，例如它的键名、`bearer`、URL 凭据所需的 `://` 和 `@`，或电话号码所需的「`+` 后跟八位及以上数字」。一次扫描同时检查所有关键字：用每个关键字前两个字节组成的位图，几乎可以跳过所有位置。1 KiB 以内的行会被小写化写入栈上缓冲区，所以干净的行不产生任何分配；有一个测试用 `testing.AllocsPerRun` 断言了这一点。
- **大小写折叠。** Go 的 `(?i)` 使用 Unicode 简单折叠：`ſ`（U+017F）匹配 `s`，开尔文符号（U+212A）匹配 `k`。快速路径也会折叠这两个字符；否则 `paſſword=x` 会跳过快速路径，却能被正则匹配。
- **JSON 遍历器。** 在合法的 JSON 文档中，后面跟着 `:` 的字符串是键，其他字符串都是值。这足以在不使用完整解析器的情况下按键屏蔽值。敏感键的值（字符串、数字、对象或数组）会变成 `"[REDACTED]"`。电话号码会变成数字已屏蔽的字符串。`null`、布尔值和 `""` 保持不变。只替换完整的值 token，而且只用 JSON 字符串替换，所以输出仍是合法 JSON。
- **自由文本。** 五条规则被编译成一个不区分大小写的 alternation。每条规则记录自己要改写哪些捕获组，因此一次扫描就能得到唯一的优先级顺序：最左匹配优先，其次按规则顺序。值的字符类排除了 `\` 和 `"`，所以替换永远不会拆开字符串里的 JSON 转义序列。

### 经模糊测试验证的性质

`FuzzRedact` 在任意输入上检查三个不变量：

1. **快速路径永远不改变结果。** 跳过一行得到的输出，必须与对它运行全部规则得到的输出相同，因此任何触发条件都不会让正则本能捕获的敏感信息漏网。
2. **脱敏是幂等的。** 经过两道脱敏器（先是应用，再是日志 shipper）的日志不会被进一步破坏。
3. **合法的单行 JSON 仍然是合法 JSON。**

种子语料在第一次运行时就发现了一个幂等性 bug：`Authorization: Bearer [REDACTED]` 被再次脱敏成了 `Authorization: [REDACTED] [REDACTED]`。现在键值规则会吃掉已经屏蔽过的值，而不改写它。

### 失效模式与局限

| 情形 | 行为 | 原因 / 缓解 |
|---|---|---|
| 敏感信息被拆到两次 `Write` 调用中 | 漏掉 | 每次调用单独脱敏。slog、zap 和 zerolog 每条记录只调用一次。 |
| 未加引号且含空格或 `,;&` 的值 | 只屏蔽第一部分 | `password=a b` 与「`password=a` 后面跟着其他文本」无法区分。给值加引号，或作为结构化字段记录。 |
| 没有 `+`、也不在电话键下的裸数字 | 不屏蔽 | `91234567` 看起来和订单 ID 或时间戳一样。这里选择了精确率而非召回率。 |
| 用转义写的 JSON 键（`"password"`） | 漏掉 | 键按原始字节匹配。 |
| 电话键对应一个对象（`"phone":{"number":...}`） | 嵌套的键逐个检查 | `number` 不是电话键。用 `WithPhoneKeys` 添加它。 |
| 散文中出现关键字：`refresh token: expired` | 过度脱敏为 `token: [REDACTED]` | 对脱敏器来说，过度脱敏是有意选择的失败方向。 |
| 大量包含关键字的行 | 走慢路径，每行约 50 µs | 见基准测试。缩小键列表，或参见下面的后续计划。 |

### 基准测试

Apple M2，darwin/arm64，Go 1.22.2；取 3 次运行的中位数（`make bench`）。

| 行 | 快速路径（实际采用） | 仅合并正则 | 每条规则一个正则 |
|---|---:|---:|---:|
| 干净的 JSON（275 B） | **837 ns** · 0 次分配 | 89.4 µs | 83.7 µs |
| 干净的文本（162 B） | **445 ns** · 0 次分配 | 53.3 µs | 49.1 µs |
| 含密码和电话的 JSON（222 B） | **3.0 µs** · 0 次分配 | 62.4 µs | 67.4 µs |
| 含 token 和 bearer 的文本（213 B） | 52.5 µs · 8 次分配 | 53.2 µs | 54.6 µs |

在 `slog.NewJSONHandler` 之后，一条干净的记录使用脱敏 writer 时耗时 **1.08 µs**，
不使用时为 0.58 µs，两种情况都是 0 次分配。

这些数字说明：

- **真正起作用的优化是快速路径。** 干净的行比运行正则便宜 100–120 倍。含敏感信息的 JSON 行便宜约 20 倍，因为遍历器只对触发了关键字的字符串值运行正则。
- **在 Go 中合并正则并不划算。** Go 的 `regexp` 没有 DFA。它运行有界回溯器（程序最多 500 条指令）或 Pike VM，两者的开销大致都是*程序大小 × 输入长度*。合并后的程序有 357 条指令；五条规则分别编译，总数也差不多。所以对一个大程序扫一遍，与对五个小程序各扫一遍开销相同。在 RE2/C++ 或 Rust 的 `regex` 中，惰性 DFA 让合并后的扫描在输入长度上接近线性，与规则数量无关。在 Go 里，关键在于快速路径和保持程序精简。把电话模式写成 `+` 并在代码里数数字，而不是用 `{7,14}`，减少了约 170 条指令。
- **快速路径的第一版在时区偏移上失效了。** 它把任何 `+` 后跟数字的情况都当作可能的电话号码，于是每一条带 `+08:00` 时间戳的 slog 行都走了慢路径（每条记录 16 µs）。现在的触发条件要求 `+` 后面有八位数字。

---

## rules：fail-closed 的允许/拒绝引擎

```go
engine := rules.NewEngine(store) // store 加载某个租户的 RuleSet，例如从 SQL 加载
d := engine.Check(ctx, rules.Request{Tenant: "t1", Account: "bob", IP: ip, Location: "SG", BankCard: card})
if !d.Allowed { /* d.Reason、d.RuleID 说明原因 */ }
```

### 评估顺序

1. **规则不可用 → 拒绝。** 存储错误、编译失败的规则集、加载超时或已取消的 context 都会拒绝。`Check` 返回的是 `Decision`，而不是 `(Decision, error)`，所以调用方无法忽略错误后落到「允许」。
2. **允许名单，每次只看一个维度：先账号，再昵称，再 IP/CIDR。** 第一个命中即允许，无论是否存在拒绝规则。
3. **拒绝规则，按优先级从高到低。** 一条规则可以指定账号、昵称、IP/CIDR、IP 归属地和银行卡中的任意子集，并且只有在*全部*匹配时才命中（AND）。优先级相同时按规则 ID 排序，保证决策是确定的。
4. **其余情况允许。**

输入会被规范化：昵称转小写并去除首尾空白，归属地转大写，卡号只保留数字，IPv4 映射的
IPv6 地址被还原（`::ffff:10.0.0.1` 匹配 `10.0.0.0/8`）。`Compile` 会拒绝非法的规则集，
例如没有任何条件的拒绝规则（它会拒绝所有人）或错误的 CIDR。在写入规则时调用它，这样坏
数据永远不会进入读路径。

**缺失信号**是一个显式的选择。默认情况下，如果某个条件针对的字段在请求中缺失（比如没有
归属地），该条件不匹配，因此「拒绝归属地 XX」会放过归属地未知的请求。`WithStrictSignals()`
会反转这一行为，缺失数据即拒绝。两种默认都不是处处正确：严格模式会把一次 geo-IP 故障
变成一次登录故障。

### 缓存

策略按租户编译一次，缓存在 `Cache` 接口之后（内置了 `MemoryCache`；Redis 实现会存储规则
集并重新编译）。

- **并发未命中共享一次加载**（`singleflight`，以租户为键）。加载使用与发起它的调用方解耦的 context（`context.WithoutCancel` 加上自己的超时）。等待者使用 `DoChan` 并在自己的 context 上 select，因此一个调用方放弃，不会让加入同一次 flight 的所有人都失败。
- **空规则集也会被缓存。** singleflight 只合并*并发*的未命中。如果不缓存「没有规则」，一个没有规则的租户每次检查都会打到存储，永远如此。`Cache` 接口区分「已缓存、为空」（`ok == true`）与未命中，空策略使用更短的 TTL（`WithEmptyTTL`），这样即使某次失效丢失，第一条规则也能很快生效。
- **失效不会被进行中的加载撤销。** 在经典的 cache-aside 竞态中，一次加载读到旧规则，管理员写入新规则并删除缓存条目，随后这次加载又把旧规则写了回去。`Invalidate` 会递增该租户的 generation 并调用 `singleflight.Forget`，让新的调用方发起一次新的加载。加载在 `Set` *之后*重新检查 generation，如果变了就删除该条目。之所以在之后而不是之前检查，是为了消除删除恰好落在检查与写入之间的窗口。
- **缓存出错时回退到存储。** 缓存只是优化；缓存故障不能导致拒绝所有人。

解耦的加载 context、空结果缓存以及 `Set` 之后的 generation 检查，都分别经过验证：去掉
它们，看着对应的测试失败。

### 失效模式与取舍

| 情况 | 结果 | 替代方案 |
|---|---|---|
| 存储宕机 | 已缓存的租户在 TTL 到期前继续正常工作，之后被拒绝 | 出错时返回旧数据（stale-if-error）并限制数据年龄：可用性更好，新鲜度更弱 |
| 大量 pod 上的 TTL 同时到期 | 每个 pod 每个租户各加载一次（singleflight 是进程内的） | 给 TTL 加抖动；在到期前提前刷新 |
| 多个 pod 共享一个缓存（如 Redis） | generation 守卫是进程内的，所以另一个 pod 正在进行的加载仍可能写入旧规则 | 带版本号的缓存键、pub/sub 失效，或延迟二次删除 |
| 大规则集 | 拒绝规则按顺序扫描：每次检查 O(rules)。100 条规则且都不匹配时，一次命中缓存的检查耗时 1.25 µs；8 个 goroutine 每秒约可完成 4M 次检查（M2，`make bench`） | 按最具选择性的字段为规则建索引 |
| 允许名单中的账号 | 永不被拒绝，即使来自被拒绝的归属地 | 面向内部和客服账号；审计允许名单的变更 |

---

## idempotent：至少一次投递，效果只发生一次

Broker 会在崩溃、rebalance 或重试后重新投递消息，所以重复是常态。这个包让每条消息的
*效果*只发生一次：

```go
c := idempotent.NewConsumer(store,
	func(m idempotent.Message) (string, error) { return idempotent.Key("invoice-paid", invoiceID(m)), nil },
	handler,
	idempotent.WithRetry(3, idempotent.Backoff{Base: 100 * time.Millisecond, Max: 5 * time.Second, Jitter: 0.5}),
	idempotent.WithDeadLetter(dlq),
	idempotent.WithLanes(8),
)
err := c.Run(ctx, deliveries, func(m idempotent.Message, err error) { if err == nil { ack(m) } })
```

### 幂等键

`Key(namespace, parts...)` 把操作及其业务身份（例如 `("invoice-paid", invoiceID)`）哈希为
`invoice-paid:<32 hex>`。键必须来自消息的*含义*。时间戳、消费时生成的随机 ID 或投递
offset 都会在重新投递时变化，让幂等失去意义。各部分在哈希前会加上长度前缀，因此
`("ab","c")` 与 `("a","bc")` 不同。

### 键与效果一起记录

```
BEGIN
  INSERT INTO processed_messages (idempotency_key, ...) ... ON CONFLICT DO NOTHING
  影响 0 行？→ 已处理过：ROLLBACK，报告重复，ack
  handler 使用同一个事务写入其效果（sqlstore.Tx(ctx)）
COMMIT
```

顺序就是关键所在：

- 先在单独的事务里记录键，然后在执行效果前崩溃：**效果丢失**。重新投递会被当作重复跳过。
- 先执行效果，然后在记录键之前崩溃：**效果发生两次**。
- 两者放在一个事务中：要么都提交，要么都不提交。

当两个消费者同时处理同一个键时（比如在 rebalance 期间），它们会在主键上串行化。第二次
插入会等待第一个事务结束，然后什么也不插入。当效果位于*另一个*系统中时，就没有共享事务。
把幂等键作为那个系统的请求 ID 或事务 ID 传过去，让它在自己那一侧去重，这样整个方案就是
端到端的。

`sqlstore` 支持 SQLite、PostgreSQL（`ON CONFLICT DO NOTHING`）和 MySQL。对 MySQL 它使用
`INSERT IGNORE`，而不是空操作的 `ON DUPLICATE KEY UPDATE k = k`。在驱动开启
`CLIENT_FOUND_ROWS` 标志时，后者对重复行会报告影响了一行，看起来就像一次新插入。而
`INSERT IGNORE` 会把截断之类的错误变成警告，可能悄无声息地把两个长键合并成一个，因此超过
128 字节的键会在查询前被拒绝。`Purge` 删除旧键。键的保留时间要长于可能的最长重新投递
延迟（broker 保留期加上任何重放窗口），否则迟到的重复消息会被再次处理。`examples/sqlite`
在真实的 SQLite 数据库上运行以上全部内容，包括对同一个键的 20 次并发尝试。

### 重试与死信

| 失败 | 处理方式 | 是否 ack？ |
|---|---|---|
| Handler 出错 | 以带上限的指数退避加抖动重试；最后一次尝试后进入死信，并合并每次尝试的错误 | 是，进入死信后 |
| `Permanent(err)`、handler panic，或无法推导出键 | 立即进入死信；重试无济于事 | 是 |
| 存储或提交出错（数据库宕机） | 重试；最后一次尝试后**返回错误，不进入死信** | 否：broker 稍后会重新投递 |
| 死信 sink 失败 | 返回错误 | 否 |
| Context 被取消（关闭） | 立即停止 | 否 |

区别对待存储故障很重要。如果像对待坏消息那样把故障送进死信，一次数据库抖动就会把整个
topic 排空到 DLQ 里。

### 顺序

`Run` 按 `Message.Key`（实体 ID）的 FNV 哈希把每条消息路由到 N 条 lane 之一。一条 lane
一次只处理一条消息，因此同一实体的消息按顺序生效，不同实体则并行处理。在 Kafka 上，生产者
应使用相同的实体 ID 作为消息 key，使 broker 的分区内顺序与消费者的 lane 内顺序一致。没有
key 的消息按轮询分发。

取舍：

- **队头阻塞。** 正在重试的消息会占住它的 lane，也就占住了所有哈希到这条 lane 的键，最长可达整个重试计划的时长。这是按键保序的代价。进程内重试要短，长时间的重试交给延迟 topic 或工作流引擎。
- **死信之后的顺序。** 某个实体的一条消息进入死信后，该实体后续的消息仍会执行，因此这个实体可能跳过一步。更严格的设计会把该键挂起（把它后续的消息也送进 DLQ），直到运维人员处理完毕。
- **Offset 提交。** 使用 lane 时，一个分区的消息会乱序完成。只能提交到每个分区最小的未完成 offset，这部分不包含在本仓库中。

---

## 测试方法

- 每个包都有表驱动单元测试，全部在 `go test -race` 下通过。
- `FuzzRedact` 验证上面的三个性质，另有一张 `TestNoLeak` 表，把同一个敏感信息嵌入十几种形式（请求头、URL、嵌套 JSON、字符串内的 JSON）。
- 并发测试基于阻塞在 channel 上而不是靠 sleep 的 fake：singleflight 把 50 次冷未命中合并为一次加载、leader 被取消而等待者继续存活、失效恰好发生在加载中途。
- 在独立模块中针对真实 SQLite 的集成测试：键与效果一起回滚、同一键的并发尝试、purge，以及把一批消息端到端重放三次。
- `redact`、`rules` 和 `idempotent` 中的可测试示例（`go test` 会检查其输出）展示了公开 API。

## 目录结构

```
redact/               io.Writer 装饰器、JSON 遍历器、模糊测试与基准测试
rules/                带缓存、singleflight 和失效机制的策略编译器与引擎
idempotent/           键推导、Store、MemoryStore、Consumer（重试、DLQ、lane）
idempotent/sqlstore/  面向 SQLite、PostgreSQL 和 MySQL 的 database/sql Store
examples/sqlite/      独立模块：SQLite 集成测试与可运行的演示
```

## 后续计划

- `redact`：按一行中实际出现的关键字集合来编译合并后的正则，这样一行只触发一个键时可以减少慢路径的开销。
- `rules`：带版本化键的 Redis `Cache`，以及 stale-if-error。
- `idempotent`：用于配合 lane 提交 offset 的分区级水位线；PostgreSQL 和 MySQL 集成测试。

## 许可证

MIT
