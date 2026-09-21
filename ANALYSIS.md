# memguard 实现分析：LockedBuffer 与 Enclave 的生命周期

本文面向新贡献者，从公开入口追踪到核心内存分配与平台适配层，说明内存所有权、
保护位（protection bits）与清零责任在每一步如何变化。所有结论均附文件与行号；
`memcall` 指 `go.mod:5` 锁定的依赖 `github.com/awnumar/memcall v0.5.0`。

## 1. 调用链总览

```
公开 API (包 memguard)                核心层 (core)                  平台层 (memcall → OS)
------------------------------        --------------------------     ------------------------------------
NewBuffer            buffer.go:34     NewBuffer        core/buffer.go:46   Alloc   memcall_unix.go:35  (mmap)
Freeze/Melt          buffer.go:231,236 freeze/melt     core/buffer.go:121,146 Protect memcall_unix.go:68 (mprotect)
Move/Copy            buffer.go:280,259 Move/Copy       core/crypto.go:123,112
Destroy              buffer.go:333    destroy          core/buffer.go:189  Unlock/Free memcall_unix.go:26,50
Seal                 buffer.go:245    Seal             core/enclave.go:77
Open                 enclave.go:42    Open             core/enclave.go:107
Purge/SafeExit/...   memguard.go:28,42 Purge/Exit/Panic core/exit.go:17,65,84
CatchSignal          signals.go:32    (调用 core.Exit)
```

- 平台分支：Unix 通用实现 `memcall_unix.go`（`mlock`/`munlock`/`mmap`/`munmap`/`mprotect`，
  并在 `memcall_unix.go:15` 先 `MADV_DONTDUMP` 再 `mlock`）；Darwin 分支
  `memcall_darwin.go:13,31,46,64`；Windows 分支 `memcall_windows.go:15,32,50,68`
  （`VirtualLock`/`VirtualAlloc`/`VirtualFree`/`VirtualProtect`，`DisableCoreDumps`
  在 `memcall_windows.go:89` 是空操作）。进程启动时 `core/init.go:7-9` 调用
  `memcall.DisableCoreDumps()` 关闭 core dump（`memcall_unix.go:89` 用
  `RLIMIT_CORE=0` 实现）。
- 页大小取自 `core/auxiliary.go:9`，向上取整在 `core/auxiliary.go:13`。

## 2. 内存布局（core/buffer.go:27-41, 46-101）

`core.NewBuffer(size)` 一次 `memcall.Alloc` 映射 `2*pageSize + roundToPageSize(size)`
字节（core/buffer.go:56-57），布局为：

```
[ preguard 页 ][ inner 页(可寻址数据区)              ][ postguard 页 ]
 NoAccess       canary 填充 | data (末尾 size 字节)    NoAccess
```

- `data` 指向 inner 末尾的 `size` 字节（core/buffer.go:63）；canary 是 inner 开头
  `innerLen-size` 字节（core/buffer.go:71），用随机数填充（core/buffer.go:79）并复制
  进两个 guard 页作为可信参照（core/buffer.go:82-83）。
- inner 页被 `mlock` 锁定（core/buffer.go:74），guard 页被设为 `NoAccess`
  （core/buffer.go:86-91）。guard 页**不**锁定，因为它们不存敏感数据。
- 每个存活 buffer 登记到全局 `buffers` 列表（core/buffer.go:98, 264-320），供
  Purge/Exit 枚举。

## 3. 状态转换序列

### 序列 A：NewBuffer → Freeze → Melt → Move → Destroy

| 步骤 | 可读 | 可写 | 已 mlock | Go slice 别名 | 释放责任 |
|---|---|---|---|---|---|
| `NewBuffer(n)` buffer.go:34 → core/buffer.go:46 | 是（inner） | 是 | 是（core/buffer.go:74） | `b.data` 由 `Bytes()` 暴露（buffer.go:368） | 调用方须 `Destroy`（buffer.go:15 注释） |
| `Freeze()` buffer.go:231 → core/buffer.go:121 | 是 | **否**（`Protect(inner, ReadOnly)` core/buffer.go:130） | 是 | 别名仍存在，但写入会触发页错误 | 同上 |
| `Melt()` buffer.go:236 → core/buffer.go:146 | 是 | 是（`Protect(inner, ReadWrite)` core/buffer.go:155） | 是 | 别名恢复可写 | 同上 |
| `Move(src)` buffer.go:280 → core/crypto.go:123 | 是 | 是 | 是 | `src`（调用方持有的外部 slice）被清零（core/crypto.go:125） | 同上；`src` 由调用方自行释放 |
| `Destroy()` buffer.go:333 → core/buffer.go:189 | 否 | 否 | **否**（`Unlock` core/buffer.go:221） | 字段全部置 nil（core/buffer.go:231-238）；**调用方私藏的旧 slice 成为悬垂别名** | `memcall.Free` 解除映射（core/buffer.go:226），并从全局列表移除（core/buffer.go:186） |

`Destroy` 内部顺序（core/buffer.go:204-238）：先把整段内存改回 RW（204）→ 清零
`data`（210）→ 校验 canary（213，失败则返回错误并触发 `Panic`）→ 清零整段内存
（218）→ `munlock`（221）→ `munmap`/`VirtualFree`（226）→ 字段置 nil。重复调用是
安全的：持锁后检查 `alive`（core/buffer.go:195-201），已销毁则直接返回。

### 序列 B：NewBufferFromBytes → Seal → Open → Destroy

| 步骤 | 明文位置 | 保护状态 | 释放/清零责任 |
|---|---|---|---|
| `NewBufferFromBytes(src)` buffer.go:48 | 复制进新 LockedBuffer（`Move` buffer.go:56）后 `Freeze`（buffer.go:59） | inner 只读、已锁定 | 调用方持有的 `src` 被 `Move` 清零（core/crypto.go:125） |
| `Seal()` buffer.go:245 → core/enclave.go:77 | 密文存入 `Enclave.ciphertext`（core/enclave.go:38）；密钥取自 Coffer 视图（core/enclave.go:54） | 先 `Melt`（core/enclave.go:83），`NewEnclave` 内清零明文（core/enclave.go:69），随后整个 Buffer 被 `Destroy`（core/enclave.go:96） | 密钥视图 `k.Destroy()`（core/enclave.go:66）；旧句柄死亡，再 `Seal` 返回 nil（buffer.go:248-250） |
| `Open()` enclave.go:42 → core/enclave.go:107 | 新建 LockedBuffer 承接明文（core/enclave.go:109），`secretbox.Open` 解密（core/crypto.go:72）后 `Move` 进 buffer 并清零临时明文 `m`（core/crypto.go:74） | 返回前 `Freeze`（enclave.go:50） | 密钥视图销毁（core/enclave.go:127）；调用方负责 `Destroy` 返回的 buffer |
| `Destroy()` | 同序列 A | 同序列 A | 同序列 A |

Enclave 本身只是普通 Go 堆上的密文（core/enclave.go:37-39），不含明文，因此不受
mlock/guard 保护；其机密性由会话密钥（Coffer，core/coffer.go:18-25，密钥分片存放并
每 500ms rekey，core/coffer.go:36-44, 99-126）和 secretbox 认证加密
（core/crypto.go:27-44，Overhead 定义在 core/crypto.go:15）保证。

### 序列 C（全局）：Purge / 信号 / Panic

`Purge`（core/exit.go:17-60）：持 `keyMtx` 停住 rekey 与新 enclave 创建（22-27）→
`buffers.flush()` 取走全部存活 buffer（30）→ 逐个 `destroy`（33-34）；若某个
destroy 失败，降级为强制改 RW 后 `Wipe` 数据（41-51），最后汇总错误并 panic（57-59）。
会话密钥随之销毁，下次使用时由 `getOrCreateKey` 重建（core/enclave.go:13-22），因此
**Purge 后旧 Enclave 全部无法解密**（memguard.go:26 注释）。

## 4. Guard page 与 canary：分工与不可替代性

- **Guard page**（core/buffer.go:66-68, 86-91）：硬件级、访问时即时生效。任何对数据区
  前后一整页的读/写都触发页错误，覆盖"线性越界访问紧邻数据区"的威胁（例如调用方对
  `Bytes()` 做越界 slice 运算、相邻代码的 wild pointer）。它防的是**访问本身**，且粒度
  是一整页。
- **Canary**（core/buffer.go:71, 79-83；校验在 core/buffer.go:213）：软件级、Destroy 时
  事后检测。它覆盖 guard page 够不着的区域：inner 页内、`data` 之前的下溢写（落在
  canary 区，不触碰 guard 页，不会 fault）。随机值使攻击者无法伪造，参照副本放在
  NoAccess 的 guard 页里（core/buffer.go:82-83），正常路径无法篡改参照。
- **为何不能互相替代**：guard page 无法发现"写进 inner 页但没越页"的下溢（页内访问
  不 fault）；canary 无法阻止越页访问，也无法在访问发生的当下报警（只在 Destroy 时
  校验），而且对越过 guard 页的远距离野写同样无能为力。一个是即时预防，一个是事后
  取证，互为补充。

## 5. Purge、信号处理与单个 Destroy 的关系

- 单个 `Destroy`（core/buffer.go:181-187）是自包含、幂等的：持互斥锁、检查 `alive`、
  清理并从全局列表摘除。并发调用安全（锁 + alive 检查，core/buffer.go:195-201）。
- `Purge`（core/exit.go:17）= 对所有登记 buffer 批量执行同一套 `destroy` 逻辑 + 轮换
  会话密钥。它**不**与单个 Destroy 冲突：`flush` 先清空列表，之后用户对已销毁句柄再
  调 `Destroy` 只是 no-op。
- 信号处理（signals.go:32-54）：`CatchSignal` 收到信号后先跑用户回调，再调
  `core.Exit(1)`（signals.go:41）；`Exit`（core/exit.go:65-79）销毁会话密钥、销毁所有
  buffer，然后 `os.Exit`。`CatchInterrupt`（signals.go:61）是其 SIGINT 特化。
  `SafePanic`/`core.Panic`（core/exit.go:84-87）先 `Purge` 再 panic，因此 recover 后
  会话仍可用（新密钥已备好）。
- 关系总结：Destroy 是原语；Purge 是"全部 Destroy + 换密钥"；信号/Panic/Exit 是
  "Purge + 终止方式"的组合。三者共用 core/buffer.go:189 的同一条清理路径。

## 6. 并发与边界路径

- **并发 Destroy**：幂等且互斥（见上）。测试 `TestLifecycleRepeatedDestroy` 覆盖。
- **Move 后旧句柄/旧 slice**：`Move` 清零源 slice（core/crypto.go:123-126），调用方
  再读 `src` 只能得到零；`Seal` 后旧 LockedBuffer 句柄已销毁，所有方法退化为 no-op
  （如 `CopyAt` 的 `IsAlive` 检查，buffer.go:267-269）。`NewBufferFromReaderUntil`
  扩容时旧 buffer 先复制后销毁（buffer.go:112-119）。
- **Open 失败时的临时明文**：`core.Open` 先分配 buffer（core/enclave.go:109）再解密；
  认证失败时（core/enclave.go:121-124）**该临时 buffer 与密钥视图都没有被 Destroy 就
  返回了**。缓解因素：解密失败时 `secretbox.Open` 不写输出（core/crypto.go:72-79），
  临时 buffer 内容仍是 Alloc 时的全零，且已登记在全局列表，会被下一次
  `Purge`/`Exit` 回收（core/exit.go:30-34, 70-75）。测试
  `TestLifecycleCorruptedEnclave` 验证失败后会话可用且后续 Purge 不 panic。

## 7. 三个具体风险与复现办法

### 风险 1：平台调用部分成功后缺少回滚

`core.NewBuffer` 中 `Alloc`（core/buffer.go:57）成功之后，若 `Lock`
（core/buffer.go:74）、`Scramble`（79）或两次 `Protect`（86-91）中任何一步失败，
直接 `Panic(err)`，**已 mmap 的内存不会 `Free`**，且因尚未 `buffers.add`
（core/buffer.go:98），Purge 也管不到它——这是一段 Go GC 无法回收的匿名映射泄漏。
两次 `Protect` 之间失败还会留下"只设了一半 guard 页"的中间态。

复现：在子进程中把锁定内存上限调低后构造 buffer，观察映射数量只增不减：

```sh
# Linux: 限制 mlock 额度后运行
bash -c 'ulimit -l 64; go run ./examples/stdin'   # NewBuffer 触发 Panic
# 另开终端观察该进程的映射数：
grep -c '' /proc/<pid>/maps   # Panic 前后对比，匿名映射未回收
# macOS 可用: vmmap <pid> | grep -c 'ALLOCATED'
```

### 风险 2：调用方保留外部 slice 造成悬垂别名

`Bytes()`（buffer.go:368）返回的是受保护内存的真实别名，memguard 无法追踪调用方
持有的副本。`Destroy` 后内存被 `munmap`（core/buffer.go:226），旧 slice 成为悬垂
指针：读写它会 SIGSEGV（不可恢复的进程崩溃），若地址被内核复用则读到无关数据。
Freeze 期间写别名同样会 fault。

复现（必须在子进程里做，因为崩溃不可捕获）：

```go
// 子进程 main:
b := memguard.NewBuffer(8)
alias := b.Bytes()
b.Destroy()
alias[0] = 1 // SIGSEGV: 写入已解除映射的内存
```

安全观测（不崩溃版本，即本仓库测试采用的方式）：`Destroy` 后 `IsAlive()` 为 false、
`Bytes()` 为 nil（`TestLifecycleRepeatedDestroy`），说明库侧句柄已失效，剩余风险
完全在调用方持有的别名上。

### 风险 3：认证失败 / panic 路径留下临时缓冲

如第 6 节所述，`core.Open` 在 `Decrypt` 失败的分支（core/enclave.go:122-124）直接
`return nil, err`，跳过了 `k.Destroy()`（127）和临时 buffer 的销毁。临时 buffer 虽
为全零且已锁定，但它占用 mlock 额度并驻留全局列表，直到 `Purge`/`Exit` 才回收；
反复触发失败 Open 会累积锁定内存。类似地，任何走到 `core.Panic` 的路径
（如 canary 校验失败，core/buffer.go:213-214）都靠 `Purge` 兜底清理。

复现：

```go
e := memguard.NewEnclave([]byte("yellow submarine"))
memguard.Purge()              // 轮换会话密钥，等价于密文被损坏
for i := 0; i < 100; i++ {
    memguard.SafePanic /* 不用 */; _, _ = e.Open() // 每次都泄漏一个临时 buffer
}
// Linux: 观察 /proc/self/status 的 VmLck 随失败次数单调增长
memguard.Purge()              // 全局清理后 VmLck 回落
```

本仓库的 `TestLifecycleCorruptedEnclave` 用公开行为验证该路径：失败 Open 返回
`ErrDecryptionFailed` 与 nil buffer，会话继续可用，最终 `Purge` 无 panic 地完成回收。

## 8. 生命周期测试（lifecycle_test.go）

| 测试 | 覆盖点 |
|---|---|
| `TestLifecycleZeroLength` | 零长度 buffer 是"准销毁"态：所有操作安全 no-op，`Seal` 返回 nil |
| `TestLifecycleRepeatedDestroy` | 重复 Destroy 与并发 Destroy 幂等 |
| `TestLifecycleMoveAndOldHandle` | `Move` 清零源 slice；`Seal` 后旧句柄死亡且 Enclave 仍可打开 |
| `TestLifecycleFreezeMeltCycle` | Freeze/Melt 幂等可循环，数据在周期中保持完整 |
| `TestLifecycleCorruptedEnclave` | 密钥失效（等价密文损坏）→ `Open` 返回 `ErrDecryptionFailed`；失败路径的临时状态可被后续 `Purge` 清理 |

这些测试只使用公开 API，不读取实现私有字段，也不故意触发不可捕获的进程崩溃
（风险 2 的崩溃复现仅作为子进程手工步骤记录在第 7 节）。
