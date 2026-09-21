# memguard 内存生命周期实现说明

本文从公开入口追踪到核心分配层（`core`）与平台适配层（`memcall`），说明
LockedBuffer 与 Enclave 在创建、Freeze/Melt、Move、Destroy、Seal/Open 各阶段中
内存所有权、保护位与清零责任的转移。所有结论均附文件与行号。

## 1. 调用链总览

```
memguard.NewBuffer            buffer.go:34
  └─ core.NewBuffer           core/buffer.go:46
       └─ memcall.Alloc       memcall_unix.go:35  (mmap)   / memcall_windows.go:32 (VirtualAlloc)
       └─ memcall.Lock        memcall_unix.go:13  (mlock)  / memcall_windows.go:14 (VirtualLock)
       └─ memcall.Protect     memcall_unix.go:68  (mprotect)/ memcall_windows.go:68 (VirtualProtect)
```

`LockedBuffer` 只是内嵌 `*core.Buffer` 的薄包装（buffer.go:16-19），所有状态都
在 `core.Buffer` 上：`alive` / `mutable` 标志与 `data`、`memory`、`preguard`、
`inner`、`postguard`、`canary` 六个切片视图（core/buffer.go:27-41）。平台差异全部
收敛在 `memcall` 的 build-tag 文件中：Unix 用 `mmap/mlock/mprotect/munmap`
（memcall_unix.go），Windows 用 `VirtualAlloc/VirtualLock/VirtualProtect/VirtualFree`
（memcall_windows.go），Darwin 单独一份（memcall_darwin.go）。`core/init.go:9-11`
在包初始化时关闭 core dump（`memcall_unix.go:89`，Windows 为 no-op，
`memcall_windows.go:89`）。

## 2. 内存布局

`core.NewBuffer` 分配 `2*pageSize + roundToPageSize(size)` 字节（core/buffer.go:56-57），
布局为：

```
| preguard 页 | inner 页（canary 前缀 | data 后缀） | postguard 页 |
   NoAccess         mlock，可读写/只读切换              NoAccess
```

- `data` 对齐到 inner 区域末尾（core/buffer.go:63），因此 data 之后紧挨 postguard 页；
- `canary` 是 inner 开头到 data 之前的填充区（core/buffer.go:71），长度
  `innerLen - size`；
- 只有 inner 被 mlock（core/buffer.go:74），guard 页不锁；
- canary 用 CSPRNG 填充并复制到两个 guard 页作为校验基准（core/buffer.go:79-83）；
- 两个 guard 页设为 `NoAccess`（core/buffer.go:86-91）；
- 最后置 `alive=true, mutable=true`（core/buffer.go:94-95）并注册进全局列表
  `buffers`（core/buffer.go:98，列表定义 core/buffer.go:13）。

## 3. 状态转换序列

### 序列 A：NewBuffer → Move → Freeze → Melt → Destroy

| 步骤 | 可读 | 可写 | 被锁定(mlock) | 仍有 Go slice 别名 | 最终释放责任 |
|---|---|---|---|---|---|
| `NewBuffer(n)` 返回（buffer.go:34 → core/buffer.go:46） | 是 | 是（`mutable=true`，core/buffer.go:95） | 是（inner，core/buffer.go:74） | 是：`b.data` 及 `Bytes()` 派生切片（core/buffer.go:105-107） | 调用方必须 `Destroy`；否则由 `Purge`/`Exit` 兜底 |
| `Move(src)`（buffer.go:280 → core/crypto.go:123-126） | 是 | 是 | 是 | 是；`src` 别名仍在但内容已被 `Wipe` 清零（core/crypto.go:125） | 不变；`src` 是普通 Go 内存，归 GC |
| `Freeze()`（buffer.go:231 → core/buffer.go:121-137） | 是 | 否（inner 设为 `ReadOnly`，core/buffer.go:130） | 是 | 是，但写入会触发页错误 | 不变 |
| `Melt()`（buffer.go:236 → core/buffer.go:146-161） | 是 | 是（恢复 `ReadWrite`，core/buffer.go:155） | 是 | 是 | 不变 |
| `Destroy()`（buffer.go:333 → core/buffer.go:181-241） | 否 | 否 | 否（`Unlock`，core/buffer.go:221） | 库侧字段全部置 nil（core/buffer.go:230-238）；调用方私藏的旧 slice 头成为悬垂别名 | 本步完成：`Wipe(data)` → 校验 canary → `Wipe(memory)` → `Unlock` → `Free`（core/buffer.go:210-226），并从全局列表移除（core/buffer.go:186） |

要点：`Destroy` 先把全部内存（含 guard 页）恢复为可读写（core/buffer.go:204），
再清零数据、校验 canary（core/buffer.go:213）、清零整段、解锁、释放。已销毁的
buffer 再调 `Destroy`/`Freeze`/`Melt` 都是 no-op（core/buffer.go:199-201、125-127、
150-152）。

### 序列 B：NewBufferFromBytes → Seal → Open → Destroy

| 步骤 | 明文位置 | 保护状态 | 所有权/清零责任 |
|---|---|---|---|
| `NewBufferFromBytes(src)`（buffer.go:48-60） | LockedBuffer（immutable） | `Move` 拷入后 `Freeze`；`src` 被清零 | 调用方持有的 `src` 别名读到的已是零 |
| `Seal()`（buffer.go:245 → core/enclave.go:77-99） | 密文在 `Enclave.ciphertext`（core/enclave.go:36-38） | 先 `Melt`（core/enclave.go:83），`NewEnclave` 加密后 `Wipe` 明文（core/enclave.go:69），再 `Destroy` 整个 buffer（core/enclave.go:96） | LockedBuffer 被消费销毁；Enclave 只是 Go 堆上的密文切片，**不在锁定内存中**，无需清零，归 GC |
| 会话密钥 | `Coffer` 分片存放（core/coffer.go:18-24），`View()` 给出 32 字节副本（core/coffer.go:77-94） | 副本是普通 LockedBuffer | 调用方负责 `Destroy` 副本：`NewEnclave` 在 core/enclave.go:66 销毁，`Open` 在 core/enclave.go:127 销毁 |
| `Open()`（enclave.go:42-55 → core/enclave.go:107-131） | 解密进新 LockedBuffer（core/enclave.go:109、121） | 新 buffer 初始 mutable，memguard 层返回前 `Freeze`（enclave.go:50） | 成功时密钥副本被销毁（core/enclave.go:127）；**失败时见 §5.3 的清理缺口** |
| `Destroy()` | 同序列 A | 同序列 A | 同序列 A |

### 序列 C：Purge / 信号 / SafeExit（全局清理）

`Purge`（memguard.go:28 → core/exit.go:17-60）：持 `keyMtx` 阻止新 enclave
（core/exit.go:22-23），`flush` 全局列表拿到快照（core/exit.go:30），逐个
`destroy`（core/exit.go:34）；单个销毁失败时回退为尽力 `Wipe`（core/exit.go:40-51），
最后汇总错误 panic（core/exit.go:57-59）。`CatchSignal`（signals.go:32-57）在收到
信号后先跑用户 handler 再 `core.Exit(1)`（signals.go:40-41）；`Exit`
（core/exit.go:65-79）销毁会话密钥、销毁快照中所有 buffer 后 `os.Exit`。
`SafePanic`（memguard.go:35-37）先 `Purge` 再 panic（core/exit.go:84-87）。

三者关系：单个 `Destroy` 只清理自己并把自己移出全局列表
（core/buffer.go:186）；`Purge`/`Exit` 是列表级兜底，只处理**仍在列表里**的
buffer。已正常 `Destroy` 的 buffer 不在列表中，不会被重复清理；`destroy` 内部的
`alive` 检查（core/buffer.go:199）提供第二重幂等保证。

## 4. Guard page 与 canary：威胁分工

- **Guard page（硬件、即时、防越界读+写）**：`PROT_NONE`/`PAGE_NOACCESS` 页
  （core/buffer.go:86-91）。任何触及它的读或写立刻触发页错误，把"静默读到相邻
  敏感数据/写穿边界"变成确定性的崩溃。由于 `data` 对齐 inner 末尾
  （core/buffer.go:63），**上溢**（越过 data 尾部）会直接撞上 postguard 页。
- **Canary（软件、事后、只防写）**：inner 内 data 之前的随机填充
  （core/buffer.go:71、79-83），在 `Destroy` 时校验（core/buffer.go:213-215）。
  **下溢**写（越过 data 头部）落在同属 inner 的可写页上，guard 页管不到，只能靠
  canary 在销毁时发现"曾发生过溢出"。

不能互相替代的原因：guard 页无法检测同一可写页区域内的越界写（下溢踩 canary
区不会触发页错误），而 canary 完全不防读（读取不产生任何校验），且只能在
`Destroy` 时事后发现、无法定位事发时刻。两者在方向（上溢/下溢）、机制
（硬件/软件）、时机（即时/事后）上互补。

## 5. 并发与失败路径

### 5.1 并发 Destroy

`destroy` 全程持有 buffer 的写锁（core/buffer.go:195-196），`alive` 检查
（core/buffer.go:199）保证只有一个调用者执行真正的清理，其余为 no-op；
`buffers.remove` 由列表自有的锁保护（core/buffer.go:289-299）。因此多 goroutine
并发 `Destroy` 安全（见 `lifecycle_test.go` 的
`TestLifecycleRepeatedAndConcurrentDestroy`）。

### 5.2 Move 后的旧句柄

`core.Move = Copy + Wipe(src)`（core/crypto.go:123-126）：调用方保留的 `src`
别名读到的是全零——这是**约定语义**，已测。另一类旧句柄是调用方私藏的
`b.Bytes()` 返回值（buffer.go:368-370 直接暴露内部指针，core/buffer.go:105-107）：
`Destroy` 后该别名指向已 `munmap`/`VirtualFree` 的区域，库无法收回调用方手里的
slice 头，读写它是 use-after-free（见 §6 风险 2）。

### 5.3 Open 失败时临时明文的清理路径

`core.Open` 先分配输出 buffer（core/enclave.go:109）并取出密钥副本
（core/enclave.go:115），`Decrypt` 失败时直接 `return nil, err`
（core/enclave.go:122-124）——**此时 `b` 和 `k` 都没有 `Destroy`**。`b` 内容仍
是全零（`Decrypt` 认证失败不产生明文，core/crypto.go:71-79），但 `k` 是明文会话
密钥的副本；两者都已注册在全局列表中，要直到下次 `Purge`/`Exit` 才被清理
（core/exit.go:30-34、65-74）。memguard 层的 `Open` 只是透传错误
（enclave.go:44-48），不做补救。`Decrypt` 成功路径则相反：`Move` 把明文搬进
输出并擦除临时明文（core/crypto.go:74），密钥副本随即销毁
（core/enclave.go:127）。

## 6. 三个具体风险与复现办法

### 风险 1：平台调用部分成功后无回滚

`core.NewBuffer` 中 `Alloc` 成功（core/buffer.go:57）之后，若 `Lock`
（core/buffer.go:74-76）或任一 `Protect`（core/buffer.go:86-91）失败，代码直接
`Panic`，已 `mmap` 的内存不 `munmap`、已设 `NoAccess` 的 preguard 不恢复，且
buffer 尚未加入全局列表（`add` 在 core/buffer.go:98），`Purge` 也扫不到它——
映射与锁计数泄漏。

复现：在子进程中把 mlock 限额降到 0 再分配，观察 panic 后残留映射：

```go
//go:build unix
package main

import (
	"fmt"
	"github.com/awnumar/memguard"
	"golang.org/x/sys/unix"
)

func main() {
	unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: 0, Max: 0})
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("panicked as expected:", r != nil)
			// 此时 /proc/self/maps（Linux）或 vmmap（macOS）中仍可见
			// NewBuffer 分配的匿名映射，且它不在任何全局列表里。
		}
	}()
	memguard.NewBuffer(4096)
}
```

### 风险 2：调用方保留外部 slice 造成的别名

`Bytes()` 返回的是内部区域的真实切片头（buffer.go:368-370），`Destroy` 后调用方
手里的旧别名指向已释放的映射。

复现（会确定性崩溃，因此只作演示、不进测试套件）：

```go
b := memguard.NewBuffer(32)
alias := b.Bytes()
b.Destroy()
_ = alias[0] // SIGSEGV：映射已 munmap；若地址被复用则读到无关数据
```

安全对照（已纳入 `lifecycle_test.go`）：`Move` 之后源切片别名读到全零，因为
`core.Move` 会 `Wipe(src)`（core/crypto.go:125）。缓解方式：不要跨 `Destroy`
保存 `Bytes()`/`Uint64()` 等派生切片；需要长期持有就 `copy` 到普通内存并自行
`WipeBytes`（memguard.go:21-23）。

### 风险 3：认证失败 / panic 路径留下临时缓冲

如 §5.3 所述，`core.Open` 解密失败时泄漏输出 buffer 与明文密钥副本
（core/enclave.go:122-124 缺少清理）；同理 `Coffer.View` 的约定是调用方负责
`Destroy`（core/coffer.go:75-77 的注释），任何在 `Destroy` 前 panic 的调用路径都
会把密钥副本留在全局列表里。

复现：

```go
e := memguard.NewEnclave([]byte("secret"))
memguard.Purge() // 重置会话密钥，使 e 无法解密（memguard.go:26-30）
for i := 0; i < 100; i++ {
	if _, err := e.Open(); err == nil {
		panic("expected decryption failure")
	}
}
// 每次失败的 Open 都向全局 buffers 列表泄漏一个已锁定的 32 字节密钥副本
// 和一个输出 buffer；可通过进程常驻内存/mlock 占用增长观察，
// 或对照 core/enclave.go:121-124 走读确认无 Destroy 调用。
```

## 7. 生命周期验证测试

`lifecycle_test.go` 用公开 API 验证本文结论，不读取私有字段、不触发不可恢复的
进程崩溃：

- `TestLifecycleZeroLength`：`NewBuffer(0)` 返回拟销毁的空 buffer
  （buffer.go:26-28、34-41），`Size()==0`、`IsAlive()==false`，重复 `Destroy`
  安全；`NewEnclave([]byte{})` 返回 nil（enclave.go:19-28，core/enclave.go:44-47）。
- `TestLifecycleRepeatedAndConcurrentDestroy`：重复与并发 `Destroy` 幂等，
  销毁后 `Bytes()` 为 nil（core/buffer.go:199、230-238）。
- `TestLifecycleMoveSemantics`：`Move` 后源被清零（core/crypto.go:123-126）；
  对已销毁 buffer 的 `Move` 是 no-op 且不动源（buffer.go:287-289）。
- `TestLifecycleFreezeMeltCycle`：`Freeze`/`Melt` 幂等且可循环，数据跨循环
  不损坏；销毁后二者为 no-op（core/buffer.go:121-161）。
- `TestLifecycleUndecryptableEnclave`：`Purge` 重置会话密钥后，旧 enclave
  `Open` 返回 `core.ErrDecryptionFailed` 且不交出 buffer（enclave.go:42-55，
  core/crypto.go:76-79）——覆盖认证失败路径而不需要篡改私有密文字段。

运行：`go test ./... -count=1`。
