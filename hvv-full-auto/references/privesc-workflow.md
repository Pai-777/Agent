# Linux / 容器提权工作流

## 第一轮固定枚举

```bash
id
whoami
uname -a
cat /etc/os-release 2>/dev/null
mount
cat /proc/self/status | grep ^Cap
find / -perm -4000 -type f 2>/dev/null
find / -writable -user root -type f 2>/dev/null | head -n 100
cat /proc/1/cmdline
cat /proc/1/cgroup
```

## 优先级决策树

### 1. 自定义 SUID

如果发现非系统默认、路径异常、名字可疑的 SUID：
- 先 `ls -l`、`file`、`strings`；
- 再决定是否复制到本地最小逆向；
- 看它是：
  - 直接读 root 文件；
  - 调用外部程序；
  - 路径/环境变量可控；
  - 只是单纯 flag helper。

**规则：不要把“能读 `/root/flag3.txt`”写成“已拿到 root shell”。**

### 2. root:root 且 world-writable 的文件

如果发现：
- `docker-entrypoint.sh`
- Apache 配置
- 服务脚本
- 启动脚本

必须先验证：
1. 它是否真被 root 进程执行；
2. 什么时候执行；
3. 是否能靠当前路径触发；
4. 写入是否会立即影响现有进程。

不要只因“可写”就直接判定可提权。

### 3. Cron / service / capabilities

看：
- `/etc/crontab`、`/etc/cron.*`
- `getcap -r / 2>/dev/null`
- systemd/service 脚本（若存在）

### 4. 容器环境专项

如果看到：
- overlay 挂载；
- `PID 1` 是 `apache2` / `sh` / 自定义 entrypoint；
- `/proc/1/cgroup` 容器痕迹；

则补做：
- `readlink -f /proc/1/exe`
- `cat /proc/1/cmdline`
- `ls -l /var/run/docker.sock /run/docker.sock`
- `unshare -r id`
- 需要时测试内核接口是否被 seccomp 拦截。

## 内核 / 本地提权 POC 前置检查

### 必查项

1. `/tmp` 是否 `noexec`
2. 是否有可执行写目录
3. `gcc` 是否存在
4. PoC 所需接口是否允许
5. seccomp / 容器是否拦截关键 syscall

### 例子：Copy Fail

如果某 PoC 依赖：
- `socket(AF_ALG, ...)`
- `bind("aead", "authencesn(...)")`

则必须先写最小测试程序验证。

如果最小程序返回：
```text
socket: Operation not permitted
```
说明前置条件不满足，应立即放弃该 PoC，而不是继续上传完整 exp。

### 例子：Dirty Pipe

如果 PoC 会把 suid shell 落到 `/tmp/sh`，而 `/tmp` 是 `noexec`，就要：
- 改落地路径；
- 写到可执行目录；
- 再编译/执行。

## 输出结论格式

提权阶段输出要明确写成下面三类之一：
- 已获得 root shell / `uid=0`
- 已获得 root 文件读取能力，但未获得 root shell
- 提权点存在，但前置条件未满足 / 需要额外触发
