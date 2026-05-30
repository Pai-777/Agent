# 模块 03：shell 稳定化 → 提权

固定动作：
1. 升级 shell
2. 环境枚举
3. 查 SUID / 可写 root 文件 / capabilities / cron / 服务配置
4. 判断是否容器
5. 再决定是否跑内核 POC

注意：
- 先做前置条件探测
- 读 root 文件 ≠ root shell
- 本地自定义 SUID 要拉回逆向
