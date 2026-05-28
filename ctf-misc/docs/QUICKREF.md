# CTF Misc Skill - 快速参考

## 目录结构
```
.agent/
└── skills/
    └── ctf-misc-solver/
        ├── SKILL.md       # 核心 Skill 定义（750+ 行）
        ├── README.md      # 使用说明
        └── CHANGELOG.md   # 更新日志
```

## 支持的题型

| 类型 | 覆盖范围 | 关键工具 |
|------|---------|---------|
| 图片隐写** | LSB/EXIF/像素/尺寸/CRC | zsteg, stegsolve, PIL |
| **音频隐写** | 频谱/LSB/SSTV/摩尔斯 | Audacity, sox, ffmpeg |
| 压缩包** | 伪加密/明文攻击/CRC爆破 | 7z, fcrackzip, bkcrack |
| 流量分析** | HTTP还原/USB解析/DNS隧道 | Wireshark, tshark, scapy |
| 内存取证** | 进程/文件/哈希/剪贴板 | Volatility 3, MemProcFS |
| 编码加密** | 多层Base/ROT/古典密码 | CyberChef, Python |

## 内置脚本（8 个）

1. **多层 Base 编码爆破** - 递归解码 Base64/32/Hex/ROT13
2. **PNG 高度修复** - 爆破被篡改的图片尺寸
3. **ZIP 伪加密修复** - 自动检测并清除伪加密标志
4. **频谱图提取** - 从音频生成频谱图
5. **USB 键盘流量解析** - HID 数据转文本
6. **Volatility 快速分析** - 自动化执行 7 个关键插件
7. **内存 Flag 搜索**  - 6 种模式匹配 + mmap 优化
8. **文件批量提取** - 自动提取可疑文件

## 快速开始

### 触发 Skill
```
"帮我分析这个 png，找一下 flag"
"这是一道 CTF Misc 题"
"这个内存镜像怎么分析？"
```

### 内存取证工作流

```bash
# 1. 快速搜索 flag
strings -e l memory.raw | grep -iE "flag|ctf"

# 2. 自动化分析（使用内置脚本 6）
python3 vol_auto.py memory.raw

# 3. 手动深入分析
vol -f memory.raw windows.pslist
vol -f memory.raw windows.filescan | grep -i flag
vol -f memory.raw windows.cmdline
vol -f memory.raw windows.clipboard

# 4. 文件提取（使用内置脚本 8）
./vol_extract.sh memory.raw
```

## Volatility 3 常用插件速查

| 插件 | 用途 | 示例 |
|------|------|------|
| `windows.info` | 系统信息 | 识别 OS 版本 |
| `windows.pslist` | 进程列表 | 查找可疑进程 |
| `windows.pstree` | 进程树 | 查看父子关系 |
| `windows.netscan` | 网络连接 | 提取 IP/端口 |
| `windows.cmdline` | 命令行 | 查看执行命令 |
| `windows.filescan` | 文件扫描 | 查找文件路径 |
| `windows.dumpfiles` | 文件提取 | 导出文件内容 |
| `windows.hashdump` | 密码哈希 | 提取 NTLM 哈希 |
| `windows.clipboard` | 剪贴板 | 查看复制内容 |
| `windows.screenshot` | 屏幕截图 | 恢复屏幕画面 |

## 解题思路

### 标准流程
```
1. 文件类型识别 → file, xxd, binwalk
2. 元数据提取 → exiftool, strings
3. 快速隐写扫描 → zsteg, steghide
4. 分类深入分析 → 根据文件类型选择工具
5. 脚本自动化 → 使用内置脚本或自定义
6. 验证结果 → 匹配 flag 格式
```

### 内存取证流程
```
1. OS 识别 → windows.info / linux.banner
2. 进程分析 → pslist, pstree
3. 网络分析 → netscan, netstat
4. 命令历史 → cmdline, bash
5. 文件搜索 → filescan + grep
6. 敏感数据 → clipboard, hashdump
7. 文件提取 → dumpfiles
8. 字符串搜索 → strings + grep
```

## 高级技巧

### 内存取证专用

```python
# 快速定位 flag（脚本 7）
python3 memory_flag_search.py memory.raw

# 提取特定进程的内存
vol -f memory.raw windows.memmap --pid 1234 --dump

# 搜索特定字符串
vol -f memory.raw windows.strings | grep -i "password"

# 提取注册表键值
vol -f memory.raw windows.registry.printkey --key "Software\Microsoft"
```

### 组合技巧

```bash
# 内存 + 流量：提取网络流量
vol -f memory.raw windows.netscan > connections.txt

# 内存 + 文件：批量提取并分析
vol -f memory.raw windows.dumpfiles --dump-dir ./files
grep -r "flag" ./files

# 内存 + 编码：提取并解码
vol -f memory.raw windows.clipboard | base64 -d
```

## 工具安装

### Volatility 3 (推荐)
```bash
# Python 安装
pip3 install volatility3

# 或使用独立版本
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
```

### 其他必备工具
```bash
# Ubuntu/Debian
apt install binwalk foremost exiftool strings file

# 隐写工具
gem install zsteg
apt install steghide

# 流量分析
apt install wireshark tshark
```

## 参考资源

- [Volatility 3 文档](https://volatility3.readthedocs.io/)
- [CTF Wiki - Misc](https://ctf-wiki.org/misc/introduction/)
- [CyberChef](https://gchq.github.io/CyberChef/)
- [Aperi'Solve](https://www.aperisolve.com/)
