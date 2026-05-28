---
name: unpacking-skills
description: This is an integration of a packer detection tool and an UPX unpacker tool, used when you need to check for or unpack UPX.
---

# Unpacking Tool

这是一个压缩壳脱壳工具，当检测到程序有压缩壳时调用。常见的压缩壳有UPX,ASPack,PECompact,RLPack,NSPack

## 功能概述

该工具提供两步式脱壳流程：
1. **检测阶段**：使用Detect It Easy (DIE)工具识别壳版本
2. **脱壳阶段**：调用对应工具或者脚本进行自动脱壳

## 目录结构

```
.
├── Detect.py              # 检测脚本
├── Unpack.py              # 脱壳脚本
└── scripts/
    ├── diec/
    │   └── diec.exe       # DIE工具
    └── upx/
        └── upx.exe        # UPX官方脱壳工具
```

## 工作流程

### 第一步：检测UPX版本

使用Python脚本调用 `./scripts/diec/diec.exe` 检测目标文件：

- **检测到具体版本** → 继续执行第二步
- **无法确定版本** → 暂停并提示用户需要手动脱壳

```bash
python Detect.py <target_file>
```

**退出码说明：**
- `0` - 成功检测到UPX版本，可以继续脱壳
- `1` - 非UPX壳或检测失败
- `2` - 检测到UPX但无法确定版本，需要手动处理

### 第二步：执行脱壳

使用Python脚本调用 `./scripts/upx/upx.exe` 进行脱壳：

```bash
python Unpack.py <type> <target_file> [output_file]
```

**特性：**
- 自动备份原文件（带时间戳）
- 支持指定输出路径或覆盖原文件
- 智能处理相对/绝对路径
- 详细的执行日志

## 脚本详细说明

### Detect.py - 检测脚本

**功能：**
- 调用DIE工具检测文件是否被加壳
- 智能提取壳以及版本号（支持多种格式）
- 自动处理目录路径关系


**输出示例：**
```
[*] DIE检测输出:
[!] To get the full heuristic scan result use '--verbose'
[HEUR/About] Generic Heuristic Analysis by DosX (@DosX_dev)
[HEUR] Scanning has begun!
[HEUR] EP like a packer: '60BE........8DBE'
[HEUR] Imports hash like UPX (version 2.90-3.XX) (4084592131)
[HEUR] Sections like UPX
[HEUR] Section names collision: 'UPX'
[HEUR] 'PUSHAL' at EP
[HEUR] Scan completed.
PE32
    Linker: Microsoft Linker(6.00.8047)
    Compiler: Microsoft Visual C/C++(12.00.8168)[C++]
    Tool: Visual Studio(6.0)
    Packer: UPX(3.07)[NRV,brute]
    (Heur)Packer: Compressed or packed data


==================================================
检测结果:
==================================================
是否加壳: True
加壳信息: UPX
版本信息: 3.07
需要手动脱壳: False
详细信息: 检测到UPX壳，版本: 3.07
==================================================
```

### Unpack.py - 脱壳脚本

**功能：**
- 调用工具或脚本进行脱壳操作
- 自动备份原始文件
- 支持自定义输出路径
- 完善的错误处理

**参数说明：**
```bash
python Unpack.py <type> <file_path> [output_path]

参数:
  type         - 壳类型(暂时只支持: UPX, ASPack, PECompact, RLPack, NSPack)
  file_path    - 要脱壳的文件路径（必需）
  output_path  - 输出文件路径（可选，默认覆盖原文件）
```

**输出示例：**
```
[*] 已备份原文件到: target.exe.backup_20260209_143022
[*] 正在脱壳文件: /path/to/target.exe
[*] 输出:
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2020
UPX 3.96        Markus Oberhumer, Laszlo Molnar & John Reiser   Jan 23rd 2020

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
    123456 <-     45678   37.01%    win32/pe     target.exe

Unpacked 1 file.

==================================================
脱壳结果:
==================================================
是否成功: True
详细信息: 脱壳成功! 输出文件: /path/to/target.exe
输出文件: /path/to/target.exe
备份文件: target.exe.backup_20260209_143022
==================================================
```

## 使用示例

### 示例1：完整流程

```bash
# 步骤1：检测壳类型和版本
python Detect.py malware.exe

# 如果检测成功（退出码为0），执行步骤2
python Unpack.py malware.exe
```

### 示例2：指定输出文件

```bash
# 检测
python Detect.py packed.exe

# 脱壳到新文件（保留原文件）
python Unpack.py packed.exe unpacked.exe
```

## 注意事项
- 主要目标文件的路径关系