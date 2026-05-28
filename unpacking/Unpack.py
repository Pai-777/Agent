#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import shutil
from pathlib import Path
from datetime import datetime

#脚本初始路径
script_dir = Path(__file__).parent.resolve()

def unpack_upx(file_path, output_path=None, backup=True):
    """
    使用UPX对文件进行脱壳
    
    Args:
        file_path: 要脱壳的文件路径
        output_path: 输出文件路径（可选，默认覆盖原文件）
        backup: 是否备份原文件
        
    Returns:
        dict: 包含脱壳结果的字典
            - success: 是否成功
            - message: 详细信息
            - output_file: 输出文件路径
            - backup_file: 备份文件路径（如果创建了备份）
    """
    #路径加载
    upx_path = script_dir / "scripts" / "upx" / "upx.exe"
    result = {
        'success': False,
        'message': '',
        'output_file': None,
        'backup_file': None
    }
    
    # 检查文件是否存在
    if not os.path.exists(file_path):
        result['message'] = f"错误: 文件不存在 - {file_path}"
        return result

    if not upx_path.exists():
        result['message'] = f"错误: 找不到upx.exe - {upx_path}"
        return result
    
    try:
        file_path = os.path.abspath(file_path)
        
        # 备份原文件
        if backup:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"{file_path}.backup_{timestamp}"
            shutil.copy2(file_path, backup_path)
            result['backup_file'] = backup_path
            print(f"[*] 已备份原文件到: {backup_path}")
        
        # 如果指定了输出路径，先复制文件
        if output_path:
            output_path = os.path.abspath(output_path)
            shutil.copy2(file_path, output_path)
            target_file = output_path
        else:
            target_file = file_path
        
        result['output_file'] = target_file
        
        # 调用upx.exe进行脱壳
        # -d 参数表示解压缩（脱壳）
        # -o 参数强制覆盖
        cmd = [str(upx_path), "-d", target_file]
        
        print(f"[*] 正在脱壳文件: {file_path}")
        print(f"[*] 使用工具: {upx_path}")
        print(f"[*] 执行命令: {' '.join(cmd)}")
        
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
        
        output = process.stdout + process.stderr
        print(f"[*] UPX输出:\n{output}")
        
        # 检查是否成功
        if process.returncode == 0:
            result['success'] = True
            result['message'] = f"脱壳成功! 输出文件: {target_file}"
        else:
            # 即使返回码不为0，也检查输出中是否有成功的标志
            if "unpacked" in output.lower() or "decompressed" in output.lower():
                result['success'] = True
                result['message'] = f"脱壳成功! 输出文件: {target_file}"
            else:
                result['message'] = f"脱壳失败! 返回码: {process.returncode}\n输出: {output}"
                # 如果失败且创建了输出文件，删除它
                if output_path and os.path.exists(output_path):
                    os.remove(output_path)
        
    except Exception as e:
        result['message'] = f"脱壳过程出错: {str(e)}"
        # 如果出错且创建了输出文件，尝试删除它
        if output_path and os.path.exists(output_path):
            try:
                os.remove(output_path)
            except:
                pass
    
    return result

def unpack_aspack(file_path, output_path=None, backup=True):
    pass

def unpack_pecompact(file_path, output_path=None, backup=True):
    pass

def unpack_rlpack(file_path, output_path=None, backup=True):
    pass

def unpack_nspack(file_path, output_path=None, backup=True):
    pass

def main():
    if len(sys.argv) < 2:
        print("用法: python unpack_upx.py <type> <file_path> [output_path]")
        print("示例: python unpack_upx.py UPX target.exe")
        print("示例: python unpack_upx.py UPX target.exe unpacked.exe")
        print("\n选项:")
        print("  type         - 脱壳类型(暂时只支持: UPX, ASPack, PECompact, RLPack, NSPack)")
        print("  file_path    - 要脱壳的文件路径")
        print("  output_path  - 输出文件路径（可选，默认覆盖原文件）")
        sys.exit(1)
    #脚本初始路径
    script_dir = Path(__file__).parent.resolve()
    type = sys.argv[1].upper()
    file_path = sys.argv[2]
    output_path = sys.argv[3] if len(sys.argv) > 3 else None
    
    if(type == "UPX"):
        result = unpack_upx(file_path, output_path, backup=True)
    elif(type == "ASPack"):
        result = unpack_aspack(file_path, output_path, backup=True)
    elif(type == "PECompact"):
        result = unpack_pecompact(file_path, output_path, backup=True)
    elif(type == "RLPack"):
        result = unpack_rlpack(file_path, output_path, backup=True)
    elif(type == "NSPack"):
        result = unpack_nspack(file_path, output_path, backup=True)
    else:
        print(f"错误: 不支持的脱壳类型 - {type}")
        sys.exit(1)
    
    print("\n" + "="*50)
    print("脱壳结果:")
    print("="*50)
    print(f"是否成功: {result['success']}")
    print(f"详细信息: {result['message']}")
    if result['output_file']:
        print(f"输出文件: {result['output_file']}")
    if result['backup_file']:
        print(f"备份文件: {result['backup_file']}")
    print("="*50)
    
    sys.exit(0 if result['success'] else 1)


if __name__ == "__main__":
    main()