#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
from pathlib import Path


def get_diec_path():
    """获取diec.exe的绝对路径"""
    # 获取当前目录
    script_dir = Path(__file__).parent.resolve()
    # 构建diec.exe路径
    diec_path = script_dir / "scripts" / "diec" / "diec.exe"
    
    if not diec_path.exists():
        exit(f"错误: 找不到diec.exe - {diec_path}")
    
    return diec_path


def detect(file_path):
    """
    检测文件是否被加壳
    
    Args:
        file_path: 要检测的文件路径
        
    Returns:
        dict: 包含检测结果的字典
            - is_packed: 是否加壳
            - packer_info: 加壳工具名称
            - version: 版本信息
            - need_manual: 是否需要手动脱壳
            - message: 详细信息
    """
    result = {
        'is_packed': False,
        'packer_info': None,
        'version': None,
        'need_manual': True,
        'message': ''
    }
    
    # 检查文件是否存在
    if not os.path.exists(file_path):
        result['message'] = f"错误: 文件不存在 - {file_path}"
        return result
    
    # 获取diec.exe路径
    diec_path = get_diec_path()
    
    if not diec_path.exists():
        result['message'] = f"错误: 找不到diec.exe - {diec_path}"
        return result
    
    try:
        # 调用diec.exe进行检测
        cmd = [str(diec_path), '-u', str(file_path)]
        
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
        
        output = process.stdout + process.stderr
        
        # 检测特定的壳类型关键字
        import re
        packers = ['UPX', 'ASPack', 'PECompact', 'RLPack', 'NSPack']
        
        found_packer = None
        for packer in packers:
            if re.search(packer, output, re.IGNORECASE):
                found_packer = packer
                # 尝试提取版本信息
                version_match = re.search(rf'{packer}\s*\(?v?(\d+\.[\d.]+)', output, re.IGNORECASE)
                if version_match:
                    result['version'] = version_match.group(1)
                break
        
        if found_packer:
            result['is_packed'] = True
            result['packer_info'] = found_packer
            if result['version']:
                result['message'] = f"检测到{found_packer}壳，版本: {result['version']}"
            else:
                result['message'] = f"检测到{found_packer}壳"
            
            result['need_manual'] = False
        else:
            result['message'] = "未找到加壳信息"
        
        print(f"[*] DIE检测输出:\n{output}")
        
    except Exception as e:
        result['message'] = f"检测过程出错: {str(e)}"
    return result


def main():
    """主函数"""
    if len(sys.argv) < 2:
        print("用法: python Detect.py <file_path>")
        print("示例: python Detect.py target.exe")
        sys.exit(1)
    
    file_path = sys.argv[1]
    result = detect(file_path)
    
    print("="*50)
    print("检测结果:")
    print("="*50)
    print(f"是否加壳: {result['is_packed']}")
    if result['packer_info']:
        print(f"加壳信息: {result['packer_info']}")
        if result['version']:
            print(f"版本信息: {result['version']}")
    print(f"需要手动脱壳: {result['need_manual']}")
    print(f"详细信息: {result['message']}")
    print("="*50)
    
    # 根据结果返回不同的退出码
    if result['is_packed'] and not result['need_manual']:
        sys.exit(0)  # 成功检测到可自动脱壳的壳
    elif result['need_manual']:
        sys.exit(2)  # 需要手动脱壳
    else:
        sys.exit(1)  # 未检测到加壳或检测失败


if __name__ == "__main__":
    main()
