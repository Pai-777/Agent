# 图片隐写分析模块

## 适用文件类型
- PNG / JPG / BMP / GIF / WEBP / TIFF

## 检查清单

```yaml
基础检查:
  - [ ] 文件类型识别（file / xxd 查看魔数）
  - [ ] EXIF 元数据（exiftool）
  - [ ] 文件尾部追加数据（binwalk / foremost）
  - [ ] 字符串搜索（strings | grep -i flag）

PNG 专项:
  - [ ] LSB 隐写（zsteg -a）
  - [ ] IDAT chunk 异常（pngcheck -v）
  - [ ] CRC 校验错误（可能是高度/宽度被修改）
  - [ ] PNG 高度/宽度爆破
  - [ ] APNG 多帧动画
  - [ ] 色板（palette）隐写
  - [ ] tEXt/zTXt/iTXt chunk 隐藏信息

JPG 专项:
  - [ ] Steghide 隐写（steghide info）
  - [ ] Steghide 密码爆破（stegseek）
  - [ ] JFIF 注释字段
  - [ ] EXIF 缩略图隐写
  - [ ] JPG 文件拼接（两个 FFD8 开头）

通用技巧:
  - [ ] 通道分析（R/G/B/Alpha 各通道 LSB）
  - [ ] Bit plane 分析（stegsolve）
  - [ ] 图片异或/拼图还原
  - [ ] 二维码/条形码识别（pyzbar）
  - [ ] 盲水印提取
  - [ ] 图片拼接（多张图合成）
  - [ ] 像素值转 ASCII/二进制

常用工具:
  - zsteg, stegsolve, pngcheck
  - steghide, stegseek
  - gimp, PIL/Pillow
  - pyzbar (二维码)
  - exiftool, binwalk, foremost
```

## 分析流程

### Step 1: 快速扫描（30 秒内完成）

```bash
# 文件类型
file image.png
xxd image.png | head -20

# EXIF 信息（重点关注 Comment/Description/Author）
exiftool image.png
exiftool -a -G1 image.png  # 显示所有标签和组

# 嵌入文件检测
binwalk image.png
binwalk -e image.png  # 自动提取

# 字符串搜索
strings image.png | grep -iE "flag|ctf|key|password"
strings -n 6 image.png  # 最小长度 6
```

### Step 2: PNG 深度分析

```bash
# LSB 全面扫描（最常用）
zsteg -a image.png
zsteg -E "b1,rgb,lsb,xy" image.png  # 提取 RGB LSB

# PNG 结构检查
pngcheck -v image.png

# 如果报 CRC 错误，可能是高度被修改
python3 scripts/png_height_fix.py image.png

# 检查 PNG chunk
pngcheck -cvt image.png

# 提取特定 chunk
python3 << EOF
import struct
with open('image.png', 'rb') as f:
    data = f.read()
    # 搜索 tEXt chunk (74 45 58 74)
    if b'tEXt' in data:
        print("Found tEXt chunk")
        idx = data.find(b'tEXt')
        print(data[idx:idx+100])
EOF
```

### Step 3: JPG 深度分析

```bash
# Steghide 检测（尝试空密码）
steghide info image.jpg
steghide extract -sf image.jpg  # 直接回车

# 密码爆破
stegseek image.jpg wordlist.txt

# JPEG 注释
exiftool -Comment image.jpg
jhead -v image.jpg

# 检查是否有多个 JPEG 拼接
xxd image.jpg | grep "ffd8"  # JPEG 文件头
# 如果有多个，手动分离
```

### Step 4: 通道和 Bit Plane 分析

```python
# 使用 PIL 手动提取各通道 LSB
from PIL import Image
import numpy as np

img = Image.open('image.png')
pixels = np.array(img)

# 提取 R 通道 LSB
r_lsb = pixels[:,:,0] & 1
Image.fromarray(r_lsb * 255).save('r_lsb.png')

# 提取 G 通道 LSB
g_lsb = pixels[:,:,1] & 1
Image.fromarray(g_lsb * 255).save('g_lsb.png')

# 提取 B 通道 LSB
b_lsb = pixels[:,:,2] & 1
Image.fromarray(b_lsb * 255).save('b_lsb.png')

# 提取所有 bit plane
for bit in range(8):
    plane = (pixels[:,:,0] >> bit) & 1
    Image.fromarray(plane * 255).save(f'plane_{bit}.png')
```

### Step 5: 高级技巧

```python
# 1. 像素值转文本
from PIL import Image
img = Image.open('image.png')
pixels = list(img.getdata())
# 尝试将像素值转为 ASCII
text = ''.join(chr(p[0]) for p in pixels if 32 <= p[0] <= 126)
print(text)

# 2. 图片异或
from PIL import Image
import numpy as np
img1 = np.array(Image.open('img1.png'))
img2 = np.array(Image.open('img2.png'))
result = img1 ^ img2
Image.fromarray(result).save('xor_result.png')

# 3. 二维码识别
from pyzbar.pyzbar import decode
from PIL import Image
img = Image.open('qr.png')
codes = decode(img)
for code in codes:
    print(code.data.decode())

# 4. 盲水印提取（频域分析）
import cv2
import numpy as np
img = cv2.imread('image.png', 0)
f = np.fft.fft2(img)
fshift = np.fft.fftshift(f)
magnitude = 20*np.log(np.abs(fshift))
cv2.imwrite('fft.png', magnitude)
```

## 常见出题套路与解法

### 套路 1: PNG 高度被修改

**特征**: 图片打不开或显示不完整

**解法**:
```bash
python3 scripts/png_height_fix.py image.png
# 爆破 1-4096 的高度值
```

### 套路 2: LSB 隐写

**特征**: 图片看起来正常，但有隐藏信息

**解法**:
```bash
# PNG
zsteg -a image.png

# 手动提取
python3 << EOF
from PIL import Image
img = Image.open('image.png')
pixels = list(img.getdata())
bits = ''.join(str(p[0] & 1) for p in pixels)
# 转为字节
bytes_data = int(bits, 2).to_bytes(len(bits)//8, 'big')
print(bytes_data)
EOF
```

### 套路 3: EXIF 隐藏

**特征**: 元数据中藏有 flag 或提示

**解法**:
```bash
exiftool -a -G1 image.jpg
# 重点关注: Comment, Description, Author, GPS 信息
```

### 套路 4: 文件拼接

**特征**: binwalk 检测到多个文件

**解法**:
```bash
binwalk -e image.png
# 或手动分离
dd if=image.png of=part1.zip bs=1 skip=12345
```

### 套路 5: Steghide 加密

**特征**: JPG 文件，steghide info 提示需要密码

**解法**:
```bash
# 1. 尝试空密码
steghide extract -sf image.jpg

# 2. 密码爆破
stegseek image.jpg rockyou.txt

# 3. 密码可能在题目描述/文件名中
```

### 套路 6: 通道隐写

**特征**: 某个颜色通道异常

**解法**:
```bash
# 使用 stegsolve 查看各个通道
# 或用 Python 分离通道
```

### 套路 7: 二维码隐藏

**特征**: 图片中有二维码或条形码

**解法**:
```python
from pyzbar.pyzbar import decode
from PIL import Image
codes = decode(Image.open('image.png'))
for code in codes:
    print(code.data.decode())
```

### 套路 8: 图片拼图

**特征**: 多张图片需要拼接

**解法**:
```python
from PIL import Image
# 横向拼接
imgs = [Image.open(f'part{i}.png') for i in range(1, 5)]
widths, heights = zip(*(i.size for i in imgs))
total_width = sum(widths)
max_height = max(heights)
result = Image.new('RGB', (total_width, max_height))
x_offset = 0
for img in imgs:
    result.paste(img, (x_offset, 0))
    x_offset += img.size[0]
result.save('combined.png')
```

### 套路 9: 像素值编码

**特征**: 像素值对应 ASCII 或其他编码

**解法**:
```python
from PIL import Image
img = Image.open('image.png')
pixels = list(img.getdata())
# RGB 值转 ASCII
text = ''.join(chr(p[0]) for p in pixels if 32 <= p[0] <= 126)
print(text)
```

### 套路 10: GIF 帧分析

**特征**: GIF 动图，某一帧藏有信息

**解法**:
```python
from PIL import Image
gif = Image.open('anim.gif')
for i in range(gif.n_frames):
    gif.seek(i)
    gif.save(f'frame_{i}.png')
```

## 实战技巧

### 技巧 1: 快速判断隐写类型

```bash
# 一键检测脚本
#!/bin/bash
FILE=$1
echo "[*] Analyzing: $FILE"

# 基础信息
file $FILE
exiftool $FILE | grep -iE "comment|description|author"

# LSB 检测
if [[ $FILE == *.png ]]; then
    zsteg -a $FILE | head -20
fi

# Steghide 检测
if [[ $FILE == *.jpg ]]; then
    steghide info $FILE 2>&1 | grep -v "passphrase"
fi

# 嵌入文件
binwalk $FILE | grep -v "^DECIMAL"
```

### 技巧 2: 批量处理

```python
# 批量提取 LSB
import os
from PIL import Image
import numpy as np

for filename in os.listdir('.'):
    if filename.endswith('.png'):
        img = Image.open(filename)
        pixels = np.array(img)
        lsb = pixels[:,:,0] & 1
        Image.fromarray(lsb * 255).save(f'lsb_{filename}')
```

### 技巧 3: 盲水印检测

```python
# 频域分析
import cv2
import numpy as np

img = cv2.imread('image.png', 0)
dft = cv2.dft(np.float32(img), flags=cv2.DFT_COMPLEX_OUTPUT)
dft_shift = np.fft.fftshift(dft)
magnitude = 20*np.log(cv2.magnitude(dft_shift[:,:,0], dft_shift[:,:,1]))
cv2.imwrite('fft_magnitude.png', magnitude)
```

## 无工具替代方案

当没有专业隐写工具时，可以使用以下方法：

### 纯 Python 替代

```python
#!/usr/bin/env python3
"""无工具依赖的图片分析"""

# 1. 文件头检查 (替代 file 命令)
def check_magic(filename):
    magic_bytes = {
        b'\x89PNG\r\n\x1a\n': 'PNG',
        b'\xff\xd8\xff': 'JPEG',
        b'GIF87a': 'GIF87a',
        b'GIF89a': 'GIF89a',
        b'BM': 'BMP',
    }
    with open(filename, 'rb') as f:
        header = f.read(10)
        for magic, fmt in magic_bytes.items():
            if header.startswith(magic):
                return fmt
    return 'Unknown'

# 2. 字符串提取 (替代 strings 命令)
def extract_strings(filename, min_len=4):
    with open(filename, 'rb') as f:
        data = f.read()
    result = []
    current = []
    for byte in data:
        if 32 <= byte < 127:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                result.append(''.join(current))
            current = []
    return result

# 3. 文件尾追加检测 (替代 binwalk)
def check_appended_data(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    # 检查 PNG 结尾后是否有额外数据
    png_end = data.find(b'IEND') + 8
    if png_end < len(data) - 4:
        print(f"[!] Found {len(data) - png_end} bytes after PNG end")
        return data[png_end:]
    return None

# 4. 简单 LSB 提取 (替代 zsteg)
from PIL import Image
def extract_lsb(filename):
    img = Image.open(filename)
    pixels = list(img.getdata())
    bits = ''.join(str(p[0] & 1) for p in pixels if isinstance(p, tuple))
    chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits)-8, 8)]
    return ''.join(c for c in chars if 32 <= ord(c) < 127)

# 5. EXIF 读取 (替代 exiftool - 需要 PIL)
from PIL.ExifTags import TAGS
def read_exif(filename):
    img = Image.open(filename)
    exif = img._getexif()
    if exif:
        for tag_id, value in exif.items():
            tag = TAGS.get(tag_id, tag_id)
            print(f"{tag}: {value}")
```

### 在线工具替代

```yaml
图片分析:
  - https://www.aperisolve.com/ - 自动分析隐写
  - https://29a.ch/photo-forensics/ - 图片取证
  - https://stegonline.net/ - 在线 LSB 分析

元数据:
  - https://exifdata.com/ - 在线 EXIF 查看
  - https://www.metadata2go.com/ - 元数据提取

二维码:
  - https://zxing.org/w/decode.jspx - 二维码解码
  - https://online-barcode-reader.inliteresearch.com/ - 条形码
```

### Hex 编辑器替代

```bash
# 使用 Python 查看十六进制
python3 -c "print(open('image.png','rb').read()[:100].hex())"

# 或使用 xxd (通常系统自带)
xxd image.png | head -20

# Windows PowerShell
Format-Hex -Path image.png | Select-Object -First 20
```

## 工具速查

```bash
# 基础工具
file image.png              # 文件类型
xxd image.png | head        # 十六进制查看
strings image.png           # 字符串提取
exiftool image.png          # 元数据
binwalk image.png           # 嵌入文件检测

# PNG 工具
zsteg -a image.png          # LSB 全扫描
pngcheck -v image.png       # PNG 结构检查
python3 scripts/png_height_fix.py image.png  # 高度爆破

# JPG 工具
steghide info image.jpg     # Steghide 检测
stegseek image.jpg wordlist.txt  # 密码爆破
jhead -v image.jpg          # JPEG 头信息

# 通用工具
stegsolve                   # 通道/Bit plane 分析
gimp                        # 图像编辑
```

## 脚本参考

详见 `scripts/png_height_fix.py`
