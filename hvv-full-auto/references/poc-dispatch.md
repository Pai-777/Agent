# 本地 POC 调度细则

## 默认检索源

- POC / EXP 仓库：`C:\Users\pai\Desktop\tool\Awesome-POC-master`
- Nuclei 模板库：`C:\Users\pai\nuclei-templates`

## 检索顺序

1. 产品名
2. 组件名
3. CVE
4. 路径特征
5. 漏洞类型

示例：
```powershell
rg -n -i "dedecms|recommend.php|CVE-2017-17731" "C:\Users\pai\Desktop\tool\Awesome-POC-master"
rg -n -i "dedecms|recommend.php|CVE-2017-17731" "C:\Users\pai\nuclei-templates"
rg -n -i "copy-fail|CVE-2026-31431|authencesn|AF_ALG" "C:\Users\pai\Desktop\tool\Awesome-POC-master"
rg -n -i "copy-fail|CVE-2026-31431|authencesn|AF_ALG" "C:\Users\pai\nuclei-templates"
rg -n -i "dirty pipe|CVE-2022-0847" "C:\Users\pai\Desktop\tool\Awesome-POC-master"
rg -n -i "dirty pipe|CVE-2022-0847" "C:\Users\pai\nuclei-templates"
```

如果已知具体路径、组件或参数，也要把路径特征带进检索词，例如：

```powershell
rg -n -i "recommend\\.php|plus/|dedecms" "C:\Users\pai\nuclei-templates"
rg -n -i "upload|avatar|htaccess|cgi|file upload" "C:\Users\pai\nuclei-templates"
```

## 读取后必须抽出的信息

每个 POC 至少抽出：
- 影响版本
- 利用前置条件
- 攻击入口
- 关键参数/文件
- 成功判据
- 副作用

若命中的是 Nuclei 模板，还至少要抽出：
- 模板 `id`
- `severity` / `tags`
- 目标路径与 HTTP 方法
- `matchers` 的判定逻辑（状态码 / 字符串 / regex / DSL）
- 是否需要 cookie、header、body、认证态
- 是否只是指纹检测、信息泄露检测，还是可直接利用

## 验证优先于执行

### Web POC
先验证：
- 路径是否存在
- 组件是否匹配
- 参数是否匹配
- 是否登录前/后触发

### Nuclei 模板
先验证：
- 模板对应的产品 / 组件 / CVE 是否命中当前目标
- 模板里的路径、参数、header、cookie 是否与当前站点一致
- 模板是“指纹/探测”还是“利用/验证”
- 是否需要认证态、特定中间件、特定版本

只有上述前置条件大体成立，才考虑运行单模板验证。

### 本地提权 POC
先验证：
- 目标内核/系统是否在影响范围
- 关键 syscall / socket / module 是否可用
- 编译器是否存在
- 落地路径是否可执行
- 是否会破坏已有二进制或服务

## 不适用时的处理

如果前置条件不满足，明确写：
- 未命中
- 条件不足
- 环境拦截
- 路径不符

不要继续为了“自动化完整性”强跑。

## 运行 Nuclei 的默认约束

默认只在以下情况运行 Nuclei：
- 已经命中明确产品、组件、路径或 CVE；
- 已经从 `robots.txt`、JS、报错、后台入口、用户提示里拿到关键路径；
- 已经通过手工请求看到了模板所需的状态码/关键字/参数形态。

默认不要：
- 对单个 Web 站点直接全量跑整个 `C:\Users\pai\nuclei-templates`
- 在用户已给出明确入口时，先做大范围模板轰炸
- 把“有模板”误当成“前置条件一定满足”

优先级：
1. 先读模板理解路径与判据
2. 再手工最小验证
3. 最后按需跑单模板或极小模板集

## 与本次实战相关的经验固化

- 用户给出具体路径时，优先验证该路径，而不是继续枚举。
- `robots.txt` 泄露路径后，要把路径当作下一步主线索。
- 用户给出明确 CVE/POC 后，先做 PoC 前置条件探测。
- 本地 `nuclei-templates` 命中后，不要直接全量扫描；先读模板，再做单模板验证。
- 内核/容器提权 POC 失败时，要指出是“环境前置条件不满足”，不是简单说“exp 失败”。
