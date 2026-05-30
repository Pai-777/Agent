# 指纹识别 → N-day 映射规则

## 为什么必须先识别

批量场景如果只知道：
- 存活
- 状态码
- 标题

那只能说明“站活着”，并不能说明：
- 是不是 DedeCMS / ThinkPHP / Ruoyi
- 是不是 Shiro / WebLogic / Tomcat / Spring
- 是不是 Jenkins / GitLab / Grafana / Nacos / Zabbix
- 有没有后台 / 默认口令 / 暴露控制台 / Swagger / `.git` / `phpinfo`
- 下一步该优先跑什么 N-day

因此多目标场景里必须先补一层：

**nuclei 识别层**

## 优先识别信号

### 1. `http/technologies`

识别：
- CMS
- Java 中间件
- 框架
- 常见面板产品
- 部分版本线索

### 2. `http/exposed-panels`

识别：
- 登录面板
- 管理后台
- 运维平台
- 数据管理控制台

### 3. 精选 `http/exposures`

识别：
- Swagger / API 暴露
- `.git/config`
- `phpinfo`
- `.env` / 配置暴露
- 其他高信号文件泄露

### 4. fallback 补充信号

仅在需要时补：
- `robots.txt`
- `generator`
- `Set-Cookie`
- favicon hash
- 常见登录口可达性

## 识别后怎么映射 N-day

### CMS / OA

如果识别出：
- `dedecms`
- `thinkphp`
- `weaver`
- `seeyon`
- `landray`

优先：
- 对应产品模板
- 上传 / 后台 / 默认口令 / RCE / SQLi / 信息泄露

### Java / 中间件

如果识别出：
- `weblogic`
- `tomcat`
- `shiro`
- `spring`
- `struts`

优先：
- Java / 中间件类模板
- `rce` / `auth-bypass` / `default-login` / `file-read`

### 运维 / 面板 / 云控

如果识别出：
- `jenkins`
- `gitlab`
- `harbor`
- `grafana`
- `nacos`
- `zabbix`
- `phpmyadmin`

优先：
- 后台默认口令
- 面板暴露
- 信息泄露
- 版本对应 N-day

### 暴露面 / 文件面

如果识别出：
- `swagger-api`
- `git-config`
- `phpinfo-files`
- `.env` 类暴露

优先：
- 同类配置暴露模板
- 接口扩展
- 凭据搜集
- 框架 / 组件二次映射

## 核心原则

1. 先识别再选模板
2. 先样本再扩同簇
3. 先高价值系统再普通门户
4. 先高信号产品链再泛 tags
5. fallback 探针只补充，不替代 nuclei 识别层
