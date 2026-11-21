# SELinux_hide_Ind (KPM)
[English](README.md)  |  [简体中文](README_ZH.md)  |

一个面向 KernelPatch / APatch 生态的 SELinux 隐藏 KPM（内核补丁模块）～

思路是尽量不动出厂策略：把生态对策略的修改劫持到内核侧的副本里，出厂策略（live）保持原样；普通 App 的请求直接透传给内核原生应答，root/system/shell 的请求则由副本作答

希望这样能让非特权检测器在常见的时序/语义检测路径上不那么容易看出差异（当然不能保证对所有检测方式都有效啦）

> 目前项目主要是个 DEMO，还在慢慢研究中喵～
> 代码大部分是 vibe 出来的，质量一般，在某些设备上可能不生效、也可能开不了机，折腾前请确保有救砖的能力
> 玻璃心不喜勿喷，大佬们欢迎提 Issue / PR 建议 qwq

## 一、设计语义

| 词汇             | 含义                                                                                |
| -------------- | --------------------------------------------------------------------------------- |
| live           | 出厂策略，内核当前管理的实时策略本体。尽量保持与出厂一致，引擎原则上不写入（连三件套也早已删除）                                  |
| 副本             | live 的内核构建拷贝（`policydb_read` 由内核自建全部派生表）+ 生态规则 + 引擎盖章；特权查询的答主体                    |
| 盖章             | 组件域 → attribute×全类全权 + inbound 六类白名单 + permissive 位，只写进副本                         |
| 模块规则           | 原则上不进 live。APatch 生态的 `/sys/fs/selinux/load` 写入被门吸收进副本；KSU 生态的批规则走 supercall/控制面进副本 |
| 组件域（comp）      | 生态组件的运行域：KP 生态 = `u:r:magisk:s0`，旧生态（无 magisk 类型）= `u:r:su:s0`                    |
| 非特权（uid≥10000） | 正常 app 域。到不了引擎：门透传内核原版、决策面一次整数比较即透传——出厂语义                                         |
| 特权（uid<10000）  | root/system/shell。问侧（selinuxfs）被门截住从副本应答；做侧（内核 deny）由决策面判定                        |
| 决策面            | 挂在 `avc_denied`（内核 deny 唯一收口）上的补丁；只对 su/comp 相关请求自处理，其余透传                         |
| flip           | 决策面放行：改栈上 avd 后 return 0——不写 avc 缓存、不打 audit 日志，live 保持出厂                         |
| orig           | 透传：backup trampoline → KP replace（若有）→ 原始 `avc_denied` ＝ 出厂行为                     |
| orig_audit_suppress | inbound deny 失败路径：透传前清掉栈上 avd 的 auditdeny 位（dontaudit 语义）——判定还是出厂的样子，只是不再打审计日志，避免 `tcontext` 从 logcat 溜出去 |

## 二、总体架构（14 文件分层）

| 文件            | 职责                                                          |
| ------------- | ----------------------------------------------------------- |
| sehide_main.c | 模块入口/装配顺序/控制面（ctl 子命令、sepolicy 批处理入口）                       |
| se_symbol.c   | 三级符号解析链（L1 kallsyms → LTO 后缀枚举 → KP 全表按名枚举）+ 符号绑定表          |
| se_layout.c   | live policydb 标定与结构推导（探针/反解/形态扫描三级）                         |
| se_policydb.c | 规则原语（avtab/ebitmap 写入）、副本生命周期（build/retire-swap）、blob 吸收、镜像 |
| se_render.c   | 渲染三路（ctx→sid、av 求值、sid→ctx）副本侧自实现 + 装机自检                    |
| se_decision.c | 决策面：avc_denied 补丁挂载/卸载、KSU 规则集、副本收口查询                       |
| se_gate.c     | 问门（/access、/context）+ 写门（/load，异步线程）+ /policy 读门            |
| se_status.c   | /sys/fs/selinux/status 冻结门（非特权看到的是出厂快照）                     |
| se_bprm.c     | exec 钩子（首触安装触发器 + 纯透传 + 组件域切轨）                              |
| se_recal.c    | 被动指纹自愈（live 三锚点 → light/full 重标定）+ 置旗代跑机制                   |
| se_shadow.c   | mkpms 式页分裂影子页（MKP 写保护机型的 hook 通道）                           |
| se_rules.c    | KSU sepolicy 批处理 wire format（与 KSU 同构）                      |
| se_util.c     | 格式化/字节序/内存/字符串底座                                            |
| sehide.h      | 共享头：符号表、静态形状表、全局状态                                          |

## 三、装机时序（图 1）

```mermaid
flowchart LR
    classDef blue fill:#E6F1FB,stroke:#185FA5,color:#0C447C
    classDef yellow fill:#FAEEDA,stroke:#854F0B,color:#633806
    classDef green fill:#EAF3DE,stroke:#3B6D11,color:#27500A
    classDef gray fill:#F1EFE8,stroke:#5F5E5A,color:#444441

    A(["系统开机"]):::gray --> B["KPM 装载：绑定内核符号<br/>必需符号缺失 → 引擎关闭零干预"]:::blue
    B --> E["KPM 事件期 early-init/init：挂 bprm 钩子<br/>事件期=RCU读临界区，不能睡觉"]:::blue
    E --> F{"首个 execve？"}:::yellow
    F -- 是 --> G["se_install_engine（进程上下文·CAS互斥）<br/>标定 live → 解析 su/magisk 域 type/sid → 布局推导<br/>决策面挂载+活体自检（失败=DEGRADED，门照装）<br/>副本重建 → 尾部建 KSU 规则表<br/>装五门 → avc flush（call_rcu 异步）"]:::yellow
    G --> H["引擎 up · 日常运行"]:::blue
    H --> I["任意 SELinux 请求"]:::blue
    I --> J{"uid？"}:::yellow
    J -- "≥10000" --> K["门透传原版 / 决策面一次分诊即透传——出厂语义"]:::blue
    K --> L(["观测面尽量长得和没 root 一样"]):::green
    J -- "<10000" --> SG["特权侧五门分流 + 决策面，见图 2"]:::yellow
```

要点：

1. **安装挂首触 exec**：KPM 在 pre-kernel-init 装载时 SELinux 策略还没读进来（`security_read_policy` 对未初始化 state 会返回 -EINVAL），所以这一步只绑符号；引擎主体等到策略就绪后的第一个 exec 再装（真进程上下文，可以睡觉，`g_recal_busy` CAS 互斥）
2. **决策面失败 = 降级（DEGRADED）**：门照装——拦生态注入是 live 干净的硬需求（决策面挂不上、门又缺席的话，LSP/Magisk 的注入就直接裸奔落 live 了）；翻转装不上（su 功能缺）会在装机自检日志里写明白
3. **注意**：装机后的 avc 冲刷只能走 `se_avc_flush_after_recal()`（call_rcu 异步）；直接调 `avc_ss_reset` 会在 RCU 段里等 grace → panic 卡死，别踩

## 四、问侧五门（特权 vs 非特权分流）

| 门          | 特权（uid<10000）                                                        | 非特权（uid≥10000）                                            | 失败路径                                                               |
| ---------- | -------------------------------------------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------ |
| /access 写  | 副本求值，按内核 selinuxfs 六字段格式应答                                           | fallback → 内核原版 `sel_write_access`（live 求值）               | 任何一步失败都回落原版；快照里查不到的类型返回出厂同款 EINVAL（不回落 live，免得被 validity oracle 问出来） |
| /context 写 | 副本规范化应答（注：MLS 渲染缺陷还没修，这个门实际恒 fallback，输出=原版=stock，无害）                | 同上                                                        | 同上                                                                 |
| /load 写    | 异步吸收进副本：入队就返回（~1ms），load 线程做 policydb_read+盖章+换代（全程持 `g_recal_busy`） | passthrough 内核原版（app 本来就被出厂策略拒写）                          | 解析/类数校验失败 → **丢弃+假成功**（返回 0）。这里不能返回错误，否则 apd 会静默退出、zygisk 全灭     |
| /policy 读  | 直供镜像（=出厂+全部生态规则，盖章前序列化存档——apd"读现行→加规则→写回"链式累积依赖）                     | 原版 open 就被 avc 拒，零干预                                      | 换代窗口期 CAS 抢不到 `g_recal_busy` → 回落出厂快照；plm 定位失败 → 出厂快照              |
| /status 读  | 真实值透传                                                                | 冻结的出厂快照（policyload=1、真 enforcing）——内核重载推高 policyload 时的保险 | -                                                                  |

门的错误路径尽量照抄出厂（errno/返回值），让 errno 指纹类检测不那么好使

## 五、决策面（做侧判定，图 2 为现行语义）

```mermaid
flowchart LR
    classDef yellow fill:#FAEEDA,stroke:#854F0B,color:#633806
    classDef green fill:#EAF3DE,stroke:#3B6D11,color:#27500A
    classDef red fill:#FCEBEB,stroke:#A32D2D,color:#791F1F

    A(["avc_denied：内核全部 deny 判定唯一收口"]):::yellow --> B{"与 su/组件域相关吗？<br/>sid 匹配 · uid 不参与本层"}:::yellow
    B -- 否 --> ORIG
    B -- 是 --> D{"源是 su/comp 吗？<br/>outbound"}:::yellow
    D -- 是 --> FLIP
    D -- 否 --> E{"命中 KSU 白名单吗？<br/>inbound · 类+perm+源域 sid"}:::yellow
    E -- 命中 --> FLIP
    E -- 否 --> F{"副本生态规则允许吗？<br/>副本收口 · 查副本 avtab"}:::yellow
    F -- 有 --> FLIP
    F -- 否 --> G{"live 策略异常吗？<br/>se_live_ok 三锚点"}:::yellow
    G -- 是 --> H["置 g_recal_pending 旗<br/>门/bprm（进程上下文）代跑<br/>重标 sid · 重建副本 · 刷 KSU 表"]:::yellow
    H -. 下一次请求重判 .-> B
    G -- 否 --> SUPPRESS

    FLIP(["flip：改栈上 avd → return 0<br/>不写缓存不打日志，live 保持出厂"]):::green
    SUPPRESS(["orig_audit_suppress：清 auditdeny 位<br/>判定还是出厂 deny，但不再打审计日志<br/>免得 tcontext 从 logcat 溜出去"]):::green
    ORIG(["orig：trampoline 透传 KP replace<br/>→ 原始 avc_denied ＝ 出厂行为"]):::red
```

## 六、构建

- **CI**：改动 `SELinux_hide_Ind/` 目录内容推送到 main 就会自动编译，产物在 Actions 的 artifact（`SELinux_hide_Ind-kpm`）里～
- **本地**：
  ```sh
  export TARGET_COMPILE=aarch64-linux-gnu-
  export KP_DIR=/path/to/KernelPatch
  cd SELinux_hide_Ind && make
  ```

刷入是嵌入 boot（kptools -m）的方式，动手前记得留一个能救砖的 boot 镜像哦

## 参考技术项目

- [KernelSU](https://github.com/tiann/KernelSU)：SELinux 策略深度拷贝与渲染器
- [KernelPatch](https://github.com/bmax121/KernelPatch/)：基础框架与魔数计算
- [SELinux_hook](https://github.com/Admirepowered/selinux_hook)：相关KPM实现参考

## License

AGPL v3
