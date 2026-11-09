# SELinux_hide_From_LunSU (KPM)

实现方向是让出厂策略不被修改。劫持所有对出厂策略的修改到备份的策略中，也就是策略恒定与出厂相同，备份策略含模块规则等
非特权就直接透传到出厂策略内核原生作答，特权信任进程就是直接到我们的副本进行作答
理论这样非特权检测器就几乎很难做到时序检测和语义检测
当前项目仅作为一个DEMO参考，正在努力研究喵

大部分为vibe的代码，代码质量一般，在某些设备会产生兼容性问题，可能是不生效也可能会导致设备无法启动，测试时需要保证有救砖的能力
初创新项目，不稳定，玻璃心不喜勿喷qwq，大佬们可以提建议

## 设计语义

| 词汇 | 含义 |
|---|---|
| live | 出厂策略 |
| 副本 | live 的内核构建拷贝 + 其他注入规则，特权查询的答题主 |
| 模块规则 | 永不进 live；/load 写入被门吸收，模块自身的批规则走 KPM 控制面进副本 |
| 非特权（uid≥10000） | 到不了引擎：出厂 avc 权限检查（compute_av 等）天然挡死，透传=出厂答案 |
| 特权（uid<10000） | /access、/context 由门截住，从副本应答；渲染失败 fail-open 回落内核原版 |

## 实现路径（流程图）
### 图 1：KPM 总决策流程图
```mermaid
flowchart TD
    classDef blue fill:#E6F1FB,stroke:#185FA5,color:#0C447C
    classDef yellow fill:#FAEEDA,stroke:#854F0B,color:#633806
    classDef green fill:#EAF3DE,stroke:#3B6D11,color:#27500A
    classDef gray fill:#F1EFE8,stroke:#5F5E5A,color:#444441
    classDef purple fill:#EEEDFE,stroke:#534AB7,color:#3C3489
    classDef white fill:#FFFFFF,stroke:#EF9F27,color:#633806

    A([系统开机]):::gray --> B[KPM 装载：绑定内核符号 kallsyms]:::blue
    B --> C{必需内核符号<br/>齐全吗？}:::yellow
    C -- 否 --> D[引擎关闭<br/>零干预]:::gray
    C -- 是 --> E[KPM 事件期 early-init/init…<br/>挂 bprm 钩子]:::blue
    E --> F{首个 execve？<br/>进程上下文}:::yellow
    F -- 否 · 等待 --> E
    F -- 是 --> G[首个 exec：se_install_engine<br/>可睡眠进程上下文<br/><br/>标定 live 策略 → 解析 su/magisk 域 type/sid → 布局推导<br/>挂 avc_denied 决策面 + 活体自检 失败 → 降级，门照装<br/>se_build_copy 重建副本 → 尾部建 KSU 规则表<br/>装五门 access/context/load/policy/status → avc flush]:::yellow
    G --> H[引擎 up · 日常运行]:::blue
    H --> I[任意一次 SELinux 请求<br/>查询 / 改规则 / 读策略 / deny]:::blue
    I --> J{是否为特权进程？<br/>uid &lt; 10000}:::yellow
    J -- 否 · uid≥10000 --> K[五门透传原版 fallback<br/>deny 未命中 → 原生处理]:::blue
    K --> L([与未 root 逐位一致]):::green
    J -- 是 · uid&lt;10000 --> SG

    subgraph SG["特权侧五门分流"]
        direction TB
        M1[access / context 查询 → 副本求值<br/>败则回落原版]:::white
        M2[load 写策略 → 异步吸收进副本<br/>盖章 + 换代]:::white
        M3[policy 读 → 答镜像<br/>出厂 + 生态规则]:::white
        M4[status 读状态 → 特权见真实值]:::white
        M5[内核 deny → avc_denied 决策面<br/>见附图 2]:::purple
    end

    class SG yellow
```

### 图 2：avc_denied 决策面判定树

```mermaid
flowchart TD
    classDef yellow fill:#FAEEDA,stroke:#854F0B,color:#633806
    classDef green fill:#EAF3DE,stroke:#3B6D11,color:#27500A
    classDef red fill:#FCEBEB,stroke:#A32D2D,color:#791F1F

    A([avc_denied：内核全部 deny 判定唯一收口]):::yellow --> B{与 su / 组件域相关吗？<br/>sid 匹配 · uid 不参与本层}:::yellow
    B -- 否 --> C{副本生态规则允许吗？<br/>查副本 avtab}:::yellow
    C -- 有 --> FLIP
    C -- 无 --> ORIG
    B -- 是 --> D{源是 su / comp 吗？<br/>outbound · 主动发出}:::yellow
    D -- 是 --> FLIP
    D -- 否 --> E{命中 KSU 白名单吗？<br/>inbound · 类 + perm + 源域 sid}:::yellow
    E -- 命中 --> FLIP
    E -- 否 --> F{副本生态规则允许吗？<br/>副本收口 · 查副本 avtab}:::yellow
    F -- 有 --> FLIP
    F -- 否 --> G{live 策略异常吗？<br/>se_live_ok 三锚点}:::yellow
    G -- 是 --> H[se_recalibrate<br/>重标 sid · 重建副本 · 刷 KSU 表]:::yellow
    H -. 重判 .-> B
    G -- 否 --> ORIG

    FLIP([flip：改栈上 avd<br/>全类置满 / 位组按位 OR → return 0<br/>不写缓存，live 恒干净]):::green
    ORIG([orig：trampoline 透传 KP<br/>原始 avc_denied ＝ 出厂行为]):::red
```

## 参考技术项目
[KernelSU](https://github.com/tiann/KernelSU):SELinux策略深度拷贝与渲染器

[KernelPatch](https://github.com/bmax121/KernelPatch/):基础框架与魔数计算


