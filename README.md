/**
 * ══════════════════════════ ░░ 脚本自述 ░░ ══════════════════════════
 *
 *   Script.js 路径（Windows）：
 *     %APPDATA%\io.github.clash-verge-rev.clash-verge-rev\profiles
 *     C:\Users\Administrator\AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev\profiles
 *
 *   名称：Clash Verge Rev（CVR，Clash 的图形前端）全局扩展脚本
 *         幂等哨兵清洗（栈重建算法）· Firefly（Adobe 生成式 AI 服务）精确放行版 - v260424
 *
 *   默认模式：拦截优先 + Firefly 精确例外放行
 *     - ENABLE_FIREFLY = true：精确放行 Firefly 推理请求，其余拦截保持不变
 *     - 鉴权端点连带影响：auth / cc-api / lcs 等端点随 Firefly 链同时放行；
 *       最终防线为 AdobeGCClient.exe → REJECT-DROP（静默丢包，需 ENABLE_PROCESS_RULE=true + TUN 模式，见风险边界）。
 *       注意：Creative Cloud.exe / CCXProcess.exe / CoreSync.exe 等进程同样
 *       访问鉴权链，进程规则仅覆盖 AdobeGCClient.exe，其余进程本脚本主动放弃拦截（原因见正文 §Firefly 连带影响）
 *       （详见 adobeAuthChain 注释及设计取舍）。
 *     - 适用场景：需要使用 PS 生成式填充、Firefly 等 Adobe AI 功能
 *
 * ══════════════════════════ ░░ 功能概览 ░░ ══════════════════════════
 *
 *   - 智能识别代理策略组（多级降级，排除组，兜底组）
 *   - 注入拦截规则（Adobe / Corel / Autodesk 等激活 / 遥测域名）
 *   - 注入代理 / 直连规则
 *   - 进程级规则（需管理员权限 + TUN（虚拟网卡透明代理）模式）
 *   - 激进阻断模块（默认关闭，需谨慎开启）
 *   - Hosts 级 DNS 拦截（黑洞/欺骗四种子模式，由 HOSTS_MODE 选择）
 *   - 规则防重复注入：幂等哨兵清洗（栈重建算法，O(N) 单次遍历，防堆叠）
 *   - 异常降级保护，详细运行日志
 *
 * ══════════════════════════ ░░ 使用说明 ░░ ══════════════════════════
 *
 *   1. 调整顶部配置区的功能开关（true / false）
 *   2. 在对应数组中增删域名即可，无需修改下方逻辑
 *   3. 保存后在 Clash Verge Rev 中重新加载配置文件即可生效，无需重启
 *
 */

function main(config) {

    // ══════════════════════ 配置区（按需调整） ══════════════════════
    // 所有 ENABLE_* 开关语义统一：true = 启用  false = 禁用
    // 修改后在 Clash Verge Rev（CVR，即本脚本所在的 Clash 图形前端）中重新加载订阅即可生效，无需重启

    const ENABLE_SCRIPT       = true;           // true = 启用脚本 / false = 受控禁用脚本（保留调试标记，非原样返回，详见下方 ENABLE_SCRIPT 分支说明）

    // ── 以下开关按 first-match（首条命中即生效，后续规则不再判断）注入优先级从高到低排列（声明顺序与注入顺序一致）──
    const ENABLE_BLOCK        = true;            // 拦截模块（Adobe/遥测/广告，最高优先级）
    const ENABLE_FIREFLY      = true;            // 精确放行 Firefly 推理请求
                                                  // ⚠️ 派生开关：实际生效取决于 ENABLE_BLOCK，见下方 effectiveFirefly 声明
                                                  // ⚠️ 需确保下方 PROXY_GROUP 变量已指向订阅中的有效节点组，否则 Firefly 请求无路由可走
                                                  // 连带影响：auth/cc-api 等鉴权端点同时放行；
                                                  // 最终防线为 AdobeGCClient.exe → REJECT-DROP（仅 ENABLE_PROCESS_RULE=true + TUN 模式下有效）
    const ENABLE_PROCESS_RULE = true;            // 进程规则模块（需 TUN（虚拟网卡透明代理）或 Service 模式 + 管理员权限；Service 模式与 TUN 均透明代理全流量，系统代理模式下完全无效）
    const ENABLE_PROXY        = true;            // 指定域名走代理模块
    const ENABLE_AGGRESSIVE   = false;           // 激进阻断模块（⚠️ 慎用，可能影响官网/插件商店访问）
                                                  // ⚠️ 已知受影响域名：adobe.io（插件市场/字体）、adsk.com（Autodesk 官网）、
                                                  //    officecdn（Office 更新/模板）、ieonline.microsoft.com（ActiveX/旧版 OA 系统）
                                                  // 注入位于 DIRECT 之前（必须）：aggressiveRules 含
                                                  // accounts.autodesk.com / ieonline.microsoft.com 等子域，
                                                  // 若排在 autodesk.com,DIRECT / microsoft.com,DIRECT 之后
                                                  // 会被父域规则遮蔽，永远无法生效（见注入区注释）
    const ENABLE_DIRECT       = true;            // 指定域名直连模块
    const ENABLE_HOSTS_TRICK  = true;            // Hosts DNS 拦截模块（黑洞/欺骗四种子模式，由 HOSTS_MODE 选择）
    // ❗ 生效前提：CVR → DNS 覆写 → 必须同时开启「启用 DNS」和「使用 Hosts」
    //    两个开关缺一不可，脚本无法感知 UI 层开关状态；未开启时本模块静默失效。
    //    注意：「使用系统 Hosts」与脚本注入的 Mihomo hosts 是两套完全独立的机制，无需开启前者。
    // ❗ 脚本注入 use-hosts:true 会被 CVR UI 层覆盖，必须在设置页手动开启，脚本无法替代手动操作。

    // Hosts 模式：ipv4-loopback(127.0.0.1) / ipv4-blackhole(0.0.0.0) /
    //            dual-stack(127.0.0.1+::1)  / blackhole(0.0.0.0+::)
    // ⚠️ 命名注意：blackhole（无前缀）与 ipv4-blackhole 并非等价——
    //   ipv4-blackhole → 单栈（IPv4 only）黑洞，对应 0.0.0.0
    //   blackhole      → 双栈（IPv4+IPv6）黑洞，对应 [0.0.0.0, "::"]，
    //                    等价于 ipv4-blackhole 的双栈扩展版（与 dual-stack 命名风格对称）
    //
    // 各模式连接失败类型（来源：Mihomo wiki + OS 网络栈行为）：
    //   ipv4-loopback  → 127.0.0.1          → ECONNREFUSED（本地无监听端口时，本地 TCP 栈返回 RST），欺骗拦截，更温和
    //   ipv4-blackhole → 0.0.0.0            → ENETUNREACH（Linux/Android）/ WSAEADDRNOTAVAIL（Windows），OS 直接拒绝路由，TCP SYN 不会发出；应用程序立即收到网络不可达错误，连接快速失败
    //   dual-stack     → 127.0.0.1 + ::1    → 同 ipv4-loopback，IPv4/IPv6 双栈欺骗拦截
    //   blackhole      → 0.0.0.0 + ::       → 同 ipv4-blackhole，IPv4/IPv6 双栈黑洞拦截（慎用：部分应用对 ENETUNREACH 容错处理不当，可能出现崩溃或异常行为）
    //
    // 各模式行为说明统一列在 HOSTS_MODE 声明之后，避免读者误认为默认模式是 blackhole。
    // 💡 推荐使用 "ipv4-loopback"：返回 127.0.0.1 产生 ECONNREFUSED（欺骗式拦截），
    // 比 ipv4-blackhole（0.0.0.0，OS 返回 ENETUNREACH）更温和——
    // 部分应用对 ENETUNREACH 的容错处理不如对 ECONNREFUSED 完善，极端情况下可能出现崩溃或持续重试。
    const HOSTS_MODE = "ipv4-loopback";

    // ── 典型配置组合参考（按需取消注释并调整上方开关，无需修改下方逻辑）──
    //
    // 【默认推荐】拦截 + Firefly 放行 + 代理 + 直连 + Hosts DNS 拦截（激进模式关闭）
    //   ENABLE_BLOCK=true  ENABLE_FIREFLY=true  ENABLE_PROCESS_RULE=true
    //   ENABLE_PROXY=true  ENABLE_DIRECT=true   ENABLE_HOSTS_TRICK=true
    //   ENABLE_AGGRESSIVE=false   HOSTS_MODE="ipv4-loopback"
    //
    // 【纯拦截模式】只拦截，不注入代理/直连规则，适合规则轻量化场景
    //   ENABLE_BLOCK=true  ENABLE_FIREFLY=false  ENABLE_PROCESS_RULE=false
    //   ENABLE_PROXY=false ENABLE_DIRECT=false   ENABLE_HOSTS_TRICK=true
    //   ENABLE_AGGRESSIVE=false
    //
    // 【激进模式】在默认推荐基础上额外开启激进阻断，彻底封堵 adobe.io / adsk.com 等
    //   ⚠️ 激进模式会影响官网/插件商店访问，开启前请仔细阅读 ENABLE_AGGRESSIVE 注释
    //   ENABLE_AGGRESSIVE=true   （其余开关与默认推荐相同）
    //
    // 【仅调试/禁用脚本】停用规则注入，保留调试标记，方便对比前后差异
    //   ENABLE_SCRIPT=false   （其余开关无效）

    // ── Firefly 派生开关：effectiveFirefly 是唯一有效的 Firefly 状态 ──────────
    // effectiveFirefly 无独立存储，是 ENABLE_FIREFLY && ENABLE_BLOCK 的派生状态（Derived State）；
    // 所有 Firefly 相关代码逻辑均使用此变量，而非原始 ENABLE_FIREFLY，
    // 防止"看起来开了但没生效"的用户误判（ENABLE_FIREFLY=true + ENABLE_BLOCK=false 时自动派生为 false）
    const effectiveFirefly = ENABLE_FIREFLY && ENABLE_BLOCK;

    // ══════════════════════ 防御性检查 ══════════════════════

    if (!config) return config;
    if (!Array.isArray(config.rules))           config.rules = [];
    if (!Array.isArray(config["proxy-groups"])) config["proxy-groups"] = [];

    // 功能依赖检查：effectiveFirefly 已处理依赖，此处仅记录日志供排查
    if (ENABLE_FIREFLY && !ENABLE_BLOCK) {
        console.warn("⚠️ 警告：ENABLE_FIREFLY=true 但 ENABLE_BLOCK=false");
        console.warn("   effectiveFirefly 已自动降级为 false，Firefly 放行不生效");
        console.warn("   原因：ENABLE_BLOCK=false 时拦截层整体不注入，放行规则无对应拦截层可豁免，注入无意义");
    }

    // ══════════════════════ ENABLE_SCRIPT 分支 ══════════════════════
    // 先清理上次遗留标记，再插入新标记，防止多次切换后堆叠
    // ── 哨兵清理前置（单次遍历重建，O(N)，幂等，处理任意数量的成对/孤儿哨兵）──
    // 此处在 ENABLE_SCRIPT 判断之前执行，即使 ENABLE_SCRIPT=false 时也清理旧哨兵，
    // 确保配置的幂等性，防多次切换后旧规则残留堆叠。
    //
    // ⚠️【算法选型说明：三方案对比】
    //
    // ① 废弃：filter 状态机（inSentinelBlock 标志位逐元素过滤）
    //   致命缺陷：孤儿 START 出现时（无对应 END），状态机进入 inSentinelBlock=true，
    //   将其后全部订阅规则无差别误删——灾难性误删。
    //
    // ② 废弃：while + findIndex + splice（"最近配对"方案）
    //   进化自原"第一个 START + 第一个 END"方案（后者嵌套 START 场景会连带删除有效规则）。
    //   缺陷：每轮循环两次 O(N) findIndex + 一次 O(N) splice，
    //         P 层堆叠时总时间复杂度 O(P×N)；splice 引发 V8 大块内存搬运。
    //
    // ③ 采用：单次遍历栈重建（Stack Rebuild）—— 当前方案
    //   原理：重建新数组，用栈记录每个 START 对应的 newRules 快照长度；
    //         遇 END 时将 newRules 截断至快照长度，等效于删除整个注入区间；
    //         孤儿 END 静默跳过；孤儿 START 的快照因无 END 匹配而留在栈中，
    //         循环结束后 newRules 中该区间内容已正常推入（不被截断），等效保留。
    //   复杂度：O(N) 时间 / O(N) 空间，无 splice 内存搬运。
    //   所有边界用例验证（node 实测）：
    //     [START,inj,END,sub]         → [sub]            ✅ 正常配对
    //     [START,validA,START,END]    → [validA]         ✅ 嵌套 START，保留区间外规则
    //     [END,sub]                   → [sub]            ✅ 孤儿 END
    //     [START,sub]                 → [sub]            ✅ 孤儿 START
    //     [START,A,START,B,END,C,END,sub] → [sub]        ✅ 正常嵌套，全部注入内容清除
    //     [START,inj1,END,START,inj2,END,sub] → [sub]    ✅ 连续两对，均清除
    // 哨兵标记（sentinel）：成对包裹本脚本注入的规则区间，供幂等清理时精确定位注入范围。
    // 采用合法但永不被真实流量命中的域名格式（.local 为保留 TLD），防止被订阅规则误伤。
    // 格式固定不可变：清理算法以精确等值（===）匹配，任何格式变化均会导致历史残留哨兵无法清除。
    const _sentinelStart = "DOMAIN,START-script-sentinel-marker.local,DIRECT";
    const _sentinelEnd   = "DOMAIN,END-script-sentinel-marker.local,DIRECT";
    {
        // 栈重建：单次遍历，O(N) 时间，O(N) 空间
        // stack 存储每个 START 被压入时 newRules 的快照长度（即注入区间在 newRules 中的起始索引）
        // newRules.splice(startIdx) 截断至快照长度，等效于撤销整个注入区间
        const newRules = [];
        const stack    = [];
        for (const rule of config.rules) {
            if (rule === _sentinelStart) {
                stack.push(newRules.length); // 记录快照：若后续遇到匹配 END，从此处截断
                continue;
            }
            if (rule === _sentinelEnd) {
                if (stack.length > 0) {
                    newRules.splice(stack.pop()); // 截断至快照长度，删除配对 START 之后的全部注入内容
                }
                // 孤儿 END（stack 为空）：静默跳过
                continue;
            }
            newRules.push(rule);
        }
        // stack 中剩余的孤儿 START 快照：其对应内容已作为普通规则推入 newRules（因无 END 未被截断），
        // 不需要额外处理——循环结束时 newRules 已正确包含孤儿 START 后的所有规则。
        config.rules = newRules;
    }

    if (!ENABLE_SCRIPT) {
        // ⚠️ 注意：ENABLE_SCRIPT=false 是「带调试钩子的受控禁用」，不是零修改的原样返回。
        //    此分支仍会执行两个操作：
        //      ① 清除上次遗留的 debug-script-disabled 标记（防堆叠）
        //      ② 在规则头部插入新的 debug-script-disabled 标记（供外部识别脚本禁用状态）
        //    因此返回的 config 与订阅原始状态有微小差异（多一条标记规则）。
        //    如需真正的原样返回（完全不修改 config），请直接 return config 并注释掉以下两行。
        //    如需保留 Hosts DNS 拦截但关闭规则注入，请保持 ENABLE_SCRIPT=true，
        //    并将 ENABLE_BLOCK / ENABLE_PROXY / ENABLE_DIRECT 等各子模块开关设为 false。
        // 精确等值匹配，与哨兵清洗保持一致，避免宽泛子串误删合法规则
        config.rules = config.rules.filter(r => r !== "DOMAIN,debug-script-disabled.marker.local,DIRECT");
        config.rules.unshift("DOMAIN,debug-script-disabled.marker.local,DIRECT");
        return config;
    }

    console.log("=".repeat(60));
    const _startTime = Date.now();
    const _ts = new Date().toTimeString().slice(0, 8);
    console.log(`📊 脚本引擎启动  [${_ts}]`);
    console.log(`配置名称: ${config.metadata?.name || "未知"}  |  备注: ${config["m_name"] || "无"}`);
    // config["m_name"] 为 CVR 订阅元数据中的用户自定义备注字段（非标准 Clash 字段，CVR 特有扩展）
    console.log("=".repeat(60));

    // ════════════════ 1. 智能识别代理策略组 ════════════════
    //
    // 逻辑：多级降级，兼容大多数订阅格式。
    // 无可用组时中止注入，防止 Mihomo 内核崩溃（见容错选取策略及出口断言）。

    let proxyGroupName = "节点选择"; // 声明占位，所有代码路径均会覆盖此值；
    // 全部策略失败时强制设为 "DIRECT" 并由出口断言拦截（见下方 Ghost Group 修复）
    // 💡 安全保证：识别逻辑通过 EXCLUDED_NAMES 明确排除了绝大多数不适合的出口；
    //    极端情况下（全部策略均失败）proxyGroupName 会被显式设为 "DIRECT"，
    //    由出口安全断言拦截并中止注入，完整降级为订阅原始规则，防止内核崩溃。

    // 策略组三级分类：
    //   排除组（EXCLUDED）：绝对不能用作代理出口，会导致代理规则失效（流量不经过任何代理节点）
    //   兜底组（FALLBACK）：可用但不优先，无更好选项时才降级使用（GLOBAL/全局 等）
    //   优选组（Eligible）：正常可用且优先选择的代理组
    const EXCLUDED_NAMES = new Set(["DIRECT", "REJECT", "COMPATIBLE", "DEFAULT", "MATCH"]);  // 排除组：绝对不能选
    const FALLBACK_NAMES = new Set(["GLOBAL"]);                                               // 兜底组：降级才选

    // 中文排除组正则（两段结构——这是有意设计，请勿合并为统一锚定写法）：
    //   前半段：^...$  精确匹配（加 $ 结尾锚定），覆盖"全部/全网/全球/所有/默认"等独立词
    //      → 避免「所有节点」「全局代理」等合法组名被误伤
    //      ⚠️ "全用"：中文代理组命名中极为罕见，如有实际案例请提 issue 评估是否保留
    //   后半段：无位置锚定，子串匹配，覆盖「直连国内」「全局直连」「拒绝广告」等任意位置变体
    //      → 「拒绝垃圾流量」含「拒绝」，被排除是有意为之——
    //        含"拒绝"之名的代理组本身即为拒绝出口（如广告拦截组），
    //        将其用作代理路由出口会导致所有流量被拒绝，排除是正确行为，并非误伤。
    //   ⚠️ "全局"已从此正则移出，由独立的 FALLBACK_CN_RE 负责识别（见 isEligibleGroup 修复说明）
    //   ⚠️ 已知盲区：「默认节点」等含「默认」的复合词组名不触发（精确词加 $ 锚定为设计取舍）
    //      此类指向 DIRECT 的订阅极为罕见；若遇到，可手动将 proxyGroupName 默认值改为正确组名
    const EXCLUDED_CN_RE = /^(?:全(?:部|网|用|球)|所有|默认)$|(?:直连|拒绝)/;

    // 中文兜底组：「全局」对应 FALLBACK_NAMES 中的 GLOBAL，语义与行为均对称
    // 修复前：EXCLUDED_CN_RE 包含"全局"，导致 isEligibleGroup("全局")=false，
    //         "全局"只能进最后兜底路径，而 GLOBAL 在前三轮优选策略中就能被选中——不对称。
    //         更深缺陷：兜底选中"全局"后，原版断言中 EXCLUDED_CN_RE.test("全局")=true，
    //         立即中止注入，净效果为零。两步修复（移出正则 + 断言放行）缺一不可。
    const FALLBACK_CN_RE = /^全局$/;

    // sanitizeName：统一零宽字符清理逻辑，消除 isEligibleGroup/isFallbackGroup 中的重复代码
    // @param {string} name - 原始组名，函数内部负责清洗；调用方无需预先清洗，传入原始字符串即可
    // @returns {string} 清洗后的组名（已移除不可见控制符并 trim）；非字符串输入返回空字符串
    // ⚠️ 攻击场景：典型攻击形如 "D\u2060IRECT"、"\u200B默认"、"DIR\u00ADECT"、"\u202EDIRECT"，
    //    视觉上与合法组名相同或倒序显示，但可绕过字符串比较
    // 清理范围（覆盖已知 Unicode Bidi（双向文本）控制符及不可见干扰字符，按码点升序排列）：
    //   \u00AD          软连字符（Soft Hyphen）
    //   \u061C          ARABIC LETTER MARK（ALM，阿拉伯字母方向标记，Unicode 6.3+ Bidi 格式字符）
    //   \u200B-\u200F   零宽空格 / 零宽不连接符 / 零宽连接符 /
    //                   LRM（LEFT-TO-RIGHT MARK，左到右方向标记）/ RLM（RIGHT-TO-LEFT MARK，右到左方向标记）
    //   \u202A-\u202E   双向文本方向控制符（LRE 左嵌/RLE 右嵌/PDF[弹出配对符，非 Override]/LRO 左覆写/RLO 右覆写）
    //   \u202C（PDF）为配对弹出符（POP DIRECTIONAL FORMATTING），非 Override 控制符
    //   \u2060          单词连接符（Word Joiner）
    //   \u2066-\u2069   Bidi 隔离控制符（LRI 左隔离/RLI 右隔离/FSI 强起始隔离/PDI 弹出隔离，Unicode 6.3+）
    //   \uFEFF          BOM（Byte Order Mark，字节顺序标记）/ 零宽不换行空格
    function sanitizeName(name) {
        if (typeof name !== "string") return "";
        return name.replace(/[\u00AD\u061C\u200B-\u200F\u202A-\u202E\u2060\u2066-\u2069\uFEFF]/g, '').trim();
    }

    // _isFallbackGroupCleaned：isFallbackGroup 的内部核心逻辑，接受已清洗字符串，跳过二次 sanitizeName。
    // 设计原因：isEligibleGroup 已对 name 清洗得到 trimmed，再传入 isFallbackGroup 时
    //   后者内部会再次调用 sanitizeName(trimmed)——sanitizeName 幂等但构成冗余遍历。
    //   拆分后 isEligibleGroup 直接调用此函数，isFallbackGroup 仍保持公开接口（清洗后调用此函数）。
    // @param {string} trimmed - 已经过 sanitizeName 清洗的组名
    function _isFallbackGroupCleaned(trimmed) {
        if (!trimmed) return false;
        if (FALLBACK_NAMES.has(trimmed.toUpperCase())) return true;
        if (FALLBACK_CN_RE.test(trimmed)) return true;
        return false;
    }

    // isEligibleGroup 修复说明：
    //   ① isFallbackGroup 提前返回 true：兜底组（GLOBAL/全局）允许进入前三轮优选策略，
    //      但前三轮优选策略均加了 !isFallbackGroup 过滤，实际仍优先选非兜底组；
    //      只有当前三轮优选策略全部无结果时，兜底组降级策略才专门选取兜底组。
    //   ② "全局"已从 EXCLUDED_CN_RE 移出，断言不再错误拦截合法选中的兜底组。
    // isEligibleGroup：判断组名是否"未被排除"（非毒化组）
    // ⚠️ 语义分层说明："合格（eligible）"≠"优选"——
    //   isEligibleGroup("全局") 返回 true，但前三轮优选策略内部会用 !isFallbackGroup() 二次过滤，
    //   "全局"仍被排出优选池，降级至兜底降级策略才被选中。
    //   "合格"仅表示"未被 EXCLUDED_NAMES/EXCLUDED_CN_RE 主动排除"，而非"适合作为主要出口"。
    function isEligibleGroup(name) {
        const trimmed = sanitizeName(name);
        if (!trimmed) return false;
        // ① 兜底组（如 GLOBAL/"全局"）返回 true，允许进入前三轮优选策略（前三轮会用 !isFallbackGroup 过滤）
        //    历史注意：修复前"全局"曾在 EXCLUDED_CN_RE 中，此行必须在其检查之前以防短路返回 false。
        //    修复后"全局"已移至 FALLBACK_CN_RE，此顺序不再是硬性要求，但保留以防回归。
        //    调用 _isFallbackGroupCleaned（内部函数）而非 isFallbackGroup，避免对已清洗的 trimmed 再次 sanitizeName。
        if (_isFallbackGroupCleaned(trimmed)) return true;
        if (EXCLUDED_NAMES.has(trimmed.toUpperCase())) return false;  // 英文排除组：大写后精确匹配
        if (EXCLUDED_CN_RE.test(trimmed)) return false;               // 中文排除组：正则匹配
        return true;
    }

    function isFallbackGroup(name) {
        // 公开接口：负责清洗原始输入，再调用内部核心逻辑
        return _isFallbackGroupCleaned(sanitizeName(name));
    }

    if (config["proxy-groups"].length > 0) {
        // 关键词列表（不含 "Global"，以免主动选中 GLOBAL 兜底组——GLOBAL 已由 FALLBACK_NAMES 单独处理；
        //             不含 "默认"，以免命中指向 DIRECT 的同名分组）
        // 大小写变体（"Proxy"/"PROXY"）均为有意保留：
        // g.name.includes(kw) 大小写敏感，订阅中两种写法均真实存在，勿合并或去重
        const KEYWORDS = [
            "节点选择", "手动选择", "选节点", "节点", "选择",
            "Proxy", "PROXY", "AUTO", "自动",
            "🚀", "飞机", "机场", "线路", "订阅"
        ];

        // [优选·关键词] 关键词 + 类型 + 多节点（最严格，优先匹配）
        let mainGroup = config["proxy-groups"].find(g => {
            const cleanName = sanitizeName(g?.name);  // 统一清洗，防止零宽字符导致关键词匹配失配
            if (!isEligibleGroup(cleanName) || isFallbackGroup(cleanName)) return false;
            const typeOk     = ["select", "url-test", "fallback"].includes(g?.type);
            const nameMatch  = KEYWORDS.some(kw => cleanName.includes(kw));
            const hasMany    = Array.isArray(g?.proxies) && g?.proxies.length > 3;
            const includeAll = (g?.["include-all"] === true || String(g?.["include-all"]).toLowerCase() === "true");
            return typeOk && (nameMatch || includeAll || hasMany);
        });

        // [优选·正则] 正则宽松匹配（次选，排除兜底组）
        if (!mainGroup) {
            mainGroup = config["proxy-groups"].find(g => {
                const cleanName = sanitizeName(g?.name);
                return isEligibleGroup(cleanName) && !isFallbackGroup(cleanName) &&
                    /代理|节点|选择|Proxy/i.test(cleanName) &&
                    Array.isArray(g?.proxies) && g?.proxies.length > 3;
            });
        }

        // [优选·类型] 类型约束（放宽数量，任意合法出口类型）
        // 增加 Array.isArray + length > 0 约束，防止选中空 proxies 的 select 组
        //   原版关键词/正则策略要求 length > 3，兜底组降级策略要求 length > 0，此策略此前无任何数量约束。
        if (!mainGroup) {
            mainGroup = config["proxy-groups"].find(g => {
                const cleanName = sanitizeName(g?.name);  // 预清洗，与策略1/2风格一致
                return isEligibleGroup(cleanName) && !isFallbackGroup(cleanName) &&
                    ["select", "url-test", "fallback"].includes(g?.type) &&
                    Array.isArray(g?.proxies) && g?.proxies.length > 0;
            });
        }

        // [兜底降级] 降级选取（GLOBAL/"全局" 等，优选策略全部失败时才触发）
        // ⚠️ 不能直接取首个元素，订阅第一个组可能是 DIRECT，导致代理规则全部失效
        // 保留类型过滤（与前三轮优选策略一致），防止选中 relay/load-balance 等不适合做出口的组
        if (!mainGroup) {
            const fallbackCandidates = config["proxy-groups"].filter(g =>
                isFallbackGroup(g?.name) &&
                ["select", "url-test", "fallback"].includes(g?.type) &&
                Array.isArray(g?.proxies) &&
                g?.proxies.length > 0
            );
            if (fallbackCandidates.length > 0) {
                mainGroup = fallbackCandidates[0];
                console.warn(`⚠️ 未找到优选代理组，降级使用兜底组 [${mainGroup.name}]`);
            }
        }

        // [一级容错选取] Ghost Group 安全兜底（全部前置策略失败时的最后屏障）────────────────
        // 根因：前四轮策略（关键词/正则/类型优选 + 兜底组降级）全部失败时，
        //       proxyGroupName 保持硬编码默认值"节点选择"。
        //       "节点选择"不在 EXCLUDED_NAMES 中，可通过出口断言，但订阅中可能根本不存在
        //       此组名，导致 Mihomo 内核启动失败（proxy group [节点选择] not found）。
        // 容错分两步：先放宽数量约束但保留类型过滤，再完全放宽类型约束（宁可选 relay 也优于注入不存在的组名）。
        if (!mainGroup) {
            // [一级容错] 放宽数量约束，保留类型过滤（允许空 proxies 组）
            mainGroup = config["proxy-groups"].find(g =>
                isEligibleGroup(g?.name) &&
                ["select", "url-test", "fallback"].includes(g?.type)
            );
            if (mainGroup) {
                console.error(`🚨 严重警告：关键词/正则/类型优选 + 兜底组降级策略均失败，触发一级容错选取`);
                console.error(`   已放宽 proxies 数量约束，保留类型过滤，抓取首个合法组 [${mainGroup.name}] (type: ${mainGroup.type})`);
                console.error(`   建议检查订阅的 proxy-groups 命名是否符合关键词列表`);
            }
        }
        if (!mainGroup) {
            // [最终容错] 完全放宽类型约束（任意合法组名，类型不限）
            mainGroup = config["proxy-groups"].find(g => isEligibleGroup(g?.name));
            if (mainGroup) {
                console.error(`🚨 严重警告：前置所有策略（含一级容错）均失败，触发最终容错选取`);
                console.error(`   已完全放宽类型约束，抓取首个合法组 [${mainGroup.name}] (type: ${mainGroup.type})`);
                console.error(`   ⚠️ 此组类型可能不适合做出口（如 relay/load-balance），建议检查订阅`);
            }
        }

        if (mainGroup?.name) {
            proxyGroupName = mainGroup.name;
            const groupFlag = isFallbackGroup(mainGroup.name) ? "⚠️" : "✅";
            console.log(`${groupFlag} 代理组识别成功: [${proxyGroupName}] (type: ${mainGroup.type})`);
        } else {
            // 容错策略全部失败：订阅中连一个合法组都没有
            // 将 proxyGroupName 设为 "DIRECT"，由下方出口安全断言拦截并中止注入，
            // 完整降级为订阅原始规则，防止 Mihomo 内核因找不到策略组而崩溃
            console.error("❌ 致命：订阅中没有任何可用的代理组，proxyGroupName 强制设为 DIRECT");
            console.error("   出口安全断言将拦截此值并中止规则注入，网络将走订阅原始规则");
            proxyGroupName = "DIRECT";
            if (config["proxy-groups"].length > 0) {
                console.log(`   已扫描的代理组：`);
                config["proxy-groups"].forEach((g, idx) => {
                    const status = !isEligibleGroup(g?.name) ? "❌" : (isFallbackGroup(g?.name) ? "⚠️" : "✅");
                    const count = g?.proxies?.length || 0;
                    console.log(`   ${idx + 1}. ${status} [${g?.name}] (${g?.type}, ${count} 节点)`);
                });
            }
        }
    } else {
        // 此前此处仅 console.warn("使用默认代理组名")，proxyGroupName 保持 "节点选择"，
        //         措辞暗示安全但实际危险：存在性断言会跳过空数组检查，"节点选择"若订阅中不存在则 Mihomo 崩溃。
        //         修复：强制设为 "DIRECT"，触发出口安全断言（EXCLUDED_NAMES 包含 DIRECT），中止规则注入。
        console.error("❌ 致命：proxy-groups 为空，强制降级 proxyGroupName=DIRECT，出口断言将中止注入");
        console.error("   网络将走订阅原始规则，不注入任何自定义规则，防止 Mihomo 内核启动失败");
        proxyGroupName = "DIRECT";
    }

    // 💡 Mihomo 规则语法中策略组名直接使用原始名称，空格 / emoji 均无需引号
    // 引号包裹反而会让内核把引号字符视为组名的一部分，导致 proxy not found 报错

    // ❗ 出口安全断言：防止 proxyGroupName 解析为排除出口导致拦截规则静默失效
    // 覆盖全部排除名：DIRECT / REJECT / COMPATIBLE / DEFAULT / MATCH 及中文等价排除词
    // 注：proxyGroupName 已通过 isEligibleGroup 过滤，此处再次清洗为防御纵深，避免极端路径绕过
    // 注：兜底组（GLOBAL/"全局"）已从 EXCLUDED_CN_RE 移出，合法选中的兜底组可通过断言
    {
        const _assertCleaned = sanitizeName(proxyGroupName);
        if (!_assertCleaned ||
            EXCLUDED_NAMES.has(_assertCleaned.toUpperCase()) ||
            EXCLUDED_CN_RE.test(_assertCleaned)) {
            console.error(`❌ 排除组断言触发：proxyGroupName 解析为排除出口 [${proxyGroupName}]`);
            console.error(`   拦截规则将等价于放行，脚本中止注入以保护安全边界`);
            return config;
        }
    }

    // ❗ 存在性断言：防止 Ghost Group（幽灵策略组）崩溃（proxy group [X] not found）
    // 出口安全断言只验证组名不是排除词，但不验证该组名是否真实存在于 proxy-groups 中。
    // 若 proxyGroupName 为默认值"节点选择"而订阅中没有此组，Mihomo 内核启动失败。
    // 此断言作为第二道防线，确保注入的组名在当前配置中真实存在。
    // 空 proxy-groups 情况已在上方 else 分支处理（proxyGroupName 强制设为 DIRECT，
    //         会被出口断言拦截），此处仅需处理非空时的存在性验证。
    if (config["proxy-groups"].length > 0) {
        const groupExists = config["proxy-groups"].some(g => g?.name === proxyGroupName);
        if (!groupExists) {
            console.error(`❌ 存在性断言触发：代理组 [${proxyGroupName}] 在当前配置中不存在`);
            console.error(`   注入此组名会导致 Mihomo 内核启动失败，脚本中止注入`);
            return config;
        }
    }

    // 💡 哨兵清理补充说明：哨兵必须是合法的 Clash 三段式规则（TYPE,VALUE,POLICY）。
    // ⚠️ 纯注释字符串（如 "# START"）会被内核视为非法规则，导致配置加载失败。
    // 哨兵格式：起始 DOMAIN,START-script-sentinel-marker.local,DIRECT
    //           结束 DOMAIN,END-script-sentinel-marker.local,DIRECT

    // ════════════ 2. 数据层（在此维护域名，无需动逻辑） ════════════
    //
    // 辅助函数：批量生成规则，减少重复代码
    const pushSuffix  = (domains, action, pool) => domains.forEach(d => pool.push(`DOMAIN-SUFFIX,${d},${action}`));
    const pushDomain  = (domains, action, pool) => domains.forEach(d => pool.push(`DOMAIN,${d},${action}`));
    const pushKeyword = (words,   action, pool) => words.forEach(k   => pool.push(`DOMAIN-KEYWORD,${k},${action}`));

    // ─────────────────────── Adobe 鉴权链（单一真相源）───────────────────────
    // [架构] 提取为独立数组，消除 adobeFireflyAllow 与 adobeSuffix 之间的历史双写。
    //
    // 路由动作由 effectiveFirefly 决定：
    //   effectiveFirefly=true  → pushSuffix(adobeAuthChain, proxyGroupName, LAYERS.allow) → 走代理
    //   effectiveFirefly=false → pushSuffix(adobeAuthChain, "REJECT",       LAYERS.block) → 走拦截
    //   两种场景下行为均与原版一致，单点维护，修改只需改此数组。
    //
    // ⚠️【Firefly 连带影响】auth.services.adobe.com / cc-api-cp.adobe.io 同时承载 CC 正版验证心跳。
    //   effectiveFirefly=true 时放行后，以下进程的鉴权请求均走代理，而进程规则仅覆盖 AdobeGCClient.exe：
    //     AdobeGCClient.exe  ← 由 processBlockRules REJECT-DROP（静默丢包，见下方说明）兜底（已覆盖）
    //     Creative Cloud.exe ← CC 桌面客户端含授权心跳（本脚本主动放弃拦截：心跳放行不触发重验证，TUN 进程规则本身不可靠）
    //     CCXProcess.exe     ← CC 扩展宿主进程（本脚本主动放弃拦截：同上）
    //     CoreSync.exe       ← CC 同步守护进程（本脚本主动放弃拦截：同上）
    //   取舍依据：非官方激活环境中，补丁通过阻断 AdobeGCClient.exe 的出站网络连接来绕过激活验证，
    //   其余进程的心跳即便放行也不会触发重新验证。进程规则本身需管理员+TUN，不可靠。
    //
    // ⚠️【QUIC（基于 UDP 的快速传输协议）豁免机制】Firefly 相关 .adobe.io 域名在 adobeUdpBlock 之前注入（first-match），
    //   其 UDP 流量先命中 allow 层走代理，adobeUdpBlock 的 adobe.io 通配不再执行。
    //   → 豁免效果由注入顺序自动保证（allow 层先于 adobeUdpBlock 入 pool），无需额外处理。
    //   ⚠️ 前提：此豁免仅在 Mihomo 能识别 SNI（Server Name Indication，TLS 握手中的服务器名称指示）时成立。
    //      ECH（Encrypted Client Hello，加密客户端握手，将 SNI 加密使 Sniffer 无法嗅探域名）场景下，
    //      allow 层 DOMAIN-SUFFIX 对 UDP 同样失效，此时 allow 层无法保护 Firefly QUIC 流量——
    //      但 adobeUdpBlock 的拦截也同样失效，
    //      二者一起失效，Firefly 的 QUIC 流量不受规则层干预（详见 adobeUdpBlock 末尾说明）。
    const adobeAuthChain = [
        // ── 已确认条目（抓包或官方资料可支撑）────────────────────────────────
        "ims-na1.adobelogin.com",                 // 登录令牌刷新（已确认）
        "adobeid-na1.services.adobe.com",         // Adobe ID 服务（已确认）
        "auth.services.adobe.com",                // Adobe ID 鉴权，Firefly Token 来源（已确认）
        "cc-api-cp.adobe.io",                     // CC 权限校验，含 Firefly 订阅验证（已确认）
        "cc-api-data.adobe.io",                   // CC 生成结果存储（已确认）
        "lcs-roaming.adobe.io",                   // 授权漫游，Firefly 订阅状态同步（已确认）

        // ── 待抓包确认条目（基于行为和命名推断，非官方文档支撑）──────────────
        // ⚠️ 设计取舍：以可用性优先于最小权限原则。
        //    以下域名尚无公开抓包资料确认其确切功能，但 Firefly 在实测中依赖这些端点，
        //    故默认放行。若追求最小权限，可手动将其移至 adobeSuffix（改为 REJECT）并
        //    重新测试 Firefly 功能是否正常，确认后再决定是否从本数组移除。
        "scdown.adobe.io",                        // 【推断】基于行为推断，未经抓包验证（Firefly 功能初始化相关，scdown 可能指 Substance Cloud Download）
        "lcs-cops.adobe.io",                      // 【推断】云端授权策略，推断为 Firefly 订阅鉴权；
                                                   //   社区有 2024+ PS 版本包含鉴权流量的反馈，但无公开抓包资料支撑，维持待确认
    ];

    // ─────────────────────── Adobe 激活 / 遥测核心拦截 ───────────────────────
    // 📌 关于 REJECT vs REJECT-DROP（Mihomo 的两种拒绝策略）：
    //    REJECT 发送 TCP RST / ICMP Unreachable，软件立即收到 ECONNREFUSED，"死心"进入离线模式，启动无卡顿，推荐用于遥测/授权域名
    //    REJECT-DROP 静默丢包，不回应任何数据包，软件 Socket 陷入 SYN_SENT 直至系统 TCP 超时；
    //      超时时长为估算值（非固定值），应用层 Socket 阻塞约 15–30s（含 TCP 重传轮次），
    //      实际取决于操作系统 TCP 重传配置（Windows 默认 SYN 重传总时长约 21s，可能更长或更短）。
    //      仅用于非官方补丁后门（backdoorSuffix/backdoorKeyword）和进程级规则，
    //      以此消耗恶意程序的连接池、拖慢其后台重试节奏，阻碍其快速识别连接已被阻断并切换备用域名。
    //
    // adobeAuthChain 条目已移出（路由动作由 effectiveFirefly 决定），此处为非鉴权拦截域名
    const adobeSuffix = [
        "adobestats.io",                          // 统计上报主域
        "activate.adobe.com",                     // 激活核心
        "lmlicenses.wip4.adobe.com",              // WIP License Manager（许可证管理器）
        "prod.adobegenuine.com",                  // Genuine Integrity Service（正版完整性验证服务）
        "na1e.services.adobe.com",                // Genuine 服务备用
        "adobedtm.com",                           // 部分遥测 / Tag Manager（标签管理器）
        "crs.cr.adobe.com",                       // License check（许可证检查）
        "cclibraries-defaults-cdn.adobe.com",     // CC Libraries 默认资源 CDN（内容分发网络）
        "adobesearch.adobe.io",                   // 搜索遥测
        "ffc-static-cdn.oobesaas.adobe.com",      // OOBE（Out-Of-Box Experience，开箱体验）静态资源
        "p13n.adobe.io",                          // 个性化遥测（p13n 为 personalization 的数字词缩略形式：p + 13个字母 + n，与 i18n/l10n 同类惯例，区别于首字母缩略词如 NASA）
        "ic.adobe.io",                            // Insight Collector（洞察收集器）
        "lcs-mobile.adobe.io",                    // 新版 CC 移动端授权
        "adobe-dns.adobe.com",                    // Adobe DNS 服务
        "adobe-dns-2.adobe.com",                  // Adobe DNS 备用节点 2
        "adobe-dns-3.adobe.com",                  // Adobe DNS 备用节点 3
        "practivate.adobe.com",                   // 预激活服务
        "lm.licenses.adobe.com",                  // License Manager（许可证管理器）
        "genuine.adobe.com",                      // 正版验证
        "oobesaas.adobe.com",                     // OOBE（开箱体验）验证（禁止弹登录框）
        "sstats.adobe.com",                       // 实时统计上报（新版 CC 框架）
        "entitlementauthz.adobe.com",             // 授权鉴权服务（2025-2026 新增）
        "assets.entitlement.adobe.com",           // 授权资产校验（2025-2026 新增）
    ];

    // ── 随机子域正则（单一真相源：adobeRegex 与 adobeUdpBlock 共用，禁止各自硬编码）──
    // 注：实际遥测子域通常为小写十六进制字符（0-9a-f），正则使用全字母数字范围（A-Za-z0-9）为保险覆盖，不影响正确性
    const _ADOBE_RAND_RE_STR      = "^[A-Za-z0-9]{8,12}\\.adobe\\.io$";
    const _ADOBESTATS_RAND_RE_STR = "^[A-Za-z0-9]{10}\\.adobestats\\.io$"; // adobestats.io 随机子域（固定10位，与 adobe.io 规则不同，独立声明）

    // 正则：拦截随机子域（遥测特征：8-12 位随机字符）
    const adobeRegex = [
        `DOMAIN-REGEX,${_ADOBE_RAND_RE_STR},REJECT-DROP`,                        // 遥测随机子域（8-12位字母数字，含大小写）
        // ⚠️ senseicore（10位）/ senseimds（9位）也满足此正则，但均为具名服务域名而非随机遥测子域；
        //    effectiveFirefly=true 时 adobeFireflyOnly 精确 SUFFIX 先命中，此正则对其无效。
        `DOMAIN-REGEX,${_ADOBESTATS_RAND_RE_STR},REJECT-DROP`,                   // adobestats.io 随机子域（10位，引用 _ADOBESTATS_RAND_RE_STR 单一真相源）
    ];

    // QUIC（Quick UDP Internet Connections，基于 UDP 的快速传输协议）/ UDP 拦截：强制 Adobe 回退至 HTTPS (TCP)，再被上方域名规则捕获
    // ❗ 生效前提：仅 TUN（虚拟网卡透明代理）模式。UDP 拦截规则在系统代理模式下完全无效
    // ⚠️ DOMAIN-SUFFIX / DOMAIN-REGEX / DOMAIN-KEYWORD 类规则依赖 Mihomo 能获取域名信息：
    //    Mihomo 通过 DNS 解析映射（已走 Mihomo DNS 的流量）或 Sniffer（嗅探 QUIC 握手 SNI）
    //    识别域名；纯 IP 形式的 UDP/QUIC 流量无域名信息可供匹配，DOMAIN 类规则对其无效。
    // ⚠️ PROCESS-NAME 规则不依赖 SNI 嗅探（通过系统 Socket 直接获取进程信息），
    //    是 QUIC+ECH（SNI 被加密，域名匹配失效）场景下最有效的兜底手段
    const adobeUdpBlock = [
        // ⚠️ 以下各条均依赖 Mihomo DNS 映射或 Sniffer SNI 嗅探才能识别域名；
        //    纯 IP 形式 QUIC 流量及 ECH 加密 SNI 场景下，DOMAIN 类规则对此无效（见末尾说明）
        "AND,((NETWORK,UDP),(DOMAIN-SUFFIX,adobe.io)),REJECT-DROP",           // 阻断 adobe.io 所有 QUIC 流量，强制回退 TCP
        "AND,((NETWORK,UDP),(DOMAIN-SUFFIX,adobestats.io)),REJECT-DROP",      // 阻断统计域 QUIC 流量
        "AND,((NETWORK,UDP),(DOMAIN-SUFFIX,adobe.com)),REJECT-DROP",          // 阻断 adobe.com 所有 QUIC 流量
        // ⚠️ 与此条 AND,((NETWORK,UDP),(DOMAIN-REGEX,...)) 规则同样依赖 dns.sniffer 解析 QUIC 握手 SNI 才能识别域名；
        //    ECH（Encrypted Client Hello，加密客户端握手）场景下 SNI 被加密，此条与该 REGEX 规则同样失效。
        `AND,((NETWORK,UDP),(DOMAIN-REGEX,${_ADOBE_RAND_RE_STR})),REJECT-DROP`, // 阻断随机子域 QUIC（遥测特征，8-12位，引用 _ADOBE_RAND_RE_STR 单一真相源）
        "AND,((DST-PORT,443),(NETWORK,UDP),(DOMAIN-KEYWORD,adobe)),REJECT-DROP", // 兜底：443/UDP + adobe 关键词，覆盖未列举子域
        // ⚠️ 可靠性存疑：纯 UDP 流量无 TLS SNI 时，DOMAIN-KEYWORD 可能无域名信息可供匹配，
        //    Mihomo 需开启 Sniffer（dns.sniffer）解析 QUIC 握手 SNI 才能识别域名；
        //    实际生效取决于 Mihomo 版本，不可作为唯一防线，上方精确规则为主要覆盖。
        //
        // ⚠️【ECH 架构级边界】QUIC + ECH（Encrypted Client Hello，加密客户端握手，将 SNI 加密）场景下：
        //    → 本数组全部 DOMAIN 类规则对 QUIC 流量完全失效（无法识别域名）
        //    → 同时，allow 层（adobeAuthChain / adobeFireflyOnly）的 DOMAIN-SUFFIX 豁免也失效
        //    → 结论：ECH 场景下 allow 层与 block 层的域名规则同时失效，规则层无法干预 QUIC 流量
        //    → 唯一有效兜底：PROCESS-NAME 规则（直接获取系统 Socket 进程信息，不依赖 SNI）
    ];

    // Adobe WebSocket 遥测（2025-2026 新增：通过 WSS（WebSocket Secure，加密 WebSocket 协议）绕过普通 HTTP 拦截）
    // ⚠️ 使用 DOMAIN 精确匹配（而非 DOMAIN-SUFFIX）：
    //    DOMAIN-SUFFIX,wss.adobe.io 只覆盖 wss.adobe.io 本身及其后代（如 sub.wss.adobe.io），
    //    不覆盖同级的 wss2.adobe.io（它是 adobe.io 的另一个子域）。
    //    WSS 走 TCP 时 adobeUdpBlock 无法保护（仅拦截 UDP），精确匹配是正确选型。
    const adobeWsDomain = [
        "wss.adobe.io",                           // WebSocket Secure 遥测通道（新版 CC 框架）
    ];

    // ─────────────── Firefly 生成式 AI 专属放行域名（不含鉴权链）───────────────
    // 原则：精确放行 Firefly 推理请求，保留其余激活/遥测域名的拦截。
    //
    // 【域名分类】
    // 鉴权链：已统一到 adobeAuthChain（单一真相源），此处仅含 Firefly/Clio/Sensei 专属推理域名
    // Firefly/Clio/Sensei 推理域名（新增，非 adobeSuffix 原有条目）：
    //   firefly.adobe.com / firefly.adobe.io / firefly-api.adobe.io /
    //   firefly-cliov2.adobe.com / clio.adobe.io / clio-prober.adobe.io /
    //   clio-assets.adobe.com / senseicore.adobe.io / senseimds.adobe.io
    //
    // ⚠️【连带影响】鉴权链（adobeAuthChain）同时承载 CC 正版验证心跳，
    //           放行后激活拦截的最终防线为 PROCESS-NAME,AdobeGCClient.exe → REJECT-DROP
    //           （需 ENABLE_PROCESS_RULE=true + TUN 模式 + 管理员权限，进程规则本身不可靠）。
    //           其余未覆盖进程详见 adobeAuthChain 注释中的 §Firefly 连带影响。
    // 关于 adobeUdpBlock 与 Firefly .adobe.io 域名的 QUIC 豁免机制：
    //   pool 注入顺序为：adobeAuthChain+adobeFireflyOnly → adobeSuffix → adobeRegex → adobeUdpBlock
    //   effectiveFirefly=true 时，allow 层的精确 DOMAIN-SUFFIX 规则（如
    //   firefly-api.adobe.io / clio.adobe.io 等）已在 adobeUdpBlock 之前入 pool。
    //   Mihomo first-match（首条命中生效）：Firefly 域名的 UDP 流量先命中 allow 层走代理，
    //   adobeUdpBlock 的 AND,((NETWORK,UDP),(DOMAIN-SUFFIX,adobe.io)) 不再执行。
    //   → 豁免效果由注入顺序自动保证（allow 层先于 adobeUdpBlock 命中），无需额外处理。
    //   ⚠️ 前提：此豁免仅在 Mihomo 能识别 SNI 时成立（DNS 映射或 Sniffer 嗅探）。
    //      ECH 场景下 allow 层与 adobeUdpBlock 的域名规则同时失效，规则层无法干预 QUIC 流量，
    //      此时豁免与拦截均不生效（见 adobeUdpBlock 末尾 ECH 架构级边界说明）。
    const adobeFireflyOnly = [
        // Firefly 推理核心
        "firefly.adobe.com",                      // Firefly 主服务入口
        "firefly.adobe.io",                       // Firefly API（.io 端点）
        "firefly-api.adobe.io",                   // PS 生成式填充调用入口
        "firefly-cliov2.adobe.com",               // Firefly Clio v2 模型接口
        // Clio 生成模型
        "clio.adobe.io",                          // Clio 生成模型主接口
        "clio-prober.adobe.io",                   // Clio 功能可用性探针
        "clio-assets.adobe.com",                  // Clio 生成结果资源 CDN（内容分发网络）
        // Sensei AI 平台
        "senseicore.adobe.io",                    // Sensei 推理服务核心
        "senseimds.adobe.io",                     // Sensei 模型分发服务（MDS = Model Distribution Service）
    ];

    // ─────────────────────── CorelDRAW 全家桶激活拦截 ───────────────────────
    // ⚠️ 不拦截整个 corel.com，否则官网无法访问（见 directRules）
    const corelSuffix = [
        "activation.corel.com",                   // 激活验证入口
        "licensing.corel.com",                    // 许可证服务
        "license1.corel.com",                     // 许可证服务器 1
        "license2.corel.com",                     // 许可证服务器 2
        "mc.corel.com",                           // 会员验证
        "ipm.corel.com",                          // In-Product Messaging（产品内弹窗消息）服务
        "ipm2.corel.com",                         // IPM 备用节点
        "telemetry.corel.com",                    // 统计上报
        "world.corel.com",                        // 消息推送 + 序列号黑名单检查
    ];

    // ───────────── Autodesk (CAD / 3dsMax / Maya) 激活与遥测拦截 ─────────────
    const autodeskSuffix = [
        "adlm.cloud.autodesk.com",               // 许可验证主域（最重要，ADLM = Autodesk Desktop Licensing Module）
        "adlm-autodesk.com",                     // ADLM 独立许可域
        "licensing-autodesk.com",                // 许可证服务备用域
        "api.entitlements.autodesk.com",         // 授权 API 接口
        "telemetry.autodesk.com",                // 遥测上报
        "api.telemetry.autodesk.com",            // 遥测 API
        "usage.autodesk.com",                    // 使用统计上报
        "metric.autodesk.com",                   // 性能指标上报
        "crashreport.autodesk.com",              // 崩溃报告上传
        "dlm.autodesk.com",                      // Download Manager（下载管理器）版本检查
        "adsklicensing.com",                     // Autodesk 许可服务独立域
        "clic.autodesk.com",                     // 核心授权验证（CLIC = Cloud Licensing）
        "genuine-software.autodesk.com",         // 正版验证服务
        "edge.activity.autodesk.com",            // 活动/行为追踪
        "developer.api.autodesk.com",            // 开发者 API（含许可验证）
        "autodesk.com.edgekey.net",              // Akamai CDN 节点（授权验证回源）
        "crp.autodesk.com",                      // 云渲染授权（CRP = Cloud Rendering Platform）
        "autodesk.flexnetoperations.com",        // FlexNet（许可证管理框架）许可服务
    ];
    const autodeskDomain = [
        "ipm-aem.autodesk.com",                  // 弹窗消息（精确匹配，防误伤子域）
    ];
    // DOMAIN-KEYWORD 杀伤力较强，仅针对 Autodesk 特有模块关键词
    //
    // ──────────── BLOCK vs AGGRESSIVE 重叠说明（设计意图，禁止清理）────────────
    // "entitlement.autodesk" 同时出现在：
    //   ① autodeskKeyword（此处）→ ENABLE_BLOCK=true 时生效，REJECT
    //      DOMAIN-KEYWORD 为子串匹配，覆盖域名中含 "entitlement.autodesk"（含点）的域名，
    //      如 entitlement.autodesk.com。
    //      ⚠️ 注意：api.entitlements.autodesk.com 因含 "entitlements"（entitlement 后跟 s 再跟点），
    //         子串 "entitlement.autodesk"（entitlement 后直接跟点）在其中不存在，不被此 KEYWORD 命中。
    //         简言之：匹配 entitlement.autodesk.com，但不匹配 entitlements.autodesk.com（多了一个 s）。
    //         该域名由 autodeskSuffix 中的 DOMAIN-SUFFIX 精确条目独立覆盖，两者不可互相替代。
    //   ② aggressiveRules → DOMAIN-SUFFIX,entitlement.autodesk.com,REJECT-DROP
    //      仅在 ENABLE_AGGRESSIVE=true 时额外生效
    //
    // 两种开关状态下的行为分析：
    //   ENABLE_BLOCK=true, ENABLE_AGGRESSIVE=false（默认）：
    //     → autodeskKeyword REJECT 先命中，aggressiveRules 不注入，无冲突
    //     → "entitlement.autodesk" 是 entitlement.autodesk.com 的唯一覆盖，必须保留
    //   ENABLE_BLOCK=true, ENABLE_AGGRESSIVE=true：
    //     → autodeskKeyword REJECT（KEYWORD 规则）先于
    //       aggressiveRules SUFFIX（SUFFIX 规则）命中（pool 注入顺序决定）
    //     → aggressiveRules 中的 entitlement.autodesk.com SUFFIX 规则被遮蔽，实质冗余但无害
    //   ENABLE_BLOCK=false, ENABLE_AGGRESSIVE=true（极少使用）：
    //     → autodeskKeyword 不注入，aggressiveRules SUFFIX 独立生效
    //     → 此时两者各司其职，无冲突
    //
    // 结论：重叠是有意设计（纵深覆盖），在所有开关组合下均无副作用，
    //       无需合并或删除任一条目。
    // ─────────────────────────────────────────────────────────────
    const autodeskKeyword = [
        "adlm",                                  // Autodesk Desktop Licensing Module（桌面许可证模块）
        "telemetry.autodesk",                    // Autodesk 遥测模块关键词兜底
        "entitlement.autodesk",                  // Autodesk 授权模块关键词兜底（见上方 BLOCK vs AGGRESSIVE 说明注释块）
    ];

    // ─────────────── 第三方非官方补丁后门（高危，强烈建议保留）───────────────
    // 这些域名会回传设备信息，甚至下发新的拦截指令
    const backdoorSuffix = [
        "966v26.com",                            // 非官方修改补丁后门主域（回传设备信息）
        "vposy.com",                             // 知名非官方补丁作者域名（Adobe/Office）
        "api.pzz.cn",                            // 国内非官方补丁回传接口
        "cc-cdn.com",                            // 伪装成 Adobe CDN（内容分发网络）的非可信域
    ];
    // 关键词兜底：覆盖 966v26.net / cdn.966v26.org 等非 .com TLD（顶级域名，Top-Level Domain）变种，
    // REJECT-DROP 策略与 backdoorSuffix 一致
    const backdoorKeyword = ["966v26"];

    // ──────────── IDM / Bandicam / Wondershare 等其他软件激活拦截 ────────────
    const idmSuffix = [
        "registeridm.com",                       // IDM 注册验证域
        // "internetdownloadmanager.com",        // ⚠️ 已注释：主域误伤官网，改用下方精确子域
        "secure.internetdownloadmanager.com",    // 序列号验证接口
        "mirror.internetdownloadmanager.com",    // 更新镜像服务器
        "mirror2.internetdownloadmanager.com",   // 更新镜像服务器
        "mirror3.internetdownloadmanager.com",   // 更新镜像服务器
        "idm-patch.com",                         // IDM 非官方补丁域（安全风险）
        "idm-update.com",                        // IDM 非官方更新域（安全风险）
    ];
    const idmKeyword = ["tonec"];

    const wondershareSuffix = [
        "activation.wondershare.com",             // Wondershare 激活验证入口
        "license.wondershare.com",                // 许可证验证服务
        "wondershare.cc",                         // Wondershare 海外追踪/统计域
        "wondershare.cn",                         // Wondershare 国内遥测/统计域
        // "iskysoft.com",  // ⚠️ 已注释：主域即官网，无已知专用验证子域，
        //                  //   拦截主域将导致官网无法访问。如有抓包确认的验证子域，请替换为精确条目。
        // "imyfone.com",   // ⚠️ 已注释：同上，主域即官网，无已知专用验证子域。
    ];

    // 当前为空（扩展占位）：主域 SUFFIX 规则因误伤官网均已移至注释，精确子域见 miscSoftwareDomain。
    // 保留此数组作为结构骨架，length 守卫（见注入区）防止未来维护者误删注释后展开空数组触发无效调用。
    const miscSoftwareSuffix = [
        // "bandicam.com",    // ⚠️ 已注释：主域误伤官网，改用下方精确子域
        // "bandisoft.com",   // ⚠️ 已注释：主域误伤官网，改用下方精确子域
        // "xmind.app",       // ⚠️ 已注释：主域误伤官网（含正版用户同步/分享功能），改用下方精确子域
        // "xmind.net",       // ⚠️ 已注释：主域误伤官网（XMind 8 下载/插件），改用下方精确子域
        // "listary.com",     // ⚠️ 已注释：主域误伤官网，改用下方精确子域
        // ⚠️ typora.io 是官网主域，直接拦截会导致插件/主题无法下载
        // 精确拦截授权验证子域，放行主站：typora.io / store.typora.io
    ];
    const miscSoftwareDomain = [
        // ──────────────────────── Bandisoft 家族 ─────────────────────────
        "cert.bandicam.com",    // Bandicam 正版证书/激活验证核心
        "ssl.bandisoft.com",    // Bandizip/Bandicam 全家桶授权验证核心
        "dl.bandisoft.com",     // 更新下载/版本心跳（不影响离线使用；如需更新可临时放开）

        // ───────────────────────────── XMind ─────────────────────────────
        // 来源：多份抓包记录及 hosts 屏蔽教程（CSDN / 博客园 / 52pojie）
        // XMind 2020+（Electron）与 XMind 8（Java）均通过以下域名验证授权：
        "www.xmind.app",        // XMind 2020+ 授权验证主接口（Electron 版）
        "www.xmind.net",        // XMind 8 授权验证接口（Java 版）/ 国际更新检查
        "www.xmind.cn",         // XMind 中文站授权验证 / 国内更新检查
        "dl2.xmind.cn",         // XMind 8 更新安装包下载服务器（弹出更新提示的来源）
        // ⚠️ 注意：XMind 2020+ 的 api.xmind.net / api.xmind.app 等 API 子域名
        // 无公开抓包资料确认，未贸然添加。如将来有抓包证据请补充于此。

        // ──────────────────────────── Listary ────────────────────────────
        // 来源：社区抓包记录（非官方文档），support 子域为目前唯一有记录的联网端点
        // 其他子域名（api.listary.com 等）无公开资料，不添加以免误判
        "support.listary.com",  // 激活/授权验证接口（精确匹配，防误伤主站）

        // ──────────────────────── WinRAR (RARLAB) ────────────────────────
        // 来源：CVE-2021-35052 安全报告；Wireshark/Burp 抓包记录；rarlab.com 官网
        "notifier.rarlab.com",  // 广告弹窗 / 试用到期通知页面（主要骚扰来源）
                                // CVE-2021-35052：该域名曾被中间人攻击利用执行任意代码
                                // 屏蔽此域名同时消除安全风险 + 关闭广告弹窗

        // ──────────────────────────── Typora ─────────────────────────────
        "license.typora.io",    // Typora 授权验证接口
        "verify.typora.io",     // Typora 激活校验
    ];

    // ────────────────── 微软 & Office 遥测（不影响正常使用）──────────────────
    // 微软遥测改用 REJECT（立即返回 RST，避免 TCP 重传开销）
    const msTelemSuffix = [
        "telemetry.microsoft.com",               // Windows/Office 遥测主域
        "v20.events.data.microsoft.com",         // Windows 诊断数据 v2.0
        "v10.events.data.microsoft.com",         // Windows 诊断数据 v1.0
        "nexus.officeapps.live.com",             // Office 遥测上报
        "officeclient.microsoft.com",            // Office 客户端统计
        "vortex.data.microsoft.com",             // Windows 错误报告
        "settings-win.data.microsoft.com",       // Windows 设置同步遥测
        "watson.telemetry.microsoft.com",        // Watson 崩溃报告服务
    ];

    // ────────────────────────── 国产广告联盟 / 遥测 ──────────────────────────
    const cnAdSuffix = [
        // WPS
        "ups.k0s.gk.kingsoft.com",               // WPS 升级推送服务
        "pcfg.wps.cn",                           // WPS 配置/广告下发
        "wps.com.cn",                            // WPS 国内统计域
        "wpsgold.wpscdn.cn",                     // WPS 广告资源 CDN（内容分发网络）
        // "sync.wps.cn",                        // ⚠️ 已注释：WPS 云文档同步，拦截后云同步失效
        // 海康威视（仅精确子域，主域不拦截）
        // ⚠️ 若使用海康摄像头/NVR/DVR 设备，建议注释以下三条：
        //   upgrade.hikvision.com  拦截后设备无法检测固件更新
        //   ezdns.hikvision.com    拦截后 DDNS（Dynamic DNS，动态域名解析）功能失效，远程访问中断
        //   cloudmsg.hikvision.com 拦截后萤石云/APP 推送通知失效
        "upgrade.hikvision.com",                 // 海康固件升级检查（可触发静默下载）
        "ezdns.hikvision.com",                   // 海康 DDNS（动态域名解析）回传（拦截后远程访问中断）
        "cloudmsg.hikvision.com",                // 海康云消息推送
        // 向日葵远程（仅遥测子域，oray.com 主域不可拦截）
        "sunloginlog.oray.com",                  // 向日葵日志上报
        "report.oray.com",                       // 向日葵行为上报
        // ToDesk 远程
        "log.todesk.com",                        // ToDesk 日志上报
        "report.todesk.com",                     // ToDesk 遥测上报
        // 百度输入法
        "shurufa.baidu.com",                     // 百度输入法云服务
        "input.baidu.com",                       // 百度输入法联网同步
        // 搜狗输入法（精确子域补充，主域 sogou.com 不拦截）
        // "api.sogoucloud.com",                 // ⚠️ 已注释：搜狗输入法云端接口，域名拼写无公开抓包资料确认，待验证后启用
        // 腾讯 Bugly 崩溃上报 SDK（Software Development Kit，软件开发工具包；大量国产软件集成，含设备指纹）
        "bugly.qq.com",                          // 腾讯 Bugly 崩溃上报 SDK
        // 字节跳动系（抖音/剪映/头条/西瓜共用）
        "log.snssdk.com",                        // 字节系客户端日志上报（头条/西瓜等）
        "i.snssdk.com",                          // 字节跳动国内 SDK（软件开发工具包）遥测
        "log.byteoversea.com",                   // 字节跳动海外日志上报（抖音/剪映共用）
        // 剪映专业版（CapCut）
        "metrics.capcut.com",                    // 剪映遥测上报
        "log.capcut.com",                        // 剪映日志收集
        // QQ音乐
        // "qqmusic.qq.com",                     // ⚠️ 待验证：命名无遥测特征前缀，可能是功能性主域，抓包确认前暂不拦截
        "stat.music.qq.com",                     // QQ音乐统计上报
        // 酷狗音乐
        "log.kugou.com",                         // 酷狗日志上报
        // 酷我音乐
        "stat.kuwo.cn",                          // 酷我统计上报
        // 网易云音乐桌面版
        "log.music.163.com",                     // 网易云音乐日志上报
        // 哔哩哔哩桌面客户端
        "data.bilibili.com",                     // B站数据上报
        "api.log.bilibili.com",                  // B站日志接口
        // 小米 / MIUI（手机系统域名，PC 端不会主动请求；若代理手机热点流量则生效）
        "stat.miui.com",                         // 小米统计 SDK
        "data.miui.com",                         // MIUI 数据采集
        "tracking.miui.com",                     // MIUI 行为追踪
        "logservice.miui.com",                   // MIUI 日志服务
        "sdkconfig.ad.xiaomi.com",               // 小米广告 SDK（软件开发工具包）配置下发
        // 钉钉
        "analytics.dingtalk.com",                // 钉钉遥测上报
        // 飞书
        "log.feishu.cn",                         // 飞书日志上报
        // 迅雷
        "ad.xunlei.com",                         // 迅雷广告接口
        "etl.xl7.xunlei.com",                    // 迅雷遥测上报（ETL = Extract-Transform-Load）
        // 百度网盘
        "update.pan.baidu.com",                  // 百度网盘强制更新推送
        // 腾讯广告
        "e.qq.com",                              // 腾讯效果广告
        "gdt.qq.com",                            // 广点通广告联盟
        "l.qq.com",                              // 腾讯广告追踪链路
        "toptips.qq.com",                        // QQ 弹窗提示推送
        "minibrowser.qq.com",                    // QQ 内置迷你浏览器广告
        // 阿里 / 友盟
        // ⚠️【副作用】umeng.com 为大量国内正规 App 集成的友盟 SDK（统计分析）主域，
        //    拦截后这些 App 首次启动可能因初始化统计失败而出现功能异常或卡顿。
        //    若发现特定软件启动异常，可考虑临时放开此条。
        "umeng.com",                             // 友盟统计 SDK 主域（⚠️ 副作用：部分正规 App 依赖此域初始化，见上方说明）
        "umengcloud.com",                        // 友盟云端统计
        "alimama.com",                           // 阿里妈妈广告联盟
        "adashbc.ut.alibaba.com",                // 阿里广告投放接口
        "update.aliyun.com",                     // 阿里云客户端强制更新
        // 百度广告
        "pos.baidu.com",                         // 百度联盟广告投放
        "hm.baidu.com",                          // 百度统计（Heatmap，热图分析）
        "cpro.baidu.com",                        // 百度内容推荐广告
        // 字节 / 穿山甲
        "pangle.io",                             // 穿山甲广告联盟（字节跳动）
        "pangolin-sdk-toutiao.com",              // 穿山甲 SDK 上报域
        "ad.toutiao.com",                        // 头条广告投放接口
        // 360（主域 360.cn 不拦截，精确拦截广告/弹窗/遥测/推广子域）
        // ⚠️ 直接拦截 360.cn 主域会屏蔽官网/下载中心/所有子域，改用以下精确条目
        "ad.360.cn",                             // 360 广告投放
        "adv.360.cn",                            // 360 广告系统备用
        "union.360.cn",                          // 360 广告联盟接入
        "stat.360.cn",                           // 360 统计遥测上报
        "log.360.cn",                            // 360 日志上传
        "push.360.cn",                           // 360 推送通知
        "notice.360.cn",                         // 360 弹窗通知
        "update.360.cn",                         // 360 强制更新推送
        "up.360.cn",                             // 360 升级服务
        "360safe.com",                           // 360 安全云端检测
        "360tp.com",                             // 360 推广/广告追踪
        "360kuai.com",                           // 360 快速通道广告
        "qhres.com",                             // 奇虎资源 CDN（广告素材）
        "qhstatic.com",                          // 奇虎静态资源（广告框架）
        "qhimg.com",                             // 奇虎图片 CDN（广告图片）
        "qhupdate.com",                          // 360 强制更新推送
        // 2345 全家桶
        "2345.com",                              // 2345 导航/弹窗主域
        "2345.net",                              // 2345 备用域
        "2345p.com",                             // 2345 推广域
        "2345uns.com",                           // 2345 升级推送
        "50yc.com",                              // 2345 旗下游戏推广
        // 驱动精灵等
        "160.com",                               // 驱动人生关联广告域
        "updrv.com",                             // 驱动人生更新推送
        "drivergenius.com",                      // 驱动精灵遥测/推广
        // 鲁大师（主域已注释，保留子域精确拦截：游戏盒跑分后的广告全家桶）
        // "ludashi.com",                        // ⚠️ 注释主域：避免误伤官网，使用子域精确拦截
        "lms.ludashi.com",                       // 鲁大师游戏盒跑分后的广告全家桶
        // 金山毒霸
        "cmcm.com",                              // 猎豹移动广告联盟
        "ijinshan.com",                          // 金山猎豹旗下追踪域
        "duba.com",                              // 金山毒霸广告/弹窗
        // 搜狗（精确子域见 cnAdDomain）
        "inte.sogou.com",                        // 搜狗整合服务遥测
        "theta.sogou.com",                       // 搜狗 A/B 测试上报
        "sogoucdn.com",                          // 搜狗 CDN（广告素材）
        "ie.sogou.com",                          // 搜狗 IE 插件推广
        "metasogou.com",                         // 搜狗元数据追踪
        // Flash（已停服）
        "flash.cn",                              // Adobe Flash 国内分发域（已停服，防止残留弹窗）
        // PotPlayer（主域已注释，保留子域精确拦截侧边栏广告）
        // "daum.net",                           // ⚠️ 注释主域：韩国最大门户，拦截影响搜索/新闻/邮件
        "kakaocorp.com",                         // 关联公司统计上报
        "p1-pc.daum.net",                        // 精准拦截侧边栏广告
        "p2-pc.daum.net",                        // PotPlayer 侧边栏广告节点 2
        "p1-pc.pdk.daum.net",                    // PotPlayer 广告 CDN 节点
    ];
    const cnAdDomain = [
        // 搜狗精确域名（避免误伤 sogou.com 整体）
        "pinyin.sogou.com",                      // 搜狗拼音输入法弹窗
        "news.sogou.com",                        // 搜狗新闻推送
        "toast.sogou.com",                       // 搜狗 Toast（弹出通知）弹窗通知
        "timer.sogou.com",                       // 搜狗定时任务上报
        "update.sogou.com",                      // 搜狗强制更新
        "config.sogou.com",                      // 搜狗远程配置下发
        "py.sogou.com",                          // 搜狗拼音云服务
        "snapshot.sogou.com",                    // 搜狗快照追踪
    ];

    // ─────── Mozilla / Firefox 遥测（REJECT 立即终止连接，减少浏览器重试） ───────
    const mozillaSuffix = [
        "telemetry.mozilla.org",                 // Firefox 遥测主域
        "incoming.telemetry.mozilla.org",        // 遥测数据接收端点
        "experiments.mozilla.org",               // Firefox 实验性功能遥测
        "healthreport.mozilla.org",              // Firefox 健康报告上报
        "metrics.mozilla.com",                   // 指标统计
        // ⚠️ 副作用：拦截后 Firefox 地址栏持续显示「网络连接可能受限」警告，
        //    对用户有明显可感知的负面体验（该请求本身无意义，但与遥测不同，拦截会影响 UI 显示）
        //    如需屏蔽此无意义探测请求，请取消以下注释：
        // "detectportal.firefox.com",           // Firefox 网络连接检测（会产生无意义请求），拦截后 Firefox 地址栏持续报"网络连接可能受限"
    ];

    // ────────────────────── Google / Chrome 隐私追踪 ──────────────────────
    const googleTrackSuffix = [
        "google-analytics.com",                  // Google Analytics（谷歌统计分析）主域
        "analytics.google.com",                  // Google Analytics API
        "googletagmanager.com",                  // Google Tag Manager（标签管理器）
        // ⚠️ gvt1.com 是 Google 的 CDN（内容分发网络）主域，Chrome 扩展下载 / 字体 / 浏览器更新均走此域
        // 直接拦截 gvt1.com 会导致扩展商店异常、字体加载失败、Chrome 无法更新
        // 精确拦截已知遥测子域，放行其余 CDN 流量
        "redirector.gvt1.com",                   // Chrome 遥测重定向节点
        "optimizationguide-pa.googleapis.com",   // Chrome 优化提示遥测
    ];
    // ⚠️【副作用】SafeBrowsing（安全浏览）API 是 Chrome/Chromium 用于检测钓鱼网站、恶意软件分发页面的安全机制。
    //    拦截后 Chrome 将无法实时获取恶意网站列表，用户访问钓鱼/恶意页面时不再弹出红色安全警告。
    //    若安全性优先于隐私，可考虑将此关键词从拦截列表中移除。
    const googleTrackKeyword = ["safebrowsing.google"]; // SafeBrowsing API（安全浏览接口）隐私追踪（⚠️ 副作用：影响 Chrome 钓鱼/恶意网站检测，见上方说明）

    // ──────────────────── YouTube 遥测（不影响正常播放）────────────────────
    // ⚠️ s.youtube.com 同时承载观看历史，如需保留历史记录请注释此行
    // 使用 REJECT（立即 RST）而非 REJECT-DROP：播放器立即放弃重试，避免请求超时导致卡顿
    const youtubeSuffix  = ["youtube-ui.l.google.com"];     // YouTube UI 遥测域
    const youtubeDomain  = ["s.youtube.com"];               // 观看历史/遥测（⚠️ 同时承载观看历史）
    // ⚠️ youtubei.googleapis.com 不仅是遥测：/youtubei/v1/player 是播放器视频元数据 API，
    //    拦截后可能导致以下异常：视频缩略图加载失败、播放器参数解析错误、码率切换失效、
    //    字幕加载中断、下一集预加载停止——不仅限于遥测或隐私影响，会直接影响播放体验。
    //    评估副作用后再决定是否保留此关键词规则。
    const youtubeKeyword = ["youtubei.googleapis"];         // YouTube 内部 API（含遥测及播放器元数据）

    // ──────────────────── 通用广告联盟（REJECT 立即终止连接） ────────────────────
    const genericAdSuffix = [
        "doubleclick.net",                       // Google DoubleClick 广告网络
        "scorecardresearch.com",                 // comScore 受众测量
        "adnxs.com",                             // Xandr（AppNexus）程序化广告
        "criteo.com",                            // Criteo 个性化重定向广告（全球主流电商广告网络）
        "taboola.com",                           // Taboola 内容推荐广告（各大新闻站底部"猜你喜欢"）
        "outbrain.com",                          // Outbrain 内容推荐广告（同上，竞品）
        "amazon-adsystem.com",                   // 亚马逊广告系统
        "mc.yandex.ru",                          // Yandex Metrica（俄罗斯搜索引擎统计）用户行为统计（大量中文站接入）
        "mc.yandex.com",                         // Yandex Metrica 备用域
    ];

    // ─────── 关键词兜底（⚠️ 已注释：杀伤力过强，2025-2026 年严重泛化）───────
    // telemetry/analytics/stats/metrics 已出现在大量合法 CDN 和第三方服务域名中
    // 例：video-stats.video.google.com / metrics.cloudflare.com / cdn.telemetry-static.com
    // 如需启用，建议仅保留最精确的词并放到所有具体规则之后
    // const globalKeyword = ["telemetry", "analytics", "stats", "metrics"];

    // ───────────────────────────── 进程级规则 ─────────────────────────────
    // ⚠️ Windows 需要管理员权限 + TUN（虚拟网卡透明代理）/Service 模式，系统代理模式无效
    //    进程名必须与任务管理器「详细信息」完全一致，含大小写和 .exe。Windows 进程名对大小写不敏感，但 macOS/Linux 严格敏感。务必核对任务管理器中的精确名称。
    // ⚠️ macOS / Linux：以下规则全部失效——进程名不含 .exe 后缀且严格区分大小写；
    //    如需在 macOS / Linux 上使用进程规则，须通过 ps 命令核对实际进程名（如 AdobeGCClient），
    //    并自行在此处添加对应条目。
    // ⚠️ PROCESS-NAME 规则直接通过系统 Socket 获取进程信息，不依赖 SNI 嗅探，
    //    是 QUIC+ECH（SNI 被加密，DOMAIN 类规则失效）场景下最有效的域名规则兜底手段
    const processBlockRules = [ // 进程拦截
        // ── 正版验证类：保留 REJECT-DROP（让软件超时等待，不快速切换备用链路）────
        // 文档性规则（不产生额外拦截效果）：
        //   此条（443/UDP）是下方"所有 UDP（含非443端口）"规则的严格子集，
        //   first-match（首条命中）语义下不产生独立效果。
        //   保留仅为明确表达"QUIC 443端口优先阻断"的设计意图，不可作为功能性规则理解。
        "AND,((PROCESS-NAME,AdobeGCClient.exe),(DST-PORT,443),(NETWORK,UDP)),REJECT-DROP",
        "AND,((PROCESS-NAME,AdobeGCClient.exe),(NETWORK,UDP)),REJECT-DROP",               // 兜底阻断所有 UDP（含非443端口），双重保障
        "PROCESS-NAME,AdobeGCClient.exe,REJECT-DROP",        // Adobe 正版验证（最重要）
        "PROCESS-NAME,AdskLicensingService.exe,REJECT-DROP", // Autodesk 许可验证
        "PROCESS-NAME,AdskAccess.exe,REJECT-DROP",           // Autodesk 访问控制服务
        "PROCESS-NAME,AdskIdentityManager.exe,REJECT-DROP",  // Autodesk 身份认证管理器
        // 适用 CorelDRAW 2017+（进程名 CorelDRW.exe，非 CorelDRAW.exe；2017 以前版本进程结构不同，请通过任务管理器核对）
        // ⚠️ 部分请求经 msedgewebview2.exe 发出（系统共享进程，不可拦截），已由 corelSuffix 域名层覆盖。
        "PROCESS-NAME,CorelDRW.exe,REJECT",
        // ── 国产流氓软件：改用 REJECT（快速拒绝，用户感知更好，不卡死软件）────────
        "PROCESS-NAME,360sd.exe,REJECT",                     // 360 杀毒主进程
        "PROCESS-NAME,360tray.exe,REJECT",                   // 360 系统托盘弹窗进程
        "PROCESS-NAME,2345Mini.exe,REJECT",                  // 2345 迷你窗口/弹窗进程
        "PROCESS-NAME,2345Helper.exe,REJECT",                // 2345 后台辅助进程
        "PROCESS-NAME,DTLocker.exe,REJECT",                  // 驱动人生锁屏弹窗
        "PROCESS-NAME,LDSGameBox.exe,REJECT",                // 鲁大师游戏盒
        "PROCESS-NAME,SogouNews.exe,REJECT",                 // 搜狗新闻弹窗
        "PROCESS-NAME,DriverGenius.exe,REJECT",              // 驱动精灵
        "PROCESS-NAME,Ludashi.exe,REJECT",                   // 鲁大师主程序
        // "PROCESS-NAME,Wps.exe,REJECT",                    // ⚠️ 慎用：WPS 主进程，拦截后全部联网功能失效（包括文档云同步）
    ];
    const processProxyRules = [ // 进程代理
        // `PROCESS-NAME,Telegram.exe,${proxyGroupName}`,      // 进程代理示例，按需取消注释
    ];
    const processDirectRules = [ // 进程直连
        "PROCESS-NAME,BaiduNetdisk.exe,DIRECT",              // 强制直连，提升下载速度
        "PROCESS-NAME,filezilla.exe,DIRECT",                 // FTP 数据通道使用随机端口，代理环境下路由难以全量覆盖，强制直连保证传输稳定性
    ];

    // ────────────────────────────── 代理规则 ──────────────────────────────
    // ⚠️ Google 风控：Gemini 检测出口 IP 漂移，google.com 与 gemini.google.com 必须命中同一策略组，否则可能触发 403 或账号异常
    const proxySuffixList = [
        "copilot.microsoft.com",                 // Microsoft Copilot AI 助手（注意：directRules 中 microsoft.com 的 SUFFIX 会匹配此域，优先级由 LAYERS 顺序保证 proxy > direct）
        "linkedin.com",                          // 领英职场社交网络
        // "openai.com",           // 按需取消注释
        // "gemini.google.com",    // 按需取消注释（注意 google.com 需同组）
        // ────────── Steam 分流：商店走代理，下载走直连 ───────────────
        // store / community / static 是国内受阻的前端域，走代理提升访问体验
        // steampowered.com 根域含 content1~9 下载 CDN（内容分发网络）子域，保留直连保证下载速度
        "store.steampowered.com",                // Steam 商店页面
        "steamcommunity.com",                    // Steam 社区 / 创意工坊 / 市场
        "steamstatic.com",                       // Steam 商店静态资源（封面/截图）
    ];

    // ────────────────────────────── 直连规则 ──────────────────────────────
    const directRules = [
        // Microsoft 全家桶直连（防止更新/登录/OneDrive 卡死）
        // DOMAIN-SUFFIX,microsoft.com 已覆盖所有 *.microsoft.com 子域，
        // 无需额外的 DOMAIN-KEYWORD,microsoft（冗余且存在误判风险）
        "DOMAIN-KEYWORD,windowsupdate,DIRECT",             // Windows Update 关键词兜底（覆盖非标子域）
        "DOMAIN-SUFFIX,microsoft.com,DIRECT",              // 微软主域（含所有 *.microsoft.com 子域）
        "DOMAIN-SUFFIX,live.com,DIRECT",                   // 微软账户 / Hotmail
        "DOMAIN-SUFFIX,outlook.com,DIRECT",                // Outlook 邮件服务
        "DOMAIN-SUFFIX,onedrive.com,DIRECT",               // OneDrive 云存储
        "DOMAIN-SUFFIX,skype.com,DIRECT",                  // Skype 通信服务
        "DOMAIN-SUFFIX,microsoftonline.com,DIRECT",        // Microsoft 365 身份认证
        "DOMAIN-SUFFIX,microsoftonline-p.com,DIRECT",      // Microsoft 365 认证备用域
        "DOMAIN-SUFFIX,msftauth.com,DIRECT",               // 微软统一身份验证
        "DOMAIN-SUFFIX,msftidentity.com,DIRECT",           // 微软身份服务
        "DOMAIN-SUFFIX,passport.net,DIRECT",               // 微软 Passport 认证（旧版）
        "DOMAIN-SUFFIX,windowsupdate.com,DIRECT",          // Windows Update 更新服务主域
        "DOMAIN-SUFFIX,microsoftpersonalcontent.com,DIRECT", // 微软个人内容 CDN
        "DOMAIN-SUFFIX,msocsp.com,DIRECT",                 // 微软证书吊销列表（OCSP = Online Certificate Status Protocol，在线证书状态协议）
        "DOMAIN-SUFFIX,msedge.net,DIRECT",                 // Microsoft Edge CDN（内容分发网络）/ 更新
        // NCSI（Network Connectivity Status Indicator，网络连通性状态指示器，Windows 右下角网络图标依赖此服务）
        // DOMAIN-SUFFIX 同时覆盖 ipv6.msftconnecttest.com 等所有子域变体
        "DOMAIN-SUFFIX,msftconnecttest.com,DIRECT",        // NCSI（网络连通性状态指示器）连通性探测（拦截后 Windows 右下角显示「无网络」）
        "DOMAIN-SUFFIX,msftncsi.com,DIRECT",               // NCSI 旧版探测域
        // Adobe 常用业务放行（字体/图库/作品展示）
        "DOMAIN-SUFFIX,fonts.adobe.com,DIRECT",            // Adobe Fonts 字体同步服务
        "DOMAIN-SUFFIX,stock.adobe.com,DIRECT",            // Adobe Stock 图库
        "DOMAIN-SUFFIX,behance.net,DIRECT",                // Behance 设计作品展示平台
        "DOMAIN-SUFFIX,behance.adobe.com,DIRECT",          // Behance Adobe 子域
        "DOMAIN-SUFFIX,color.adobe.com,DIRECT",            // Adobe Color 配色工具
        "DOMAIN,assets.adobe.com,DIRECT",                  // Adobe 静态资源 CDN（内容分发网络）
        // ⚠️ 非默认条件下的备用规则（默认配置下被上层规则遮蔽，处于休眠状态，禁止删除）
        //
        // 【原设计意图】
        //   欺骗式绕过：只给补丁一条生路完成自检，核心统计域已被封锁，即便联通也无法回传有效数据。
        //
        // 【默认配置下不可达的原因】
        //   ① ENABLE_BLOCK=true（默认）：backdoorSuffix 中的
        //      DOMAIN-SUFFIX,966v26.com,REJECT-DROP 先命中，此处 DIRECT 被遮蔽
        //   ② ENABLE_HOSTS_TRICK=true（默认）：hijackDomains 已在 DNS 层注入
        //      黑洞（0.0.0.0），TCP 连接根本不会发出
        //
        // 【何时实际生效（激活条件）】
        //   非默认组合：ENABLE_BLOCK=false && ENABLE_HOSTS_TRICK=false && ENABLE_DIRECT=true
        //   三个条件同时满足时，此 DIRECT 规则成为唯一覆盖，设计意图在该场景下实际执行。
        "DOMAIN,api.966v26.com,DIRECT",                    // 休眠规则：默认配置下被遮蔽，非默认组合下激活（见上方说明）
        "DOMAIN,status.966v26.com,DIRECT",                 // 休眠规则：默认配置下被遮蔽，非默认组合下激活（见上方说明）
        // 官网放行
        "DOMAIN-SUFFIX,autodesk.com,DIRECT",               // Autodesk 官网放行（下载/账户/论坛）
        "DOMAIN-SUFFIX,corel.com,DIRECT",                  // ⚠️ 不要拦截整个 corel.com
        // 常用工具直连
        // NTP（Network Time Protocol，网络时间协议）时间同步强制直连（仅 TUN 模式有效）
        // ⚠️ DST-PORT,123 同时匹配 TCP/UDP；NTP 仅使用 UDP 123，如需精确匹配可改为：
        //    AND,((DST-PORT,123),(NETWORK,UDP)),DIRECT
        //    但当前写法更兼容旧版 Mihomo（AND 规则支持程度因版本而异），保守使用 DST-PORT
        "DST-PORT,123,DIRECT",
        "DOMAIN-SUFFIX,steampowered.com,DIRECT",  // Steam 根域直连（含 content1~9 下载 CDN 子域，保证满速）
        "DOMAIN-SUFFIX,steamcontent.com,DIRECT",  // Steam 游戏内容分发 CDN（满速下载）
        "DOMAIN-SUFFIX,steamserver.net,DIRECT",   // Steam 联机对战后端
        // "DOMAIN-SUFFIX,tmall.hk,DIRECT",          // 淘宝相关，.hk 域名被兜底走代理影响商品价格加载
        "DOMAIN-SUFFIX,pixpinapp.com,DIRECT",     // 截图贴图工具
        "DOMAIN-SUFFIX,pixpin.cn,DIRECT",         // 截图贴图工具
        "DOMAIN-SUFFIX,lanzou.com,DIRECT",        // 蓝奏云主域
        "DOMAIN-SUFFIX,lanzoui.com,DIRECT",       // 蓝奏云备用域 1
        "DOMAIN-SUFFIX,lanzoux.com,DIRECT",       // 蓝奏云备用域 2
        "DOMAIN-SUFFIX,masuit.com,DIRECT",        // 学习版软件站 懒得勤快
        "DOMAIN-SUFFIX,masuit.net,DIRECT",        // 学习版软件站 懒得勤快
        "DOMAIN-SUFFIX,masuit.org,DIRECT",        // 学习版软件站 懒得勤快
        "DOMAIN-SUFFIX,423down.com,DIRECT",       // 知名绿色软件站
        "DOMAIN-SUFFIX,ghxi.com,DIRECT",          // 果核剥壳（绿色软件站）
        "DOMAIN-SUFFIX,mpyit.com,DIRECT",         // 殁漂遥软件分享站
        "DOMAIN-SUFFIX,25xianbao.com,DIRECT",     // 卡圈线报
        "DOMAIN-SUFFIX,dir28.com,DIRECT",         // 羊毛活动
        "DOMAIN-SUFFIX,aserweb.com,DIRECT",       // 行业 ERP 软件
        "DOMAIN-SUFFIX,zlkj.com,DIRECT",          // 行业 SCRM 软件
        "DOMAIN-SUFFIX,threadify.com,DIRECT",     // 独立站，直连以确保访问
    ];

    // ────────────── 激进阻断规则（默认关闭，开启前请仔细阅读注释）──────────────
    const aggressiveRules = [
        // REGEX 与 SUFFIX 互补关系（禁止以"冗余"为由删除任一条）：
        //   REGEX: ^.+ 要求至少一字符前缀，不匹配 adobe.io 裸域本身
        //   SUFFIX: 补充覆盖 adobe.io 裸域。删除 SUFFIX 则裸域漏网。两者相互补充，缺一不可。
        "DOMAIN-REGEX,^.+\\.adobe\\.io$,REJECT-DROP",         // ⚠️ 激进：所有 adobe.io 子域（影响字体/素材/插件市场等官方服务）
        "DOMAIN-SUFFIX,adobe.io,REJECT-DROP",                // ⚠️ 激进：补充覆盖裸域（REGEX 不匹配裸域，见上方说明）
        // 多平台共用域（Zapier/Notion/GitHub Actions 也在用，慎用）
        "DOMAIN-SUFFIX,workflowusercontent.com,REJECT-DROP", // ⚠️ 激进：多平台共用（Zapier/Notion/GitHub Actions）
        // adsk.com 旧版遥测（影响官网/插件商店，慎用）
        "DOMAIN-SUFFIX,adsk.com,REJECT-DROP",                // ⚠️ 激进：Autodesk 旧版遥测（影响官网/插件商店访问）
        // 影响 Office 更新/模板下载
        "DOMAIN-KEYWORD,officecdn,REJECT-DROP",              // ⚠️ 激进：Office CDN（内容分发网络）关键词（影响 Office 更新/模板下载）
        // 区域识别，影响 CC 登录
        "DOMAIN,geo.adobe.com,REJECT-DROP",                  // ⚠️ 激进：地理区域识别（影响 CC 登录）
        "DOMAIN,geo2.adobe.com,REJECT-DROP",                 // ⚠️ 激进：地理区域识别备用
        // 拦截后无法登录 Autodesk 账户
        "DOMAIN-SUFFIX,accounts.autodesk.com,REJECT-DROP",   // ⚠️ 激进：拦截后无法登录 Autodesk 账户
        // ⚠️ 激进：Autodesk 授权端点。
        //    ENABLE_BLOCK=true 时，autodeskKeyword 中的 KEYWORD 规则（"entitlement.autodesk"）
        //    因注入顺序更早而先命中，本 SUFFIX 规则被遮蔽（实质冗余但无害）。
        //    ENABLE_BLOCK=false 时本条独立生效，为纵深防御保留，禁止删除。
        //    注意：api.entitlements.autodesk.com 不被上述 KEYWORD 覆盖，
        //    已在 autodeskSuffix 独立列出，与本条无重叠（见 autodeskKeyword 注释块）。
        "DOMAIN-SUFFIX,entitlement.autodesk.com,REJECT-DROP",
        // IE 遗留检测（拦截后影响 ActiveX 控件 / 旧版 OA 系统，不影响 NCSI）
        "DOMAIN,ieonline.microsoft.com,REJECT-DROP",         // ⚠️ 激进：IE 内核在线检测（影响 ActiveX 控件 / 旧版 OA 系统，不影响 NCSI 网络连通性状态指示器）
    ];

    // ════════════════ 3. 规则组装与注入 ════════════════

    try {
        // ── 分层规则容器（优先级由 LAYER_ORDER 数组唯一决定）──────────
        // 层级固定顺序：allow（放行）> block（拦截）> process（进程）
        //              > proxy（代理）> aggressive（激进）> direct（直连）
        // LAYERS 对象仅用作具名容器，方便分类追加规则；
        // 优先级由下方 LAYER_ORDER 数组显式保证，与 LAYERS 对象键迭代顺序无关。
        // ⚠️ 禁止随意调整 LAYER_ORDER——
        //    危险示例1：将 "aggressive" 移至 "allow" 之前，
        //      adobe.io 通配 REJECT-DROP 将先于 allow 层的 Firefly 精确放行规则命中，
        //      导致 Firefly 推理请求被错误拦截。
        //    危险示例2：将 "direct" 移至 "aggressive" 之前，
        //      父域 autodesk.com,DIRECT 将遮蔽子域 accounts.autodesk.com,REJECT-DROP，
        //      激进拦截规则永久无效。
        const LAYERS = { allow: [], block: [], process: [], proxy: [], aggressive: [], direct: [] };
        const pushLayer = (layer, rules) => LAYERS[layer].push(...rules);

        if (ENABLE_BLOCK) {
            // ── Firefly 放行（adobeAuthChain 单一来源，effectiveFirefly 决定路由动作）──
            if (effectiveFirefly) {
                // 鉴权链走代理（first-match 保证在 adobeSuffix REJECT 之前命中）
                pushSuffix(adobeAuthChain, proxyGroupName, LAYERS.allow);
                // Firefly/Clio/Sensei 专属域名走代理
                pushSuffix(adobeFireflyOnly, proxyGroupName, LAYERS.allow);
            } else {
                // 此 else 分支仅在 ENABLE_BLOCK=true 且 effectiveFirefly=false 时执行
                // 即：ENABLE_BLOCK=true 且 ENABLE_FIREFLY=false
                // ENABLE_BLOCK=false 时整个外层 if 不进入，adobeAuthChain 不会注入任何层，
                // 既不放行也不拦截——与此处"走 REJECT"的描述无关。
                pushSuffix(adobeAuthChain, "REJECT", LAYERS.block);
            }
            // Adobe（遥测/授权域改用 REJECT，软件立即进入离线模式，避免启动卡顿）
            pushSuffix(adobeSuffix, "REJECT", LAYERS.block);
            LAYERS.block.push(...adobeRegex);
            // ❗ adobeUdpBlock 仅 TUN 模式有效，系统代理模式下这些规则不会命中任何 UDP 流量（见 adobeUdpBlock 声明处注释）
            LAYERS.block.push(...adobeUdpBlock);
            // WSS（WebSocket Secure）精确匹配（DOMAIN，原因见 adobeWsDomain 注释）
            pushDomain(adobeWsDomain, "REJECT", LAYERS.block);
            // Corel
            pushSuffix(corelSuffix, "REJECT", LAYERS.block);
            // Autodesk
            pushSuffix(autodeskSuffix, "REJECT", LAYERS.block);
            pushDomain(autodeskDomain, "REJECT", LAYERS.block);
            pushKeyword(autodeskKeyword, "REJECT", LAYERS.block);
            // 非官方补丁后门（保留 REJECT-DROP：消耗连接池、阻碍快速切换备用域名，拖慢重试节奏）
            pushSuffix(backdoorSuffix, "REJECT-DROP", LAYERS.block);
            pushKeyword(backdoorKeyword, "REJECT-DROP", LAYERS.block);
            // IDM / Wondershare / 杂项
            pushSuffix(idmSuffix, "REJECT", LAYERS.block);
            pushKeyword(idmKeyword, "REJECT", LAYERS.block);
            pushSuffix(wondershareSuffix, "REJECT", LAYERS.block);
            // miscSoftwareSuffix 当前为空（扩展占位），length 守卫防止未来维护者误删注释后展开空数组
            if (miscSoftwareSuffix.length > 0) pushSuffix(miscSoftwareSuffix, "REJECT", LAYERS.block);
            pushDomain(miscSoftwareDomain, "REJECT", LAYERS.block);
            // 微软遥测（REJECT 立即终止连接）
            pushSuffix(msTelemSuffix, "REJECT", LAYERS.block);
            // 国产广告 / 遥测（REJECT 快速拒绝，广告类无需静默超时）
            pushSuffix(cnAdSuffix, "REJECT", LAYERS.block);
            pushDomain(cnAdDomain, "REJECT", LAYERS.block);
            // 浏览器遥测（REJECT 立即终止连接）
            pushSuffix(mozillaSuffix, "REJECT", LAYERS.block);
            pushSuffix(googleTrackSuffix, "REJECT", LAYERS.block);
            pushKeyword(googleTrackKeyword, "REJECT", LAYERS.block);
            // YouTube 遥测（REJECT 立即返回，避免播放器因超时卡顿）
            pushSuffix(youtubeSuffix, "REJECT", LAYERS.block);
            pushDomain(youtubeDomain, "REJECT", LAYERS.block);
            pushKeyword(youtubeKeyword, "REJECT", LAYERS.block);
            // 通用广告联盟
            pushSuffix(genericAdSuffix, "REJECT", LAYERS.block);
            // 关键词兜底（已注释，globalKeyword 变量已注释禁用，见数据层说明）
            // pushKeyword(globalKeyword, "REJECT", LAYERS.block);
        }

        if (ENABLE_PROCESS_RULE) {
            // processBlockRules / processProxyRules / processDirectRules 均为同作用域 const 字面量数组，
            // Array.isArray 永远为 true，此处仅保留 length 守卫防止 pushLayer 展开空数组造成无意义操作。
            if (processBlockRules.length  > 0) pushLayer("process", processBlockRules);
            if (processProxyRules.length  > 0) pushLayer("process", processProxyRules);
            if (processDirectRules.length > 0) pushLayer("process", processDirectRules);
        }

        if (ENABLE_PROXY) {
            // action 参数此处传入策略组名（非 DIRECT/REJECT），Mihomo 语法合法
            pushSuffix(proxySuffixList, proxyGroupName, LAYERS.proxy);
        }

        // ⚠️ aggressiveRules 必须在 directRules 之前注入（父域遮蔽问题）：
        //   aggressiveRules 含 DOMAIN-SUFFIX,accounts.autodesk.com /
        //   entitlement.autodesk.com / DOMAIN,ieonline.microsoft.com 等子域规则；
        //   若排在 directRules（含 autodesk.com,DIRECT / microsoft.com,DIRECT）之后，
        //   父域 DIRECT 规则先命中，子域 REJECT-DROP 永远不会执行。
        //
        // ── BLOCK 与 AGGRESSIVE 重叠域名（此处行为说明）──────────────
        //   entitlement.autodesk.com（SUFFIX）在 aggressiveRules 中；
        //   entitlement.autodesk（KEYWORD）在 ENABLE_BLOCK=true 时由 autodeskKeyword 注入。
        //   两者注入顺序：autodeskKeyword（BLOCK 层）先入 pool，aggressiveRules 后入。
        //   first-match（首条命中）语义下 KEYWORD 规则先命中，SUFFIX 被遮蔽。无额外影响，设计正确。
        //   详见 autodeskKeyword 上方「BLOCK vs AGGRESSIVE 重叠说明」注释。
        if (ENABLE_AGGRESSIVE) {
            pushLayer("aggressive", aggressiveRules);
        }

        if (ENABLE_DIRECT) {
            pushLayer("direct", directRules);
        }

        // 规则按层级顺序展开。
        // 优先级由 LAYER_ORDER 数组显式保证，与 LAYERS 对象键序无关。
        // Object.freeze：const 仅防止重新赋值，不防止 push/splice 等原地变异；
        //   freeze 确保 LAYER_ORDER 内容在整个注入过程中绝对不变，防止未来扩展时意外的优先级静默失效。
        // ⚠️ LAYER_ORDER 顺序 = first-match 策略优先级，禁止随意调整——
        //    危险示例：将 "aggressive" 移至 "allow" 之前，adobe.io 通配 REJECT-DROP 先于
        //    Firefly 精确放行命中；或将 "direct" 移至 "aggressive" 之前，父域 DIRECT 遮蔽子域拦截。
        //    插入/删除层级时只需修改 LAYER_ORDER，finalPool 构建逻辑无需改动。
        const LAYER_ORDER = Object.freeze(["allow", "block", "process", "proxy", "aggressive", "direct"]);
        const finalPool = [_sentinelStart];
        for (const key of LAYER_ORDER) finalPool.push(...LAYERS[key]);
        finalPool.push(_sentinelEnd);

        // 插入到规则列表最前面（最高优先级）
        config.rules = finalPool.concat(config.rules);

        console.log("=".repeat(60));
        console.log("✅ 规则注入成功");
        // ⚠️ ENABLE_SCRIPT=false 时函数已在上方提前 return，此行永不执行；末尾文字为自证注释
        console.log(`   脚本状态:   ${ENABLE_SCRIPT        ? "✅ 已启用" : "⏭️ 已跳过（此行不会出现）"}`);
        console.log(`   拦截模块:   ${ENABLE_BLOCK         ? "✅" : "❌"}`);

        // Firefly 放行状态需结合 effectiveFirefly 综合判断后显示
        if (ENABLE_FIREFLY) {
            if (effectiveFirefly) {
                console.log(`   Firefly放行: ✅（effectiveFirefly=true，鉴权链已从单一来源注入）⚠️ 鉴权端点已放行`);
            } else {
                console.log(`   Firefly放行: ❌ ENABLE_BLOCK=false，effectiveFirefly 已自动降级（不生效）`);
            }
        } else {
            console.log(`   Firefly放行: ❌`);
        }

        console.log(`   进程规则:   ${ENABLE_PROCESS_RULE  ? "✅（依赖管理员+TUN，不可靠）" : "❌"}`);
        console.log(`   代理规则:   ${ENABLE_PROXY         ? "✅" : "❌"}`);
        // ENABLE_AGGRESSIVE 激进模式日志增加警告行，列出已知受影响域
        if (ENABLE_AGGRESSIVE) {
            console.warn(`   激进模式:   ⚠️ 已开启`);
            console.warn(`   ⚠️ 激进模式已开启，可能导致以下服务不可用：`);
            console.warn(`      adobe.io（插件市场/字体）、adsk.com（Autodesk 官网）、`);
            console.warn(`      officecdn（Office 更新/模板）、ieonline.microsoft.com（ActiveX/旧版 OA）`);
        } else {
            console.log(`   激进模式:   ❌`);
        }
        console.log(`   直连规则:   ${ENABLE_DIRECT        ? "✅" : "❌"}`);
        console.log(`   Hosts拦截:  ${ENABLE_HOSTS_TRICK   ? "✅ [" + HOSTS_MODE + "]" : "❌"}`);
        console.log(`   注入规则数: ${finalPool.length} 条（含首尾哨兵）`);
        console.log(`   总规则数:   ${config.rules.length} 条`);
        console.log(`   代理组:     [${proxyGroupName}]`);
        console.log(`   耗时:       ${Date.now() - _startTime} ms`);
        console.log("=".repeat(60));

    } catch (err) {
        // 降级：注入异常时中止并返回当前配置；
        // 若错误发生在 config.rules 赋值之后，返回的配置可能已含部分注入规则（见错误消息）。
        // 注意：下次脚本执行时，哨兵栈重建算法会将这些遗留的注入规则视为普通规则保留，
        //       直至完整的 START...END 对被正常写入后方能清除。概率极低，不影响网络通畅。
        console.error("❌ 规则注入异常，已中止并返回当前配置（若错误发生在 config.rules 赋值之后，可能含部分已注入规则）:", err);
        console.log(`   失败耗时:   ${Date.now() - _startTime} ms`);
        return config;
    }

    // ═══════════════ 4. Hosts 级 DNS 拦截 ═══════════════
    //  （黑洞 / 欺骗四种子模式，由 HOSTS_MODE 选择）
    //
    // 【DNS 内部处理流（来源：wiki.metacubex.one/en/config/dns/diagram）】
    //
    //   DNS 解析阶段（按优先级）：
    //     1. Hosts 匹配  → 命中则立即返回映射地址，不再向下执行
    //     2. fake-ip-filter（虚假 IP 过滤表）判断 → 域名在列表中则走真实 DNS 查询
    //     3. Fake-IP（虚假 IP，Mihomo 分配的 198.18.x.x 虚拟地址）生成 → 不在列表则分配虚拟 IP
    //     → 结论：hosts 优先级高于 fake-ip-filter
    //
    //   三条拦截路径：
    //
    //   路径 A（系统代理模式）
    //     app → Mihomo DNS → hosts → 返回拦截地址（黑洞/欺骗，取决于 HOSTS_MODE）→ app 连接立即失败
    //
    //   路径 B（TUN（虚拟网卡透明代理）模式，需满足前提：dns-hijack: any:53）
    //     app → TUN → DNS 接管 → hosts → 返回拦截地址（黑洞/欺骗，取决于 HOSTS_MODE）→ app 连接立即失败
    //     ⚠️ 若 TUN 未配置 dns-hijack，app 可绕过 Mihomo DNS 直接查询
    //        外部 DNS，hosts 将不生效
    //
    //   路径 C（硬编码 IP，完全绕过 DNS）
    //     app → 直接发起 IP 连接 → 路由规则匹配
    //     → DOMAIN-SUFFIX / DOMAIN 规则不触发（无域名可匹配）
    //     → PROCESS-NAME / IP-CIDR / NETWORK 规则触发 → REJECT-DROP
    //     ⚠️ 路径 C 下 DOMAIN-SUFFIX 类规则（含 backdoorSuffix）同样无效；
    //        唯一有效防线为 PROCESS-NAME（进程规则）和 IP-CIDR 规则
    //
    // ⚠️【Hosts 与 Rules 分层说明】
    //    hosts 命中后，DNS 已在解析阶段返回拦截地址，TCP 连接不会发出，
    //    rules 层（DOMAIN-SUFFIX REJECT-DROP 等）不会执行。
    //    rules 层是 hosts 未生效时（用户未开启「使用 Hosts」或走硬编码 IP 路径）的兜底。
    //    两者不冲突，是分层防御的设计意图。
    //
    //   各 HOSTS_MODE 的连接失败类型：
    //     0.0.0.0 / :: → ENETUNREACH（Linux/Android）/ WSAEADDRNOTAVAIL（Windows）
    //                    OS 直接拒绝路由，TCP SYN（握手第一包）不会发出
    //     127.0.0.1 / ::1 → ECONNREFUSED（本地无监听端口时，本地 OS TCP 栈返回 RST 重置包）
    //                       欺骗拦截，软件以为"到达了服务器"
    //
    // 模式说明（与顶部 HOSTS_MODE 对应）：
    //   ipv4-loopback  → 127.0.0.1          欺骗拦截（ECONNREFUSED），更温和
    //   ipv4-blackhole → 0.0.0.0            黑洞拦截（ENETUNREACH），应用程序立即收到网络不可达错误
    //   dual-stack     → 127.0.0.1 + ::1    IPv4/IPv6 双栈欺骗拦截
    //   blackhole      → 0.0.0.0 + ::       IPv4/IPv6 双栈黑洞拦截（慎用，最彻底但可能影响某些应用）
    //
    // 【hosts 值格式（来源：wiki.metacubex.one/en/config/dns/hosts）】
    //   单 IP：字符串 "0.0.0.0"
    //   多 IP：数组   ["0.0.0.0", "::"]
    //   域名重定向：字符串（不支持数组）
    //   → 单元素数组 ["0.0.0.0"] 与字符串 "0.0.0.0" 语义相同，
    //     但部分版本 Mihomo 对单元素数组解析行为未明确，
    //     本脚本统一使用字符串（单 IP）或数组（多 IP）

    if (ENABLE_HOSTS_TRICK) {
        // ⚠️ 此警告旨在提醒用户检查 CVR UI 设置。若已正确开启「启用 DNS」和「使用 Hosts」，可安全忽略此消息。
        console.warn(
            "⚠️ Hosts DNS 拦截模块已启用，但可能因 CVR 设置而失效：\n" +
            "❗ 前提1：CVR → DNS 覆写 → 必须开启「启用 DNS」（关闭则 dns 块整体失效）\n" +
            "❗ 前提2：CVR → DNS 覆写 → 必须开启「使用 Hosts」\n" +
            "❗ 注意：脚本注入的 use-hosts:true 会被 CVR UI 层覆盖，必须手动开启，脚本无法替代手动操作\n" +
            "💡 两个开关缺一不可，脚本无法检测 UI 层开关状态；未开启时本模块静默失效\n" +
            "   （静默失效意味着脚本仍会打印成功日志，但 hosts 拦截实际不生效）"
        );
        try {

            // modeMap 值格式：
            //   单 IP 模式 → 字符串（避免单元素数组的解析歧义）
            //   双栈模式   → 数组（Mihomo hosts 明确支持多 IP 数组）
            const modeMap = {
                "ipv4-loopback":  "127.0.0.1",
                "ipv4-blackhole": "0.0.0.0",
                "dual-stack":     ["127.0.0.1", "::1"],
                "blackhole":      ["0.0.0.0", "::"],
            };
            const target = modeMap[HOSTS_MODE];
            if (!target) throw new Error(`未知 HOSTS_MODE: ${HOSTS_MODE}`);

            // 拦截域名列表（仅针对高危非官方补丁回传域名）
            // Mihomo hosts 通配符说明（来源：wiki.metacubex.one/en/config/dns/hosts）：
            //   +.domain → 匹配主域本身 + 所有多级子域，等效 DOMAIN-SUFFIX
            //   *.domain → 仅匹配单级子域，不含主域和多级子域
            //   .domain  → 匹配所有多级子域，不含主域本身
            //
            // 冗余项保留说明：
            //   新版 Mihomo 内核中，+.966v26.com 已完全包含 966v26.com 和 *.966v26.com。
            //   保留精确项（966v26.com / *.966v26.com / api.966v26.com / status.966v26.com）是为旧版内核兜底：
            //   旧版不识别 +. 语法时：
            //     *.966v26.com 通配单级子域（覆盖绝大多数访问路径）
            //     api.966v26.com / status.966v26.com 精确条目双重保障核心接口
            //     966v26.com 保障主域本身
            //   代价：内核 hosts 树略有冗余，无功能影响。
            const hijackDomains = [
                "+.966v26.com",           // 新版内核：匹配主域 + 所有多级子域
                "966v26.com",             // 旧版内核兜底：主域精确匹配
                "*.966v26.com",           // 旧版内核兜底：单级通配符
                "api.966v26.com",         // 显式精确（双重保障核心接口）
                "status.966v26.com",      // 显式精确（双重保障状态接口）
            ];

            const customHosts = {};
            hijackDomains.forEach(d => { customHosts[d] = target; });

            // 顶层 hosts + DNS 模块双重注入（兼容性策略，而非功能需要）
            // ⚠️ 不同内核/版本对 hosts 段和 dns.hosts 段的支持情况可能不同，双写确保覆盖
            // ⚠️ config.dns 可能不存在（订阅无 dns 块时为 undefined），
            //    必须先确保 dns 对象存在再操作子字段

            // hosts 合并前增加类型硬校验：若上游订阅将 hosts 写成数组、字符串等非对象结构，
            //   原版 { ...(config.hosts || {}) } 会将数组/字符串展开为以索引为 key 的非法对象（如 {"0":"..."}）。
            //   修复：typeof 检查 + !Array.isArray 双重验证，类型异常时初始化为空对象。
            const _safeTopHosts = (typeof config.hosts === "object" && config.hosts !== null && !Array.isArray(config.hosts))
                ? config.hosts : {};
            config.hosts = { ..._safeTopHosts, ...customHosts };

            if (typeof config.dns === "undefined" || config.dns === null) {
                config.dns = {};
            }
            // ⚠️ 重要限制：此处写入 use-hosts: true 会被 Clash Verge Rev UI 设置覆盖。
            //
            //    Clash Verge Rev 的配置生效顺序：
            //      订阅 yaml → 脚本注入 → UI 设置覆盖 → 写入 clash-verge.yaml → Mihomo 加载
            //
            //    脚本在"脚本注入"阶段写入 use-hosts: true，但随后"UI 设置覆盖"
            //    阶段会将"使用 Hosts"开关的值（默认 false）写入合并配置，
            //    将脚本注入的值覆盖。脚本无法绕过此 UI 层覆盖。
            //
            //    → 必须在 Clash Verge Rev 设置 → DNS 覆写 → 手动开启"使用 Hosts"，
            //      Hosts DNS 拦截才能真正生效。
            //
            //    注意：同页面还有"使用系统 Hosts"开关，无需开启。
            //      "使用系统 Hosts" 对应 Windows 自带的
            //      C:\Windows\System32\drivers\etc\hosts 文件，
            //      与脚本注入的 Mihomo hosts 是两套完全独立的机制。
            config.dns["use-hosts"] = true;

            // dns.hosts 同样增加类型硬校验
            const _safeDnsHosts = (typeof config.dns.hosts === "object" && config.dns.hosts !== null && !Array.isArray(config.dns.hosts))
                ? config.dns.hosts : {};
            config.dns.hosts = { ..._safeDnsHosts, ...customHosts };

            // 双重保险：hosts 优先级高于 fake-ip-filter（DNS 解析顺序：hosts → fake-ip-filter → Fake-IP）。
            // hosts 命中时请求直接返回拦截地址，根本不会走到 fake-ip 分配阶段，此处 fake-ip-filter
            // 追加为次级防线——当 hosts 因「使用 Hosts」未开启而失效时，阻止内核为拦截域名
            // 分配 198.18.x.x 虚拟 IP，避免补丁误以为"已获得可用地址"而继续发起连接。
            //
            // [优化] 仅追加新条目，不对全量 fake-ip-filter 排序，保留订阅原有顺序。
            //        全量重排会触发 Mihomo DNS hash 重建，可能导致连接瞬断，故仅追加。
            //        新增条目本身做 .sort()：hijackDomains 为固定 5 项，排序确保每次 reload
            //        追加顺序一致，与"不打乱订阅原有顺序"不矛盾（仅对新条目排序，不影响已有条目）。
            // ⚠️ 注意：CVR UI 若开启了某些预设模板或覆盖 DNS 配置，可能清空或重置
            //    fake-ip-filter 列表，导致此处追加的条目丢失。建议在 CVR 日志中
            //    确认最终生效的 fake-ip-filter 条目包含本脚本注入的域名。
            if (!Array.isArray(config.dns["fake-ip-filter"])) {
                config.dns["fake-ip-filter"] = [];
            }
            // fake-ip-filter 写回时同步清洗原数组非字符串元素：
            //   原版 existingSet 的 filter(typeof === "string") 仅作用于去重 Set 的输入，
            //   写回时仍原样展开含 null/对象/数字等脏数据的原数组，注释说"类型安全过滤"但实际未清洗输出。
            //   修复：提取 cleanExisting 变量，对原数组过滤一次后同时用于去重和写回，消除重复遍历。
            const cleanExisting = config.dns["fake-ip-filter"].filter(i => typeof i === "string");
            const existingSet   = new Set(cleanExisting);
            // hijackDomains 为字面量常量，5 个条目已保证唯一，直接 filter 无需额外去重
            const newEntries    = hijackDomains.filter(d => !existingSet.has(d)).sort();
            config.dns["fake-ip-filter"] = [...cleanExisting, ...newEntries];

            const targetStr = Array.isArray(target) ? target.join(" / ") : target;
            console.log(`🛡️ Hosts DNS 拦截注入成功 [${HOSTS_MODE}] → ${targetStr}`);
            console.log(`   拦截域名数: ${hijackDomains.length} 条（含旧版内核兜底条目）`);
            // 补充打印实际追加条目数，方便排查 CVR UI 清空后是否重新注入了正确数量
            // 若 existingSet.size=0 且 newEntries.length 等于 hijackDomains.length，
            // 说明 fake-ip-filter 此前为空（CVR UI 已清空或首次注入），脚本已完整重新写入
            console.log(`   实际新增数: ${newEntries.length} 条（fake-ip-filter 中已存在 ${existingSet.size} 条本脚本条目）`);

        } catch (err) {
            console.error("❌ Hosts DNS 拦截注入失败:", err);
        }
    }

    return config; // 返回修改后的最终配置

} // function main 结束

/**
 *
 * ══════════════════════ ░░ 附录：技术白皮书 ░░ ═══════════════════════
 * 
 * ══════════════════════════ ░░ 风险边界 ░░ ══════════════════════════
 *
 *   ⚠️ 进程规则（PROCESS-NAME）：
 *     - 需要管理员权限 + TUN / Service 模式，系统代理模式下完全无效
 *     - Windows 进程名大小写不敏感，macOS / Linux 严格区分大小写
 *       扩展前务必在任务管理器中核对精确名称，建议仅作为辅助手段
 *
 *   ⚠️ 激进模式（ENABLE_AGGRESSIVE）：
 *     - 可能影响官网 / 插件商店 / 云功能访问，请阅读注释后谨慎开启
 *     - 已知受影响域名：adobe.io（插件市场/字体）、adsk.com（Autodesk 官网）、
 *       officecdn（Office 更新/模板）、ieonline.microsoft.com（ActiveX/旧版 OA 系统）
 *
 *   ℹ️ no-resolve 修饰符：
 *     - 仅对 IP 类规则（IP-CIDR / GEOIP）有意义，
 *       DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / DOMAIN-REGEX 等域名类规则加 no-resolve 无效，
 *       本脚本已全部移除，无需手动处理
 *     - 补充：若流量到达 Mihomo（本脚本所依赖的代理内核）时已携带真实 IP
 *       （应用层自行完成 DNS（域名系统）解析），no-resolve 在此场景下自然无需发挥作用，
 *       规则仍按 IP 直接比对，与有无 no-resolve 无关
 *
 *   ⚠️ REJECT-DROP（静默丢包）vs REJECT（立即重置）选型原则：
 *     REJECT      → 立即返回 TCP RST（重置报文），软件立刻感知失败，
 *                   进入离线模式，启动无卡顿；推荐用于遥测 / 授权域名
 *     REJECT-DROP → 静默丢包，不回应任何报文，软件 Socket 陷入 SYN_SENT
 *                   直至系统 TCP 超时；超时时长为估算值（非固定值），
 *                   应用层 Socket 阻塞约 15–30s（含 TCP 重传轮次，期间可能伴随数次重试），
 *                   实际取决于 OS TCP 重传配置（Windows 默认 SYN 重传总时长约 21s）
 *                   → 仅用于非官方补丁后门（backdoorSuffix / backdoorKeyword）
 *                     和进程级规则，以此消耗恶意程序连接池、阻碍其快速切换备用域名，拖慢重试节奏
 *     ⚡ 代价：软件启动时若命中 REJECT-DROP 会有明显卡顿，
 *              如遇启动极慢可将 REJECT-DROP 批量改为 REJECT
 *
 *   ⚠️ Hosts 模块生效前提（ENABLE_HOSTS_TRICK）：
 *     - CVR → DNS 覆写 → 必须同时开启「启用 DNS」和「使用 Hosts」，缺一不可
 *     - 脚本注入 use-hosts: true 会被 CVR UI 层覆盖，必须手动开启，脚本无法替代手动开启设置
 *     - 「使用系统 Hosts」是两套独立机制（对应 Windows 自带的 hosts 文件），无需开启
 *     - 未开启时本模块静默失效（脚本仍打印成功日志，但拦截实际不生效）
 *
 * ══════════════════════════ ░░ 设计取舍 ░░ ══════════════════════════
 *
 *   💡 规则去重策略：未采用 Set+filter 去重——真正原因是去重操作可能改变规则顺序，
 *      而 first-match 语义下顺序即策略，顺序改变直接导致规则语义变化（语义风险）。
 *      工程成本（代码复杂度）仅为次要因素。
 *      数据层按厂商拆分后各数组职责单一，跨数组重复概率极低，改由人工维护数据层唯一性。
 *      注：fake-ip-filter（虚假 IP 过滤表）合并使用 Set 仅为去重，顺序无关，与此场景不同。
 *
 *   💡 adobeAuthChain 推测项集中于数组末尾：
 *      独立块注释区分「已确认 / 待抓包确认」，以可用性优先于最小权限原则；
 *      待抓包确认后可视情况将推测项移至 adobeSuffix（改为 REJECT）。
 *
 *   💡 Firefly 连带影响（本脚本主动放弃拦截，原因见下）：
 *      effectiveFirefly=true 时，以下进程的鉴权请求均走代理，进程规则仅覆盖 AdobeGCClient.exe：
 *        AdobeGCClient.exe  ← 由 processBlockRules REJECT-DROP 兜底（已覆盖）
 *        Creative Cloud.exe ← 含授权心跳（主动放弃拦截）
 *        CCXProcess.exe     ← CC 扩展宿主进程（主动放弃拦截）
 *        CoreSync.exe       ← CC 同步守护进程（主动放弃拦截）
 *      放弃原因：非官方激活环境中，补丁通过阻断 AdobeGCClient.exe 的出站网络连接来绕过激活验证，
 *      其余进程的心跳即便放行也不会触发重新验证；TUN 进程规则本身不可靠，扩展覆盖成本高于收益。
 *
 *   💡 KEYWORD "entitlement.autodesk" 与 "api.entitlements.autodesk.com" 无重叠：
 *      DOMAIN-KEYWORD 为子串匹配，"entitlement.autodesk"（entitlement 后紧跟点）
 *      在 "api.entitlements.autodesk.com"（entitlement 后跟 s 再跟点）中不存在；
 *      简言之：匹配 entitlement.autodesk.com，但不匹配 entitlements.autodesk.com（多了一个 s）。
 *      两者均为独立覆盖，不可互相替代（见 autodeskKeyword / autodeskSuffix 注释）。
 *
 *   💡 BLOCK vs AGGRESSIVE 重叠为纵深防御设计意图：
 *      "entitlement.autodesk" 同时出现在 autodeskKeyword（BLOCK 层）和 aggressiveRules（AGGRESSIVE 层）。
 *      所有开关组合下均无副作用，无需合并或删除任一条目（见 BLOCK vs AGGRESSIVE 重叠说明注释块）。
 *
 * ══════════════════════════ ░░ 逻辑架构 ░░ ══════════════════════════
 *
 *   ── 规则分层结构（LAYERS 容器 + LAYER_ORDER 驱动）──────────────────
 *     allow → block → process → proxy → aggressive → direct
 *     first-match（首条命中即生效，后续规则不再判断）
 *     LAYERS 对象为具名容器，优先级由 LAYER_ORDER 数组显式保证，
 *     与 LAYERS 键迭代顺序无关。禁止随意调整 LAYER_ORDER（调整即改变规则语义）
 *   ──────────────────────────────────────────────────────────────
 *
 *   ── 代理组识别策略链（多级降级，依次尝试直至成功）──────────────────
 *     [优选·关键词] 关键词 + 类型 + 多节点  ← 最严格，优先匹配
 *     [优选·正则]   正则宽松匹配           ← 次选，排除兜底组
 *     [优选·类型]   类型约束              ← 放宽数量约束
 *     [兜底降级]    兜底组选取             ← GLOBAL/"全局" 等
 *     [一级容错选取]   放宽数量，保留类型过滤  ← 防 Ghost Group
 *     [最终容错选取]   完全放宽，类型不限
 *     全部失败 → proxyGroupName="DIRECT" → 出口断言拦截 → 中止注入
 *   ──────────────────────────────────────────────────────────────
 *
 *   ── 哨兵清理算法（栈重建，O(N) 单次遍历，处理任意数量堆叠）────────────
 *     原理：单次遍历原数组，重建新数组 newRules，用栈记录每个 START 被压入时
 *           newRules 的长度（作为注入区间在 newRules 中的起始位置快照）；
 *           遇 END 时弹出栈顶快照，将 newRules 截断至快照长度，
 *           等效于删除整个注入区间（含区间内的全部旧注入规则）；
 *           孤儿 END（栈为空）静默跳过；孤儿 START 的快照留在栈中无 END 匹配，
 *           其后内容已正常推入 newRules，循环结束后自然保留，无需额外处理。
 *     复杂度：O(N) 时间 / O(N) 空间（newRules 重建），无 splice 内存搬运，
 *             优于旧"最近配对 while"方案的 O(P×N)。
 *     选型说明：废弃 filter 状态机——孤儿 START 会导致其后全部订阅规则被误删
 *     （灾难性误删）；废弃"第一个 START + 第一个 END"——嵌套场景连带删除有效规则；
 *     废弃"最近配对 while + splice"——O(P×N) 且每次 splice 触发 V8 内存搬运；
 *     栈重建一次遍历完成全部处理，是时间/空间/安全的最优解。
 *   ──────────────────────────────────────────────────────────────
 *
 *   ── effectiveFirefly 派生开关 ────────────────────────────────────
 *     effectiveFirefly = ENABLE_FIREFLY && ENABLE_BLOCK
 *     所有 Firefly 逻辑均使用此变量，防止"看起来开了但没生效"的误判
 *     （ENABLE_FIREFLY=true + ENABLE_BLOCK=false 时自动降级为 false）
 *   ──────────────────────────────────────────────────────────────
 *
 * ══════════════════════════ ░░ 维护规范 ░░ ══════════════════════════
 *
 *   ⚠️ 去坐标化准则（解除对绝对位置的绑定，防止行号变动后锚点失效）：
 *     - 【去行号化】禁止在注释中引用具体行号（如"见 120 行"），
 *                  必须使用变量名或锚点关键词定位（如"见 adobeAuthChain 注释"）
 *     - 【禁绝对值】禁止引用"数组第 N 项"、"前几项"、"第几个"等绝对坐标；
 *                  禁止引用策略编号（如"阶段 1"、"步骤 3"）；
 *                  必须使用逻辑描述或变量名作为锚点
 *                  （如"关键词优选策略"、"一级容错选取策略"）
 *     - 【禁止标记】严禁在逻辑行添加动态标记（如 // Fix by XXX），保持代码无状态
 *     - 【版本隔离】逻辑变更必须记录在"版本演进"区，严禁原地覆盖关键逻辑说明
 *
 *   🛠️ 编程防御：
 *     - 严禁直接访问 config[n]，必须使用 ?. 或 Array.isArray() 级联校验
 *     - 数据层（域名 / 组名）必须在配置区声明，逻辑层只负责读取，严禁硬编码
 *
 *   📐 注释语义与 emoji 规范：
 *     - 🛡️ [安全/防护/注入成功]  核心加固逻辑或注入点生效
 *     - 🚫 [拦截/阻断]           拦截策略、REJECT / REJECT-DROP 逻辑
 *     - 🔓 [放行/豁免]           Firefly 调度或特定域名白名单
 *     - ⚠️ [高危/警告/风险边界]  必须重点阅读，涉及系统代理失效或权限要求
 *     - ⚡ [风险/潜在隐患]       可能导致卡顿、重连或极端情况下的逻辑失效
 *     - ⚙️ [配置/开关]           用户可调节的变量定义
 *     - 🔍 [诊断/审计]           console.log 运行日志或逻辑对齐
 *     - 💡 [设计/原理]           解释为何不使用状态机、为何采用 while 循环等深度意图
 *     - ℹ️ [提示/注意]           中性信息说明，如环境要求、路径说明等
 *
 * ══════════════════════════ ░░ 版本演进 ░░ ══════════════════════════
 *   （按主题合并，去版本号，保留全部技术细节）
 *
 *   [术语统一]
 *     危险组 → 排除组（EXCLUDED）/ 风险组 → 兜底组（FALLBACK）/ 安全组 → 优选组（Eligible）
 *     对应变量：DANGEROUS_NAMES → EXCLUDED_NAMES，RISKY_NAMES → FALLBACK_NAMES
 *     对应函数：isSafeGroup → isEligibleGroup，isRiskyGroup → isFallbackGroup
 *     Hosts 黑洞欺骗模块 → Hosts DNS 拦截模块（"黑洞"仅指 0.0.0.0 模式，不适合作两类机制的统称）
 *
 *   [高危修复]
 *     ① Ghost Group 崩溃漏洞：前四轮策略全部失败时，proxyGroupName 保持硬编码默认值
 *        "节点选择"，该组名通过出口断言后注入规则，但 Mihomo 内核找不到此策略组，
 *        导致启动失败、网络瘫痪。
 *        修复：新增容错选取策略——从配置中抓取首个合法组；
 *        容错选取也失败时将 proxyGroupName 设为 "DIRECT"，由出口断言拦截并中止注入，
 *        完整降级为订阅原始规则，防止内核崩溃。
 *     ② proxy-groups 为空时同样强制 proxyGroupName="DIRECT"，触发出口断言中止注入。
 *     ③ proxyGroupName 存在性断言：出口安全断言之后、规则注入之前，验证
 *        proxyGroupName 真实存在于 proxy-groups 中，防止极端路径下硬编码默认值
 *        漏过断言后导致内核崩溃。
 *
 *   [安全加固]
 *     · sanitizeName 最终覆盖范围（按 Unicode 码点升序）：
 *         \u00AD（软连字符）/ \u061C（ALM，阿拉伯字母方向标记）/
 *         \u200B–\u200F（零宽空格 / 零宽不连接符 / 零宽连接符 /
 *                        LRM 左到右标记 / RLM 右到左标记）/
 *         \u202A–\u202E（LRE 左嵌 / RLE 右嵌 / PDF 弹出 / LRO 左覆写 / RLO 右覆写）/
 *         \u2060（Word Joiner）/ \u2066–\u2069（LRI / RLI / FSI / PDI Bidi 隔离符）/
 *         \uFEFF（BOM，字节顺序标记）
 *       历次迭代补充：\u00AD（防 "DIR\u00ADECT" 绕过）→ \u202A–\u202E（防视觉欺骗攻击）→
 *       \u2066–\u2069（Unicode 6.3+ Bidi 隔离符）→ \u061C / \u200E / \u200F（补全主要 Bidi 格式字符）
 *       正则字符类按码点升序排列，便于按范围扩充。
 *     · 关键词 / 正则优选策略代理组名匹配改用 sanitizeName 清洗后的字符串，防止含零宽
 *       字符的组名（如 "节\u200B点选择"）通过 isEligibleGroup 但在匹配中失配。
 *     · fake-ip-filter 追加段增加类型安全过滤：构建 existingSet 前过滤非字符串元素，
 *       防止订阅中混入 null / 对象导致 Set 吸入脏数据；
 *       写回时同步清洗原数组非字符串元素，彻底消除脏数据回流。
 *     · config.hosts / config.dns.hosts 合并前增加类型硬校验（typeof + !Array.isArray 双重验证），
 *       防止上游订阅将 hosts 写成数组 / 字符串后展开为以索引为 key 的非法对象。
 *
 *   [架构优化]
 *     · adobeAuthChain 提取为单一真相源，消除 adobeFireflyAllow 与 adobeSuffix 历史双写。
 *     · effectiveFirefly = ENABLE_FIREFLY && ENABLE_BLOCK（派生开关），防止错误启用。
 *     · HOSTS_MODE 提升至顶部开关区，统一配置入口。
 *     · 引入 pushSuffix / pushDomain / pushKeyword 辅助函数，规则组装更简洁。
 *     · 数据层按厂商 / 类别拆分为具名数组，维护成本大幅降低。
 *     · HOSTS 模式改用 modeMap 对象，替代 switch-case。
 *     · miscSoftwareSuffix 空数组调用加 length 判断，明确扩展占位意图。
 *     · ENABLE_DIRECT 非默认备用规则（休眠规则）补全激活条件（补充 ENABLE_DIRECT=true 前提）。
 *     · finalPool 注入顺序改用 LAYER_ORDER 数组驱动，顺序显式数据化，
 *       消除"顺序隐含在展开语句里"的隐式耦合（双源真相漏洞）。
 *     · 规则去重策略说明深化：未采用 Set 去重的真正原因是去重可能改变规则顺序，
 *       而 first-match 语义下顺序即策略，是语义风险而非工程成本问题。
 *
 *   [工程修复]
 *     · GLOBAL / "全局" 中英文不对称修复（两步缺一不可）：
 *         ① 将"全局"从 EXCLUDED_CN_RE 移出，由 FALLBACK_CN_RE 单独识别。
 *         ② isEligibleGroup 中对 isFallbackGroup 提前返回 true，允许兜底组进入优选策略；
 *            出口断言不再错误拦截合法选中的兜底组。
 *         深层缺陷：兜底选中"全局"后，原版断言中 EXCLUDED_CN_RE.test("全局")=true，
 *         立即中止注入，整条路径净效果为零——两步修复缺一不可。
 *     · 优选·类型约束策略增加 Array.isArray + length > 0 约束，防止选中空 proxies 组。
 *     · 兜底组降级策略补加类型约束 ["select","url-test","fallback"]，与优选策略一致，
 *       防止 relay / load-balance 等不适合做出口的组被选中。
 *     · 容错选取策略分两步（保守 → 最终），relay 组不再第一优先。
 *     · 哨兵清理升级为 O(N) 栈重建算法（单次遍历重建新数组 newRules，无 splice 内存搬运；
 *       孤儿标记由栈结构自然处理，不再需要两步清理，时间复杂度由 O(P×N) 降至 O(N)）。
 *     · 哨兵清理改为精确等值比较（=== 替代 startsWith），更精确更快速。
 *     · fake-ip-filter 仅追加新条目，不打乱订阅原有顺序；
 *       hijackDomains 为字面量常量，去除冗余的 new Set() 包装。
 *     · ENABLE_SCRIPT 分支先清理旧标记再插入，防止多次切换后堆叠。
 *     · 文件末尾补充换行符（POSIX 规范）。
 *
 *   [注释与日志]
 *     · 全部英文术语首次出现处补充中文解释：
 *       first-match / TUN / REJECT-DROP / QUIC / SNI / ECH / BOM /
 *       OOBE / TLD / DDNS / NCSI / WSS / CDN / SDK 等
 *     · adobeUdpBlock 全条目补充 DNS / Sniffer（流量嗅探器）依赖说明：
 *       DOMAIN-SUFFIX 类规则依赖 Mihomo 能获取域名（DNS 解析映射或 Sniffer 嗅探 SNI），
 *       纯 IP 形式的 QUIC（基于 UDP 的快速传输协议）流量无法被 DOMAIN 类规则命中。
 *     · adobeUdpBlock 末尾补充 ECH（Encrypted Client Hello，加密客户端握手）完整失控结论：
 *       ECH 场景下 allow 层与 block 层的 DOMAIN 类规则同时失效，规则层完全失去控制权；
 *       PROCESS-NAME 是 ECH 下唯一有效的兜底手段（不依赖 SNI 嗅探）。
 *     · adobeAuthChain / adobeFireflyOnly QUIC 豁免说明补充 ECH 前提：
 *       豁免仅在 Mihomo 能识别 SNI 时成立；ECH 场景下 allow 层对 UDP 流量同样失效。
 *     · Autodesk KEYWORD / SUFFIX 重叠注释修正：
 *       "entitlement.autodesk" 不覆盖 "api.entitlements.autodesk.com"（子串断裂，
 *       "entitlement" 后紧跟 "s" 而非点），两者各自独立覆盖，不可互相替代。
 *     · EXCLUDED_CN_RE 两段结构说明（精确匹配 vs 子串匹配，禁止合并为统一锚定）。
 *     · youtubei.googleapis 补充影响播放器元数据 API 的说明（不仅限于遥测）。
 *     · aggressiveRules REGEX / SUFFIX 互补关系（前者不匹配裸域，后者补充覆盖）。
 *     · processBlockRules 首条明确标注为纯文档性规则，不产生额外拦截效果。
 *     · CorelDRW.exe 补充适用版本范围（CorelDRAW 2017+）。
 *     · scdown.adobe.io / lcs-cops.adobe.io 保持推测态，标注【待抓包确认】。
 *     · detectportal.firefox.com 默认注释，副作用明显，按需开启。
 *     · Hosts / rules 分层说明：hosts 命中后 rules 不执行，rules 为 hosts 未生效时的兜底。
 *     · fake-ip-filter 追加段补充 CVR 预设模板可能清空追加项的提示；
 *       补充 .sort() 的理由（确保每次 reload 追加顺序一致）；
 *       补充全量重排触发 DNS hash 重建的风险说明。
 *     · umeng.com / safebrowsing.google 补充副作用说明。
 *     · ENABLE_SCRIPT=false 分支注释修正：
 *       该分支仍会清除旧 debug 标记并插入新标记，是"带调试钩子的受控禁用"，非零修改；
 *       如需保留 Hosts DNS 拦截但关闭规则注入，应保持 ENABLE_SCRIPT=true 并关闭各子模块开关。
 *     · 哨兵三段式规则描述统一为 TYPE,VALUE,POLICY（更通俗）。
 *     · 哨兵清理算法补充选型说明（why not filter 状态机：孤儿 START 会导致灾难性误删）。
 *     · 诊断日志 g.name → g?.name，防止 proxy-groups 混入 null 时抛 TypeError。
 *     · effectiveFirefly 及 Firefly 相关日志格式统一为 ✅/❌ 风格，与同日志块保持一致。
 *     · 日志补充实际追加条目数（newEntries.length），方便排查 CVR UI 清空问题。
 *     · ENABLE_AGGRESSIVE 日志增加受影响域名警告行。
 *
 *   [去绝对值化]
 *     代理组识别逻辑注释全量替换为语义标签，消除"阶段 N"编号依赖：
 *     原"阶段 1–5"改为 [优选·关键词] / [优选·正则] / [优选·类型] /
 *     [兜底降级] / [一级容错选取] / [最终容错选取]，插入新策略不影响现有标签语义。
 *     规则：禁止在注释中引用策略编号，使用功能描述作为锚点。
 *
 * ════════════════════════════════════════════════════════════════════
 */
