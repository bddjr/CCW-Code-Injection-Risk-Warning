// ==UserScript==
// @name         CCW-Code-Injection-Risk-Warning
// @description  CCW代码注入风险警告，让你的账号更安全。
// @author       bddjr
// @version      20260718-1319
// @match        https://www.ccw.site/*
// @match        https://learn.ccw.site/*
// @match        https://m.ccw.site/*
// @icon         https://m.ccw.site/community/images/logo-ccw.png
// @grant        none
// @run-at       document-start
// @updateURL    https://bddjr.github.io/CCW-Code-Injection-Risk-Warning/CCW-Code-Injection-Risk-Warning.user.js
// @downloadURL  https://bddjr.github.io/CCW-Code-Injection-Risk-Warning/CCW-Code-Injection-Risk-Warning.user.js
// ==/UserScript==
//@ts-nocheck

// 更多注意事项，请看源代码仓库：
// https://github.com/bddjr/CCW-Code-Injection-Risk-Warning

if (location.hostname == 'm.ccw.site') {
    // 基于新标签页访问 svg 网址的代码注入攻击
    // 脚本无法防御该攻击，因为攻击者的代码先执行。
    // 参考 https://github.com/bddjr/CCW-Code-Injection-Risk-Warning/issues/3

    // 该漏洞已修复，但不确定通过缓存访问的人是否能接收到CSP响应头，所以暂时保留这段代码。

    if (document.contentType == 'image/svg+xml') {
        try {
            window.stop()
        } catch (e) { }
        alert(`【脚本 CCW代码注入风险警告】

您正在使用标签页访问svg，恶意代码可能已经执行。
建议您关掉该标签页，然后尽快修改您的账号的密码。
如果攻击者已经使用您的账号捣乱，请及时向共创世界管理员或鸭鸭院长申诉。`)
    }

} else if (location.hostname == 'learn.ccw.site' || location.pathname.toLowerCase().startsWith('/post/')) {
    // 自动防御基于 iframe 的代码注入攻击，仅允许白名单网址

    // 创作者学院编辑器提示：暂时只支持bilibili和西瓜视频以及站内链接
    // 查找并分析js文件
    // https://learn.ccw.site/_next/static/chunks/708-9a7dbfbb32eca7d3.js
    // https://learn.ccw.site/_next/static/chunks/5191-e0df96b8928838d4.js
    // https://learn.ccw.site/_next/static/chunks/app/(normal)/home/layout-a9cb46b1ff2d4762.js
    // 创作者学院前端支持插入的 URL origin ：
    // [
    //   // 境内不能直连的，非必要
    //   "https://scratch.mit.edu",
    //   "https://youtube.com", // 重定向到 www.youtube.com
    //   "https://www.facebook.com",
    //   "https://www.twitch.tv",
    //   "https://twitter.com", // 重定向到 x.com
    //
    //   // 已无 DNS 解析
    //   "https://qa.cocrea.world",
    //
    //   // 西瓜视频已改名为抖音精选，以下旧域名会重定向到 www.douyin.com/jingxuan
    //   // 目前为止没看到有人嵌入这个网站的视频，非必要
    //   "https://www.ixigua.com",
    //   "https://ixigua.com",
    //
    //   // bilibili
    //   "https://bilibili.com",
    //   "https://player.bilibili.com",
    //   "https://www.bilibili.com",
    //
    //   // CCW
    //   "https://www.ccw.site",
    //   "https://ccw.site",
    //   "https://learn.ccw.site",
    //   "https://learn-qa.xiguacity.cn" // 已无 DNS 解析
    // ]
    // 或者 origin 包含 "ccw.site" 或 "xiguacity.cn" 。
    // 仅在编辑器里插入的时候会校验，但查看文章的时候加载iframe前不会校验。
    // 我不知道服务器会不会校验。

    // 定义自己的白名单
    // 参考 https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/frame-src
    const whitelist = [
        // CCW 兼容旧文章
        "https://ccw.site/post/",
        "https://www.ccw.site/post/",

        // CCW 使用 embed 页面嵌入作品，不会在点开文章的时候立即执行恶意代码
        "https://www.ccw.site/embed",
        "https://ccw.site/embed",

        // bilibili 嵌入视频
        "https://player.bilibili.com/player.html",
        "https://www.bilibili.com/video/",
        "https://bilibili.com/video/",
    ]
    const meta = document.createElement('meta')
    meta.setAttribute('http-equiv', 'content-security-policy')
    meta.setAttribute('content', `frame-src ${whitelist.join(' ') || "'none'"};`)
    document.head.appendChild(meta)
    console.log('【脚本 CCW代码注入风险警告】自动防御基于 iframe 的代码注入攻击，仅允许白名单网址\n', meta, '\n', whitelist)

} else {
    // www.ccw.site

    const allowExtensionURLPrefix = "https://static.xiguacity.cn/h1t86b7fg6c7k36wnt0cb30m/static/js/"

    // let hasCCWDataCodeInjectionFix = null
    // /** 检测是否已安装 CCWData-Code-Injection-Fix.user.js */
    // function checkHasCCWDataCodeInjectionFix() {
    //     if (hasCCWDataCodeInjectionFix !== null) return hasCCWDataCodeInjectionFix
    //     const head = document.createElement('head')
    //     const script = document.createElement('script')
    //     script.src = "https://static.xiguacity.cn/h1t86b7fg6c7k36wnt0cb30m/static/js/scratch3_ccw_data.cbf43b4e.js"
    //     head.appendChild(script)
    //     return hasCCWDataCodeInjectionFix = !!(!script.hasAttribute("src") && script.innerHTML?.includes('ccwdataExtensionSafeEval'))
    // }

    function checkHasExt(extensions, id) {
        id = id.toLowerCase()
        return extensions?.some(v => (String(v).toLowerCase() == id))
    }

    let acceptLoadExt = null

    const { parse } = JSON

    if (location.pathname.startsWith('/profile/')) {
        // 防止个人资料的“学校”字段太长，导致页面无响应（卡死）
        JSON.parse = function myParse() {
            const out = parse.apply(this, arguments)
            if (typeof out?.body?.school == 'string' && out.body.school.length > 200) {
                console.log('【脚本 CCW代码注入风险警告】防止个人资料的“学校”字段太长，导致页面无响应（卡死）')
                out.body.school = out.body.school.slice(0, 200)
            }
            return out
        }
    } else {
        JSON.parse = function myParse() {
            const out = parse.apply(this, arguments)
            if (out?.targets?.[0]?.blocks) {
                // project.json
                if (acceptLoadExt !== true) {
                    if (acceptLoadExt === null) {
                        const { targets, extensions, extensionURLs } = out
                        let hasCustomExt = false
                        let needWarn = false
                        const msg = ['【脚本 CCW代码注入风险警告】']
                        // 自制扩展
                        if (typeof extensionURLs == 'object' && extensionURLs) {
                            const customExtDisplayArray = ['作品试图加载自制扩展：']
                            for (const key in extensionURLs) {
                                const url = new URL(extensionURLs[key], location).href;
                                if (!url.startsWith(allowExtensionURLPrefix)) {
                                    hasCustomExt = true
                                    customExtDisplayArray.push(JSON.stringify(key) + '\n' + url)
                                }
                            }
                            if (hasCustomExt) {
                                needWarn = true
                                msg.push(...customExtDisplayArray)
                            }
                        }
                        // 警告
                        if (needWarn) {
                            console.warn(msg.join('\n\n'))
                            if (hasCustomExt) msg.push('如果要复制链接，请打开DevTools，查看控制台(Console)。\n如果控制台没有内容，请刷新页面。')
                            msg.push('如果要继续加载作品，请输入“继续加载”，然后点击“确定”，\n否则点击“取消”。')
                            for (const message = msg.join('\n\n'); ;) {
                                let input = window.prompt(message)
                                if (input == null) {
                                    acceptLoadExt = false
                                    break
                                }
                                input = input.trim().toLowerCase()
                                if (["继续加载", "繼續加載", "jixujiazai"].includes(input)) {
                                    acceptLoadExt = true
                                    break
                                }
                            }
                        }
                    }
                    if (acceptLoadExt === false) throw Error("Reject by user script: CCW-Code-Injection-Risk-Warning")
                }
                if (acceptLoadExt === true && JSON.parse === myParse) {
                    // 取消劫持
                    JSON.parse = parse
                }
            }
            return out
        }
    }
}