// ==UserScript==
// @name         CCW-Code-Injection-Risk-Warning
// @description  CCW代码注入风险警告，让你的账号更安全。
// @author       bddjr
// @version      20260509-1820
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

// Source Code:
// https://github.com/bddjr/CCW-Code-Injection-Risk-Warning

if (location.hostname == 'learn.ccw.site') {
    // 自动防御基于 iframe 的代码注入攻击，仅允许白名单网址

    // 创作者学院编辑器提示：暂时只支持bilibili和西瓜视频以及站内链接
    // 查找并分析js文件
    // https://learn.ccw.site/_next/static/chunks/708-9a7dbfbb32eca7d3.js
    // https://learn.ccw.site/_next/static/chunks/5191-e0df96b8928838d4.js
    // https://learn.ccw.site/_next/static/chunks/app/(normal)/home/layout-a9cb46b1ff2d4762.js
    // 创作者学院前端支持插入的 URL origin ： 
    // [
    //   "https://scratch.mit.edu", 
    //   "https://youtube.com", 
    //   "https://www.facebook.com", 
    //   "https://www.twitch.tv", 
    //   "https://twitter.com", 
    //   "https://qa.cocrea.world", 
    //   "https://www.ixigua.com", 
    //   "https://ixigua.com", 
    //   "https://bilibili.com", 
    //   "https://player.bilibili.com", 
    //   "https://www.bilibili.com", 
    //   "https://www.ccw.site", 
    //   "https://ccw.site", 
    //   "https://learn.ccw.site", 
    //   "https://learn-qa.xiguacity.cn"
    // ]
    // 或者 origin 包含 "ccw.site" 或 "xiguacity.cn" 。
    // 仅在编辑器里插入的时候会校验，但查看文章的时候加载iframe前不会校验。
    // 我不知道服务器会不会校验。

    // 定义自己的白名单
    // 参考 https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/frame-src
    const whitelist = [
        "https://www.ccw.site/embed",
        "https://ccw.site/embed",
        "https://player.bilibili.com/player.html",
        "https://www.bilibili.com/video/",
        "https://bilibili.com/video/",
    ]
    const meta = document.createElement('meta')
    meta.setAttribute('http-equiv', 'content-security-policy')
    meta.setAttribute('content', `frame-src ${whitelist.join(' ') || "'none'"};`)
    document.head.appendChild(meta)
    console.log('【脚本 CCW代码注入风险警告】自动防御基于 iframe 的代码注入攻击，仅允许白名单网址\n', meta, '\n', whitelist)

} else if (location.hostname == 'm.ccw.site') {
    // 基于svg的代码注入攻击
    // 脚本无法防御该攻击，因为攻击者的代码先执行。
    // 参考 https://github.com/bddjr/CCW-Code-Injection-Risk-Warning/issues/3
    if (document.contentType == 'image/svg+xml') {
        try {
            window.stop()
        } catch (e) { }
        alert(`【脚本 CCW代码注入风险警告】

您正在使用标签页访问svg，恶意代码可能已经执行。
建议您关掉该标签页，然后尽快修改您的账号的密码。
如果攻击者已经使用您的账号捣乱，请及时向共创世界管理员或鸭鸭院长申诉。`)
    }

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

    JSON.parse = function myParse() {
        const out = parse.apply(this, arguments)
        if (acceptLoadExt !== true && out?.targets?.[0]?.blocks) {
            if (acceptLoadExt === null) {
                const { targets, extensions, extensionURLs } = out
                const hasCCWData = checkHasExt(extensions, "CCWData")
                const hasWitCatJSSandBox = checkHasExt(extensions, "WitCatJSSandBox")
                let hasCustomExt = false
                let needWarn = false
                const msg = ['【脚本 CCW代码注入风险警告】']
                // CCWData
                if (hasCCWData) {
                    // needWarn = true
                    if (hasWitCatJSSandBox) {
                        needWarn = true
                        msg.push('漏洞链警告！作品可能会使用“白猫的JS沙箱”扩展调用“Gandi云数据”扩展的代码注入漏洞积木！')
                    }
                    // 检测代码注入漏洞积木
                    let hasCodeInjectionBlock = false
                    const codeInjectionBlocksCount = {
                        CCWData_getValueInJSON: 0,
                        CCWData_setValueInJSON: 0
                    }
                    for (const target of targets) {
                        const { blocks } = target
                        for (const id in blocks) {
                            const block = blocks[id]
                            const { opcode } = block
                            if (codeInjectionBlocksCount.hasOwnProperty(opcode)) {
                                hasCodeInjectionBlock = true
                                codeInjectionBlocksCount[opcode]++
                            }
                        }
                    }
                    // 生成警告消息
                    const thisMsgPrefix = '作品试图加载“Gandi云数据”扩展，'
                    if (hasCodeInjectionBlock) {
                        needWarn = true
                        const thisMsg = [thisMsgPrefix + '并使用以下代码注入漏洞积木：']
                        for (const opcode in codeInjectionBlocksCount) {
                            const count = codeInjectionBlocksCount[opcode]
                            if (count) thisMsg.push(JSON.stringify(opcode) + ' × ' + count + ' 块')
                        }
                        msg.push(thisMsg.join('\n'))
                    } else {
                        // msg.push(thisMsgPrefix + '但未检测到代码注入漏洞积木。')
                    }
                }
                // 自制扩展
                if (extensionURLs instanceof Object) {
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
                    if (window !== window.top && !location.pathname.startsWith('/embed')) {
                        acceptLoadExt = false
                        console.log('【脚本 CCW代码注入风险警告】检测到在 iframe 里，且网址路径开头不是 /embed ，自动阻止加载可疑作品')
                    } else {
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
            }
            if (acceptLoadExt === false) throw Error("Reject by user script: CCW-Code-Injection-Risk-Warning")
        }
        if (acceptLoadExt === true && JSON.parse === myParse) {
            // 取消劫持
            JSON.parse = parse
        }
        return out
    }
}