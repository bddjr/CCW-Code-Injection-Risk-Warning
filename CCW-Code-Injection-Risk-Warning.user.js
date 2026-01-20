// ==UserScript==
// @name         CCW-Code-Injection-Risk-Warning
// @description  CCW代码注入风险警告，让你的账号更安全。
// @author       bddjr
// @version      20260120-1436
// @match        https://www.ccw.site/*
// @icon         https:/m.ccw.site/community/images/logo-ccw.png
// @grant        none
// @run-at       document-start
// @updateURL    https://bddjr.github.io/CCW-Code-Injection-Risk-Warning/CCW-Code-Injection-Risk-Warning.user.js
// @downloadURL  https://bddjr.github.io/CCW-Code-Injection-Risk-Warning/CCW-Code-Injection-Risk-Warning.user.js
// ==/UserScript==


//@ts-nocheck

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
                needWarn = true
                if (hasWitCatJSSandBox) {
                    msg.push('作品可能会使用“白猫的JS沙箱”扩展调用“Gandi云数据”扩展的代码注入漏洞积木！')
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
                    const thisMsg = [thisMsgPrefix + '并使用以下代码注入漏洞积木：']
                    for (const opcode in codeInjectionBlocksCount) {
                        const count = codeInjectionBlocksCount[opcode]
                        if (count) thisMsg.push(JSON.stringify(opcode) + ' × ' + count + ' 块')
                    }
                    msg.push(thisMsg.join('\n'))
                } else {
                    msg.push(thisMsgPrefix + '但未检测到代码注入漏洞积木。')
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
                console.warn(msg.join('\n\n'))
                if (hasCustomExt) msg.push('如果要复制链接，请打开DevTools，查看控制台(Console)。\n如果控制台没有内容，请刷新页面。')
                msg.push('如果要继续加载作品，请输入“继续加载”，然后点击“确定”，\n否则点击“取消”。')
                for (const message = msg.join('\n\n'); ;) {
                    const input = window.prompt(message)
                    if (input == null) {
                        acceptLoadExt = false
                        break
                    }
                    if (["继续加载", "繼續加載"].includes(input.trim())) {
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
    return out
}