CCW代码注入风险警告，让你的账号更安全。  

安装TamperMonkey，然后点击下方链接，安装脚本：  
https://bddjr.github.io/CCW-Code-Injection-Risk-Warning/CCW-Code-Injection-Risk-Warning.user.js  

该脚本支持检测并拦截以下攻击：
- 基于作品使用 “Gandi 云数据” 扩展的代码注入漏洞攻击
- 基于作品加载第三方扩展的代码注入漏洞攻击
- 基于创作者学院的文章里嵌入 iframe 的代码注入漏洞攻击

> [!CAUTION]  
> 该脚本无法拦截使用标签页访问 m.ccw.site 加载恶意 svg 的代码注入攻击。  
> 使用 iframe 嵌入 m.ccw.site 加载恶意 svg 也可以执行恶意代码。  
> 该漏洞可以被攻击者用于盗号。  
> 漏洞演示：https://m.ccw.site/user_projects_assets/a8039314e7b97ea48e176b34090b680e.svg  
> 建议根据按照以下步骤操作，增强安全性：
> 
> - 如果您使用 Google Chrome 浏览器：  
>   访问 https://m.ccw.site ，然后点击网址左侧的按钮，然后点击“网站设置”，然后将“JavaScript”权限改为“阻止”。  
> 
> - 如果您使用 Microsoft Edge 浏览器：  
>   访问 https://m.ccw.site ，然后点击网址左侧的🔒按钮，然后点击“此网站的权限”，然后将“JavaScript”权限改为“阻止”。  
> 
> - 如果您使用 Mozilla Firefox 浏览器：  
>   无法禁用网站的 JavaScript 权限，建议更换浏览器。  

> [!CAUTION]  
> 攻击者成功注入恶意代码之后，可以盗取浏览器自动填充的账号密码，即使网页未显示输入框。  
> 建议禁用浏览器的自动填充密码，或者改为“在查看或填写网站密码之前提示设备登录选项。始终征求许可”  
> 
> ![3](readme-image/3.png)  

> [!CAUTION]  
> 该脚本暂时不能检测或拦截基于 Scratch 编辑器编辑造型的代码注入攻击。  
> 参考 https://muffin.ink/blog/scratch-vulnerability-disclosure/  
> 漏洞演示 https://www.ccw.site/detail/69f73e772a7d36316189ef73  

---

参考 https://github.com/bddjr/CCW-Code-Injection

---

效果图：

![0](readme-image/0.png)

![1](readme-image/1.png)

![2](readme-image/2.png)

