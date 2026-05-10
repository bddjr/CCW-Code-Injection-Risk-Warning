// （实验性）限制网站可以使用的资源来源。
// 不建议使用，这会影响一些必须对外交互的作品，例如KukeChat
const meta = document.createElement('meta')
meta.setAttribute('http-equiv', 'content-security-policy')
meta.setAttribute('content', `default-src 'self' 'unsafe-eval' 'unsafe-inline' https://*.ccw.site https://*.xiguacity.cn https://zhishi.oss-cn-beijing.aliyuncs.com/ https://*.qq.com;`)
document.head.appendChild(meta)