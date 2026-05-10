const meta = document.createElement('meta')
meta.setAttribute('http-equiv', 'content-security-policy')
meta.setAttribute('content', `default-src 'self' 'unsafe-eval' 'unsafe-inline' https://*.ccw.site https://*.xiguacity.cn https://zhishi.oss-cn-beijing.aliyuncs.com/ https://*.qq.com;`)
document.head.appendChild(meta)