import { connect } from 'cloudflare:sockets';
let 临时TOKEN, 永久TOKEN;
export default {
    async fetch(request, env, ctx) {
        const 网站图标 = env.ICO || 'https://cf-assets.www.cloudflare.com/dzlvafdwdttg/19kSkLSfWtDcspvQI5pit4/c5630cf25d589a0de91978ca29486259/performance-acceleration-bolt.svg';
        const url = new URL(request.url);
        const UA = request.headers.get('User-Agent') || 'null';
        const 路径 = url.pathname;
        const currentDate = new Date();
        const timestamp = Math.ceil(currentDate.getTime() / (1000 * 60 * 60 * 8)); // 每8小时一个时间戳
        临时TOKEN = await 双重哈希(url.hostname + timestamp + UA);
        永久TOKEN = env.TOKEN || 临时TOKEN;
        if (路径 === '/check') {
            const 查询参数 = url.searchParams.get('dns64') || url.searchParams.get('nat64') || 'dns64.cmliussss.net';
            const host = url.searchParams.get('host') || 'cf.hw.090227.xyz';
            try {
                const ipv6地址 = await resolveToIPv6(host, 查询参数);

                // 使用 socket 方式请求 cdn-cgi/trace
                const traceResult = await fetchCdnCgiTrace(ipv6地址);
                const simplifiedIPv6 = simplifyIPv6(ipv6地址);
                const nat64Prefix = extractNAT64Prefix(simplifiedIPv6);
                if (traceResult.success) {
                    const result = parseCdnCgiTrace(traceResult.data);
                    const response = {
                        success: true,
                        nat64_ipv6: simplifiedIPv6,
                        nat64_prefix: nat64Prefix,
                        cdn_cgi_url: `http://[${simplifiedIPv6}]/cdn-cgi/trace`,
                        trace_data: result,
                        timestamp: new Date().toISOString()
                    };
                    return new Response(JSON.stringify(response, null, 2), {
                        status: 200,
                        headers: { 'Content-Type': 'application/json' }
                    });
                } else {
                    return new Response(JSON.stringify({
                        success: false,
                        nat64_ipv6: simplifiedIPv6,
                        nat64_prefix: nat64Prefix,
                        cdn_cgi_url: `http://[${simplifiedIPv6}]/cdn-cgi/trace`,
                        error: '请求失败',
                        message: traceResult.error,
                        timestamp: new Date().toISOString()
                    }, null, 2), {
                        status: 500,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
            } catch (error) {
                console.error('解析错误:', error);
                return new Response(JSON.stringify({
                    success: false,
                    error: '解析失败',
                    message: error.message,
                    timestamp: new Date().toISOString()
                }, null, 2), {
                    status: 500,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
        } else if (路径 === '/ip-info') {
            if (!url.searchParams.has('token') || (url.searchParams.get('token') !== 临时TOKEN) && (url.searchParams.get('token') !== 永久TOKEN)) {
                return new Response(JSON.stringify({
                    status: "error",
                    message: `IP查询失败: 无效的TOKEN`,
                    timestamp: new Date().toISOString()
                }, null, 4), {
                    status: 403,
                    headers: {
                        "content-type": "application/json; charset=UTF-8",
                        'Access-Control-Allow-Origin': '*'
                    }
                });
            }
            let ip = url.searchParams.get('ip') || request.headers.get('CF-Connecting-IP');
            if (!ip) {
                return new Response(JSON.stringify({
                    status: "error",
                    message: "IP参数未提供",
                    code: "MISSING_PARAMETER",
                    timestamp: new Date().toISOString()
                }, null, 4), {
                    status: 400,
                    headers: {
                        "content-type": "application/json; charset=UTF-8",
                        'Access-Control-Allow-Origin': '*'
                    }
                });
            }

            if (ip.includes('[')) {
                ip = ip.replace('[', '').replace(']', '');
            }

            try {
                // 使用Worker代理请求HTTP的IP API
                const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);

                if (!response.ok) {
                    throw new Error(`HTTP error: ${response.status}`);
                }

                const data = await response.json();

                // 添加时间戳到成功的响应数据中
                data.timestamp = new Date().toISOString();

                // 返回数据给客户端，并添加CORS头
                return new Response(JSON.stringify(data, null, 4), {
                    headers: {
                        "content-type": "application/json; charset=UTF-8",
                        'Access-Control-Allow-Origin': '*'
                    }
                });

            } catch (error) {
                console.error("IP查询失败:", error);
                return new Response(JSON.stringify({
                    status: "error",
                    message: `IP查询失败: ${error.message}`,
                    code: "API_REQUEST_FAILED",
                    query: ip,
                    timestamp: new Date().toISOString(),
                    details: {
                        errorType: error.name,
                        stack: error.stack ? error.stack.split('\n')[0] : null
                    }
                }, null, 4), {
                    status: 500,
                    headers: {
                        "content-type": "application/json; charset=UTF-8",
                        'Access-Control-Allow-Origin': '*'
                    }
                });
            }
        }
        // 直接返回HTML页面，路径解析交给前端处理
        return await HTML(url.hostname, 网站图标);
    },
};

// 使用 socket 方式获取 cdn-cgi/trace
async function fetchCdnCgiTrace(ipv6Address) {
    try {
        const socket = connect({
            hostname: isIPv6(ipv6Address) ? `[${ipv6Address}]` : ipv6Address,
            port: 80
        });

        const writer = socket.writable.getWriter();
        const reader = socket.readable.getReader();

        try {
            // 构建 HTTP 请求
            const httpRequest = [
                'GET /cdn-cgi/trace HTTP/1.1',
                `Host: [${ipv6Address}]`,
                'User-Agent: Mozilla/5.0 cmliu/CF-Workers-CheckNAT64',
                'Accept: */*',
                'Connection: close',
                '',
                ''
            ].join('\r\n');

            // 发送 HTTP 请求
            await writer.write(new TextEncoder().encode(httpRequest));

            // 读取响应
            const chunks = [];
            while (true) {
                const { value, done } = await reader.read();
                if (done) break;
                chunks.push(value);
            }

            // 合并响应数据
            const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
            const fullResponse = new Uint8Array(totalLength);
            let offset = 0;
            for (const chunk of chunks) {
                fullResponse.set(chunk, offset);
                offset += chunk.length;
            }

            // 解析 HTTP 响应
            const responseText = new TextDecoder().decode(fullResponse);
            const headerEndIndex = responseText.indexOf('\r\n\r\n');

            if (headerEndIndex === -1) {
                return { success: false, error: '无效的HTTP响应' };
            }

            const headers = responseText.substring(0, headerEndIndex);
            const body = responseText.substring(headerEndIndex + 4);

            // 检查状态码
            const statusLine = headers.split('\r\n')[0];
            const statusMatch = statusLine.match(/HTTP\/\d\.\d (\d+)/);

            if (!statusMatch || statusMatch[1] !== '200') {
                return { success: false, error: `HTTP状态码: ${statusMatch ? statusMatch[1] : '未知'}` };
            }

            return { success: true, data: body };

        } finally {
            await writer.close();
            await reader.cancel();
        }

    } catch (error) {
        return { success: false, error: error.message };
    }
}

// 解析 cdn-cgi/trace 响应内容
function parseCdnCgiTrace(text) {
    let result = {};

    const lines = text.trim().split('\n');
    for (const line of lines) {
        const [key, value] = line.split('=');
        if (key && value !== undefined) {
            result[key] = value;
        }
    }

    return result;
}

// 检查是否为IPv4
function isIPv4(str) {
    const parts = str.split('.');
    return parts.length === 4 && parts.every(part => {
        const num = parseInt(part, 10);
        return num >= 0 && num <= 255 && part === num.toString();
    });
}

// 检查是否为IPv6
function isIPv6(str) {
    return str.includes(':') && /^[0-9a-fA-F:]+$/.test(str);
}

async function resolveToIPv6(target, DNS64Server) {
    // 获取域名的IPv4地址
    async function fetchIPv4(domain) {
        const url = `https://cloudflare-dns.com/dns-query?name=${domain}&type=A`;
        const response = await fetch(url, {
            headers: { 'Accept': 'application/dns-json' }
        });

        if (!response.ok) throw new Error('DNS查询失败');

        const data = await response.json();
        const ipv4s = (data.Answer || [])
            .filter(record => record.type === 1)
            .map(record => record.data);

        if (ipv4s.length === 0) throw new Error('未找到IPv4地址');
        return ipv4s[Math.floor(Math.random() * ipv4s.length)];
    }

    // 查询NAT64 IPv6地址
    async function queryNAT64(domain) {
        const socket = connect({
            hostname: isIPv6(DNS64Server) ? `[${DNS64Server}]` : DNS64Server,
            port: 53
        });

        const writer = socket.writable.getWriter();
        const reader = socket.readable.getReader();

        try {
            // 发送DNS查询
            const query = buildDNSQuery(domain);
            const queryWithLength = new Uint8Array(query.length + 2);
            queryWithLength[0] = query.length >> 8;
            queryWithLength[1] = query.length & 0xFF;
            queryWithLength.set(query, 2);
            await writer.write(queryWithLength);

            // 读取响应
            const response = await readDNSResponse(reader);
            const ipv6s = parseIPv6(response);

            return ipv6s.length > 0 ? ipv6s[0] : '未找到IPv6地址';
        } finally {
            await writer.close();
            await reader.cancel();
        }
    }

    // 构建DNS查询包
    function buildDNSQuery(domain) {
        const buffer = new ArrayBuffer(512);
        const view = new DataView(buffer);
        let offset = 0;

        // DNS头部
        view.setUint16(offset, Math.floor(Math.random() * 65536)); offset += 2; // ID
        view.setUint16(offset, 0x0100); offset += 2; // 标志
        view.setUint16(offset, 1); offset += 2; // 问题数
        view.setUint16(offset, 0); offset += 6; // 答案数/权威数/附加数

        // 域名编码
        for (const label of domain.split('.')) {
            view.setUint8(offset++, label.length);
            for (let i = 0; i < label.length; i++) {
                view.setUint8(offset++, label.charCodeAt(i));
            }
        }
        view.setUint8(offset++, 0); // 结束标记

        // 查询类型和类
        view.setUint16(offset, 28); offset += 2; // AAAA记录
        view.setUint16(offset, 1); offset += 2; // IN类

        return new Uint8Array(buffer, 0, offset);
    }

    // 读取DNS响应
    async function readDNSResponse(reader) {
        const chunks = [];
        let totalLength = 0;
        let expectedLength = null;

        while (true) {
            const { value, done } = await reader.read();
            if (done) break;

            chunks.push(value);
            totalLength += value.length;

            if (expectedLength === null && totalLength >= 2) {
                expectedLength = (chunks[0][0] << 8) | chunks[0][1];
            }

            if (expectedLength !== null && totalLength >= expectedLength + 2) {
                break;
            }
        }

        // 合并数据并跳过长度前缀
        const fullResponse = new Uint8Array(totalLength);
        let offset = 0;
        for (const chunk of chunks) {
            fullResponse.set(chunk, offset);
            offset += chunk.length;
        }

        return fullResponse.slice(2);
    }

    // 解析IPv6地址
    function parseIPv6(response) {
        const view = new DataView(response.buffer);
        let offset = 12; // 跳过DNS头部

        // 跳过问题部分
        while (view.getUint8(offset) !== 0) {
            offset += view.getUint8(offset) + 1;
        }
        offset += 5;

        const answers = [];
        const answerCount = view.getUint16(6); // 答案数量

        for (let i = 0; i < answerCount; i++) {
            // 跳过名称
            if ((view.getUint8(offset) & 0xC0) === 0xC0) {
                offset += 2;
            } else {
                while (view.getUint8(offset) !== 0) {
                    offset += view.getUint8(offset) + 1;
                }
                offset++;
            }

            const type = view.getUint16(offset); offset += 2;
            offset += 6; // 跳过类和TTL
            const dataLength = view.getUint16(offset); offset += 2;

            if (type === 28 && dataLength === 16) { // AAAA记录
                const parts = [];
                for (let j = 0; j < 8; j++) {
                    parts.push(view.getUint16(offset + j * 2).toString(16));
                }
                answers.push(parts.join(':'));
            }
            offset += dataLength;
        }

        return answers;
    }

    function convertToNAT64IPv6(ipv4Address) {
        const parts = ipv4Address.split('.');
        if (parts.length !== 4) {
            throw new Error('无效的IPv4地址');
        }

        // 将每个部分转换为16进制
        const hex = parts.map(part => {
            const num = parseInt(part, 10);
            if (num < 0 || num > 255) {
                throw new Error('无效的IPv4地址段');
            }
            return num.toString(16).padStart(2, '0');
        });

        // 构造NAT64
        return DNS64Server.split('/96')[0] + hex[0] + hex[1] + ":" + hex[2] + hex[3];
    }

    try {
        // 判断输入类型并处理
        const ipv4 = isIPv4(target) ? target : await fetchIPv4(target);
        const nat64 = DNS64Server.endsWith('/96') ? convertToNAT64IPv6(ipv4) : await queryNAT64(ipv4 + atob('LmlwLjA5MDIyNy54eXo='));
        return nat64;
    } catch (error) {
        console.error('解析错误:', error);
        return '解析失败';
    }
}

// 从IPv6地址提取NAT64 Prefix (/96)
function extractNAT64Prefix(ipv6Address) {
    // 展开IPv6地址为完整形式
    function expandIPv6(ipv6) {
        // 处理 :: 缩写
        if (ipv6.includes('::')) {
            const parts = ipv6.split('::');
            const leftParts = parts[0] ? parts[0].split(':') : [];
            const rightParts = parts[1] ? parts[1].split(':') : [];
            const missingParts = 8 - leftParts.length - rightParts.length;

            const expandedParts = [
                ...leftParts,
                ...Array(missingParts).fill('0000'),
                ...rightParts
            ];

            // 补全每个部分为4位
            return expandedParts.map(part => part.padStart(4, '0')).join(':');
        } else {
            // 补全每个部分为4位
            return ipv6.split(':').map(part => part.padStart(4, '0')).join(':');
        }
    }

    try {
        // 移除方括号
        let cleanIPv6 = ipv6Address.replace(/^\[|\].*$/g, '');

        // 展开IPv6地址为完整形式
        const expandedIPv6 = expandIPv6(cleanIPv6);

        // NAT64 IPv6地址格式: [prefix:96][IPv4:32]
        // 提取前96位(前6个16位组)作为前缀
        const parts = expandedIPv6.split(':');
        if (parts.length !== 8) {
            throw new Error('Invalid IPv6 address format');
        }

        // 取前6个部分作为NAT64前缀，移除前导0
        const prefixParts = parts.slice(0, 6).map(part => {
            return part.replace(/^0+/, '') || '0';
        });

        // 构建前缀并简化 - 如果最后几部分都是0，则用::简化
        let prefix = prefixParts.join(':');

        // 移除末尾的0部分并添加::
        while (prefix.endsWith(':0')) {
            prefix = prefix.slice(0, -2);
        }

        return prefix + '::/96';
    } catch (error) {
        console.error('提取NAT64前缀失败:', error);
        return 'unknown::/96';
    }
}

// 简化IPv6地址
function simplifyIPv6(ipv6) {
    // 移除方括号
    let simplified = ipv6.replace(/^\[|\].*$/g, '');

    // 循环处理 :0: 替换为 ::
    while (simplified.includes(':0:')) {
        simplified = simplified.replace(':0:', '::');
    }

    // 循环处理 ::: 替换为 ::
    while (simplified.includes(':::')) {
        simplified = simplified.replace(':::', '::');
    }

    // 移除前导零
    simplified = simplified.replace(/:0+([0-9a-fA-F])/g, ':$1');
    simplified = simplified.replace(/^0+([0-9a-fA-F])/g, '$1');

    // 处理开头的 :0:
    simplified = simplified.replace(/^:0:/, '::');

    return simplified;
}

async function 双重哈希(文本) {
    const 编码器 = new TextEncoder();

    const 第一次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(文本));
    const 第一次哈希数组 = Array.from(new Uint8Array(第一次哈希));
    const 第一次十六进制 = 第一次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');

    const 第二次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(第一次十六进制.slice(7, 27)));
    const 第二次哈希数组 = Array.from(new Uint8Array(第二次哈希));
    const 第二次十六进制 = 第二次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');

    return 第二次十六进制.toLowerCase();
}

async function HTML(hostname, 网站图标) {
    // 首页 HTML
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Check NAT64/DNS64 可用性检测</title>
    <link rel="icon" href="${网站图标}" type="image/x-icon">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'PingFang SC', 'Microsoft YaHei', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            max-width: 600px;
            width: 100%;
        }
        
        .header {
            text-align: center;
            margin-bottom: 40px;
        }
        
        .header h1 {
            color: #333;
            font-size: 2.5em;
            margin-bottom: 10px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .header p {
            color: #666;
            font-size: 1.1em;
        }
        
        .form-group {
            margin-bottom: 30px;
        }
        
        .form-group label {
            display: block;
            color: #333;
            font-weight: 600;
            margin-bottom: 10px;
            font-size: 1.1em;
        }
        
        .dns64-container {
            position: relative;
            display: flex;
            align-items: center;
        }
        
        .dns64-input {
            width: 100%;
            padding: 15px 50px 15px 15px;
            border: 2px solid #e1e5e9;
            border-radius: 12px;
            font-size: 1em;
            transition: all 0.3s ease;
            background: #fff;
        }
        
        .dropdown-arrow {
            position: absolute;
            right: 8px;
            top: 50%;
            transform: translateY(-50%);
            width: 36px;
            height: 36px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 6px;
            transition: all 0.3s ease;
            color: #666;
        }
        
        .dropdown-arrow:hover {
            background: rgba(102, 126, 234, 0.1);
            color: #667eea;
        }
        
        .dropdown-arrow.active {
            transform: translateY(-50%) rotate(180deg);
            color: #667eea;
        }
        
        .dns64-input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .dropdown {
            position: absolute;
            top: 100%;
            left: 0;
            right: 0;
            background: #fff;
            border: 2px solid #667eea;
            border-top: none;
            border-radius: 0 0 12px 12px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            z-index: 1000;
            display: none;
            max-height: 200px;
            overflow-y: auto;
        }
        
        .dropdown.show {
            display: block;
        }
        
        .dropdown-item {
            padding: 12px 15px;
            cursor: pointer;
            transition: all 0.2s ease;
            border-bottom: 1px solid #f0f0f0;
            font-size: 0.95em;
        }
        
        .dropdown-item:last-child {
            border-bottom: none;
        }
        
        .dropdown-item:hover {
            background: #667eea;
            color: white;
        }
        
        .check-btn {
            width: 100%;
            padding: 18px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            border: none;
            border-radius: 12px;
            font-size: 1.2em;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-bottom: 30px;
        }
        
        .check-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);
        }
        
        .check-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        
        .result {
            margin-top: 30px;
            padding: 25px;
            border-radius: 12px;
            display: none;
        }
        
        .result.success {
            background: linear-gradient(135deg, #5cbf60, #4caf50);
            color: white;
        }
        
        .result.error {
            background: linear-gradient(135deg, #f44336, #e53935);
            color: white;
        }
        
        .result h3 {
            margin-bottom: 20px;
            font-size: 1.3em;
        }
        
        .copy-section {
            display: grid;
            gap: 15px;
            margin: 20px 0;
        }
        
        .copy-item {
            background: rgba(255, 255, 255, 0.2);
            padding: 15px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
            border: 2px solid transparent;
        }
        
        .copy-item:hover {
            background: rgba(255, 255, 255, 0.3);
            border-color: rgba(255, 255, 255, 0.5);
        }
        
        .copy-item .label {
            font-weight: 600;
            margin-bottom: 5px;
        }
        
        .copy-item .value {
            font-family: 'Courier New', monospace;
            word-break: break-all;
        }
        
        .ip-info {
            margin-top: 20px;
            padding: 15px;
            background: rgba(255, 255, 255, 0.2);
            border-radius: 8px;
        }
        
        .ip-info h4 {
            margin-bottom: 10px;
        }
        
        .loading {
            display: none;
            text-align: center;
            margin: 20px 0;
        }
        
        .loading-spinner {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: conic-gradient(from 0deg, #667eea, #764ba2, #667eea);
            mask: radial-gradient(circle at center, transparent 50%, black 52%);
            -webkit-mask: radial-gradient(circle at center, transparent 50%, black 52%);
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }
        
        .loading-text {
            font-size: 1.1em;
            color: #333;
            position: relative;
            overflow: hidden;
        }
        
        .loading-dots {
            display: inline-block;
            animation: loadingDots 1.5s infinite;
        }
        
        .loading-progress {
            display: inline-block;
            animation: loadingProgress 2s ease-in-out infinite;
        }
        
        .loading-pulse {
            animation: loadingPulse 1.2s ease-in-out infinite;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        @keyframes loadingDots {
            0%, 20% { 
                content: '';
                opacity: 0;
            }
            25% { 
                content: '.';
                opacity: 1;
            }
            50% { 
                content: '..';
                opacity: 1;
            }
            75% { 
                content: '...';
                opacity: 1;
            }
            100% { 
                content: '';
                opacity: 0;
            }
        }
        
        @keyframes loadingProgress {
            0% { 
                transform: translateX(-100%);
                opacity: 0.5;
            }
            50% { 
                transform: translateX(0%);
                opacity: 1;
            }
            100% { 
                transform: translateX(100%);
                opacity: 0.5;
            }
        }
        
        @keyframes loadingPulse {
            0%, 100% { 
                opacity: 1;
                transform: scale(1);
            }
            50% { 
                opacity: 0.7;
                transform: scale(1.02);
            }
        }
        
        .loading-wave {
            display: inline-block;
            animation: wave 1.5s ease-in-out infinite;
        }
        
        @keyframes wave {
            0%, 100% { transform: translateY(0px); }
            25% { transform: translateY(-3px); }
            50% { transform: translateY(0px); }
            75% { transform: translateY(3px); }
        }
        
        @keyframes octocat-wave {
            0%, 100% { transform: rotate(0) }
            20%, 60% { transform: rotate(-25deg) }
            40%, 80% { transform: rotate(10deg) }
        }
        
        .toast {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: #5cbf60;
            color: white;
            padding: 15px 20px;
            border-radius: 8px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
            transform: translateX(200%);
            transition: all 0.3s ease;
            z-index: 1000;
            max-width: 300px;
            word-wrap: break-word;
        }
        
        .toast.show {
            transform: translateX(0);
        }

        .github-corner {
            position: fixed;
            top: 0;
            right: 0;
            z-index: 1000;
            transition: all 0.3s ease;
        }
        
        .github-corner:hover {
            transform: scale(1.05);
        }
        
        .github-corner svg {
            fill: rgba(102, 126, 234, 0.9);
            color: #fff;
            width: 80px;
            height: 80px;
            filter: drop-shadow(0 4px 8px rgba(0,0,0,0.2));
            transition: all 0.3s ease;
        }
        
        .github-corner:hover svg {
            fill: rgba(102, 126, 234, 1);
        }

        .github-corner:hover .octo-arm {
            animation: octocat-wave 560ms ease-in-out;
        }

        @media (max-width: 768px) {
            .github-corner svg {
                width: 60px;
                height: 60px;
            }
            
            .github-corner:hover .octo-arm {
                animation: none;
            }
            
            .github-corner .octo-arm {
                animation: octocat-wave 560ms ease-in-out;
            }
        }
    </style>
</head>
<body>
  <a href="https://github.com/cmliu/CF-Workers-CheckNAT64" target="_blank" class="github-corner" aria-label="View source on Github">
    <svg viewBox="0 0 250 250" aria-hidden="true">
      <path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path>
      <path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path>
      <path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path>
    </svg>
  </a>
    <div class="container">
        <div class="header">
            <h1>🌐 DNS64/NAT64 检测</h1>
            <p>检测DNS64作为NAT64的PROXYIP可用性</p>
        </div>
        
        <div class="form-group">
            <label for="dns64Input">DNS64 Server/NAT64 Prefix</label>
            <div class="dns64-container">
                <input type="text" id="dns64Input" class="dns64-input" placeholder="请选择预设值或输入自定义值">
                <div class="dropdown-arrow" id="dropdownArrow" onclick="toggleDropdown()">
                    <svg width="12" height="8" viewBox="0 0 12 8" fill="currentColor">
                        <path d="M1 1l5 5 5-5" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </div>
                <div class="dropdown" id="dropdown">
                    <div class="dropdown-item" onclick="selectPreset('2001:67c:2960:6464::/96')">level66.services（德国）</div>
                    <div class="dropdown-item" onclick="selectPreset('dns64.ztvi.hw.090227.xyz')">ZTVI（美国）</div>
                </div>
            </div>
        </div>
        
        <button class="check-btn" onclick="checkNAT64()">🚀 开始检测</button>
        
        <div class="loading" id="loading">
            <div class="loading-spinner"></div>
        </div>
        
        <div class="result" id="result">
            <!-- 结果将在这里显示 -->
        </div>
    </div>
    
    <div class="toast" id="toast"></div>
    
    <script>
        const dns64Input = document.getElementById('dns64Input');
        const dropdown = document.getElementById('dropdown');
        const dropdownArrow = document.getElementById('dropdownArrow');
        
        // 本地存储键名
        const STORAGE_KEY = 'dns64_nat64_server';
        
        // 从本地存储读取值
        function loadFromStorage() {
            try {
                const savedValue = localStorage.getItem(STORAGE_KEY);
                if (savedValue) {
                    dns64Input.value = savedValue;
                }
            } catch (error) {
                console.warn('无法读取本地存储:', error);
            }
        }
        
        // 保存到本地存储
        function saveToStorage(value) {
            try {
                localStorage.setItem(STORAGE_KEY, value);
            } catch (error) {
                console.warn('无法保存到本地存储:', error);
            }
        }
        
        function selectPreset(value) {
            dns64Input.value = value;
            saveToStorage(value);
            hideDropdown();
        }
        
        function showDropdown() {
            dropdown.classList.add('show');
            dropdownArrow.classList.add('active');
        }
        
        function hideDropdown() {
            dropdown.classList.remove('show');
            dropdownArrow.classList.remove('active');
        }
        
        function toggleDropdown() {
            if (dropdown.classList.contains('show')) {
                hideDropdown();
            } else {
                showDropdown();
            }
        }
        
        // 文本框聚焦时显示下拉框（如果为空）
        dns64Input.addEventListener('focus', function() {
            if (this.value.trim() === '') {
                showDropdown();
            }
        });
        
        // 文本框失去焦点时隐藏下拉框
        dns64Input.addEventListener('blur', function() {
            // 延迟隐藏，以便点击下拉选项时有时间处理
            setTimeout(() => {
                // 检查是否点击的是下拉箭头，如果是则不隐藏
                if (!dropdownArrow.matches(':hover')) {
                    hideDropdown();
                }
            }, 150);
        });
        
        // 监听输入事件
        dns64Input.addEventListener('input', function() {
            const value = this.value.trim();
            saveToStorage(this.value); // 保存原始值（包含空格）
        });
        
        // 监听键盘事件
        dns64Input.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                hideDropdown();
            }
        });
        
        // 点击页面其他地方时隐藏下拉框
        document.addEventListener('click', function(e) {
            if (!e.target.closest('.dns64-container')) {
                hideDropdown();
            }
        });
        
        function showToast(message) {
            const toast = document.getElementById('toast');
            toast.textContent = message;
            toast.classList.add('show');
            setTimeout(() => {
                toast.classList.remove('show');
            }, 3000);
        }
        
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                showToast('已复制到剪贴板');
            }).catch(() => {
                // fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = text;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                showToast('已复制到剪贴板');
            });
        }
        
        async function checkNAT64() {
            const dns64Value = dns64Input.value.trim();
            const loading = document.getElementById('loading');
            const result = document.getElementById('result');
            const checkBtn = document.querySelector('.check-btn');
            
            // 显示加载状态
            loading.style.display = 'block';
            result.style.display = 'none';
            checkBtn.disabled = true;
            
            const MAX_RETRIES = 3;
            let retryCount = 0;
            let lastError = null;
            
            // 检测函数
            async function performCheck() {
                const apiUrl = dns64Value 
                    ? \`https://${hostname}/check?nat64=\${encodeURIComponent(dns64Value)}\`
                    : \`https://${hostname}/check\`;
                
                const checkResponse = await fetch(apiUrl);
                const checkData = await checkResponse.json();
                
                if (!checkData.success) {
                    throw new Error(checkData.message || '检测失败');
                }
                
                return checkData;
            }
            
            // 重试逻辑
            while (retryCount < MAX_RETRIES) {
                retryCount++;
                
                try {
                    // 第一步：检测NAT64
                    const checkData = await performCheck();
                    
                    // 检测成功，生成复制值
                    const nat64Value = \`[\${checkData.nat64_ipv6}]\`;
                    const proxyIPValue = \`ProxyIP.\${checkData.nat64_ipv6.replace(/:/g, '-')}.ip.090227.xyz\`;
                    
                    result.className = 'result success';
                    result.innerHTML = \`
                        <h3>✅ 检测成功</h3>
                        <p>此DNS64/NAT64服务器可用作PROXYIP</p>
                        \${retryCount > 1 ? \`<p style="color: rgba(255,255,255,0.8); font-size: 0.9em;">经过 \${retryCount} 次尝试后成功</p>\` : ''}
                        
                        <div class="copy-section">
                            <div class="copy-item" onclick="copyToClipboard('\${nat64Value}')">
                                <div class="label">PROXYIP (IPv6格式)</div>
                                <div class="value">\${nat64Value}</div>
                            </div>
                            <div class="copy-item" onclick="copyToClipboard('\${proxyIPValue}')">
                                <div class="label">PROXYIP (域名格式)</div>
                                <div class="value">\${proxyIPValue}</div>
                            </div>
                            <div class="copy-item" onclick="copyToClipboard('\${checkData.nat64_prefix}')">
                                <div class="label">NAT64 (IPv6前缀)</div>
                                <div class="value">\${checkData.nat64_prefix}</div>
                            </div>
                        </div>
                        
                        <div id="ipInfo" class="ip-info" style="display: none;">
                            <h4>🌍 落地IP信息</h4>
                            <div id="ipInfoContent"></div>
                        </div>
                    \`;
                    
                    // 第二步：获取IP信息
                    if (checkData.trace_data && checkData.trace_data.ip) {
                        try {
                            const ipInfoResponse = await fetch(\`https://${hostname}/ip-info?token=${临时TOKEN}&ip=\${checkData.trace_data.ip}\`);
                            const ipInfoData = await ipInfoResponse.json();
                            
                            if (ipInfoData.status === 'success') {
                                document.getElementById('ipInfo').style.display = 'block';
                                document.getElementById('ipInfoContent').innerHTML = \`
                                    <p><strong>IP地址：</strong>\${ipInfoData.query}</p>
                                    <p><strong>国家：</strong>\${ipInfoData.country} (\${ipInfoData.countryCode})</p>
                                    <p><strong>地区：</strong>\${ipInfoData.regionName}, \${ipInfoData.city}</p>
                                    <p><strong>ISP：</strong>\${ipInfoData.isp}</p>
                                    <p><strong>AS：</strong>\${ipInfoData.as}</p>
                                \`;
                            }
                        } catch (ipError) {
                            console.error('获取IP信息失败:', ipError);
                        }
                    }
                    
                    result.style.display = 'block';
                    loading.style.display = 'none';
                    checkBtn.disabled = false;
                    return; // 成功退出函数
                    
                } catch (error) {
                    console.error(\`检测错误 (第\${retryCount}次尝试):\`, error);
                    lastError = error;
                    
                    // 如果还有重试机会，等待100毫秒后继续
                    if (retryCount < MAX_RETRIES) {
                        await new Promise(resolve => setTimeout(resolve, 100));
                        continue;
                    }
                }
            }
            
            // 所有重试都失败了
            result.className = 'result error';
            result.innerHTML = \`
                <h3>❌ 检测失败</h3>
                <p>经过 \${MAX_RETRIES} 次尝试后仍然失败</p>
                <p><strong>最后一次错误：</strong>\${lastError?.message || '未知错误'}</p>
                <p>此DNS64/NAT64服务器不可用作PROXYIP</p>
                <p style="color: rgba(255,255,255,0.8); font-size: 0.9em; margin-top: 10px;">
                    建议：请尝试其他DNS64服务器
                </p>
            \`;
            
            result.style.display = 'block';
            loading.style.display = 'none';
            checkBtn.disabled = false;
        }
        
        // 回车键触发检测
        dns64Input.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                checkNAT64();
            }
        });
        
        // 页面加载时读取缓存值
        loadFromStorage();
    </script>
</body>
</html>`;
    return new Response(html, {
        headers: { "content-type": "text/html;charset=UTF-8" }
    });
}