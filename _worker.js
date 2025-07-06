import { connect } from 'cloudflare:sockets';
let 临时TOKEN, 永久TOKEN;
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const UA = request.headers.get('User-Agent') || 'null';
        const 路径 = url.pathname;
        const currentDate = new Date();
        const timestamp = Math.ceil(currentDate.getTime() / (1000 * 60 * 31)); // 每31分钟一个时间戳
        临时TOKEN = await 双重哈希(url.hostname + timestamp + UA);
        永久TOKEN = env.TOKEN || 临时TOKEN;
        if (路径 === '/check') {
            const 查询参数 = url.searchParams.get('dns64') || url.searchParams.get('nat64') || 'dns64.cmliussss.net';
            const host = url.searchParams.get('host') || 'speed.cloudflare.com';
            try {
                const ipv6地址 = await resolveToIPv6(host, 查询参数);

                // 使用 socket 方式请求 cdn-cgi/trace
                const traceResult = await fetchCdnCgiTrace(ipv6地址);

                if (traceResult.success) {
                    const result = parseCdnCgiTrace(traceResult.data);
                    const response = {
                        success: true,
                        nat64_ipv6: ipv6地址,
                        cdn_cgi_url: `http://[${ipv6地址}]/cdn-cgi/trace`,
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
                        nat64_ipv6: ipv6地址,
                        cdn_cgi_url: `http://[${ipv6地址}]/cdn-cgi/trace`,
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
        return new Response(临时TOKEN);
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
    const html = `<!DOCTYPE html>`;
    return new Response(html, {
        headers: { "content-type": "text/html;charset=UTF-8" }
    });
}