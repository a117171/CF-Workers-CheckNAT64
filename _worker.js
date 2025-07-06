import { connect } from 'cloudflare:sockets';
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const 路径 = url.pathname;
        if (路径 === '/check') {
            const 查询参数 = url.searchParams.get('dns64') || 'dns64.cmliussss.net';
            try {
                const ipv6地址 = await resolveToIPv6('speed.cloudflare.com', 查询参数);

                // 使用 socket 方式请求 cdn-cgi/trace
                const traceResult = await fetchCdnCgiTrace(ipv6地址);

                if (traceResult.success) {
                    const result = parseCdnCgiTrace(traceResult.data);
                    return new Response(JSON.stringify(result, null, 2), {
                        status: 200,
                        headers: { 'Content-Type': 'application/json' }
                    });
                } else {
                    return new Response(JSON.stringify({
                        nat64_ipv6: ipv6地址,
                        //cdn_cgi_url: `http://[${ipv6地址}]/cdn-cgi/trace`,
                        error: '请求失败',
                        message: traceResult.error
                    }, null, 2), {
                        status: 500,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
            } catch (error) {
                console.error('解析错误:', error);
                return new Response(JSON.stringify({ error: '解析失败', message: error.message }), {
                    status: 500,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
        }
        return new Response('Hello World!');
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
    let result = { };

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

    try {
        const ipv4 = await fetchIPv4(target);
        const nat64 = await queryNAT64(ipv4 + '.ip.090227.xyz');
        return nat64;
    } catch (error) {
        console.error('解析错误:', error);
        return '解析失败';
    }
}
