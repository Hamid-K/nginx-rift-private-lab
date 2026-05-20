function proxy_endpoint(r) {
    let proxyAuth = r.headersIn['Proxy-Authorization'] || '';

    if (!proxyAuth) {
        r.return(407, 'PROXY:NO-AUTH');
        return;
    }

    r.return(200, 'PROXY:' + proxyAuth.slice(0, 64));
}

function origin_endpoint(r) {
    r.return(200, 'ORIGIN:OK');
}

async function http_fetch(r) {
    try {
        let reply = await ngx.fetch('http://127.0.0.1:19413/origin');
        let body = await reply.text();
        r.return(200, body);
    } catch (e) {
        r.return(500, e.message);
    }
}

export default {proxy_endpoint, origin_endpoint, http_fetch};
