import fs from 'fs';

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

function file_read(r) {
    let path = r.args.path;

    if (!path) {
        r.return(400, 'missing path\n');
        return;
    }

    try {
        r.headersOut['Content-Type'] = 'text/plain';
        r.return(200, fs.readFileSync(path).toString());
    } catch (e) {
        r.return(500, e.message + '\n');
    }
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

export default {proxy_endpoint, origin_endpoint, http_fetch, file_read};
