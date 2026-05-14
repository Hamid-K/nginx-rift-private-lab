set pagination off
set confirm off
handle SIGPIPE nostop noprint pass

break /nginx-src/src/http/ngx_http_request.c:594
commands
silent
printf "REQ_ALLOC r=%p pool=%p c=%p header_in=%p uri_len=%zu uri_data=%p\n", r, pool, c, r->header_in, r->uri.len, r->uri.data
continue
end

break ngx_http_script_copy_capture_code
commands
silent
set $e = (ngx_http_script_engine_t *) $rdi
set $r = $e->request
printf "COPY_CAPTURE r=%p pool=%p pos=%p is_args=%d quote=%d quoted=%d plus=%d uri_len=%zu uri_data=%p\n", $r, $r->pool, $e->pos, $e->is_args, $e->quote, $r->quoted_uri, $r->plus_in_uri, $r->uri.len, $r->uri.data
continue
end

break /nginx-src/src/core/ngx_palloc.c:336
commands
silent
printf "CLEANUP_ADD pool=%p cleanup=%p size=%zu old_next=%p\n", p, c, size, c->next
continue
end

break ngx_http_free_request
commands
silent
set $r = (ngx_http_request_t *) $rdi
printf "REQ_FREE r=%p pool=%p pool_cleanup=%p uri_len=%zu uri_data=%p\n", $r, $r->pool, $r->pool ? $r->pool->cleanup : 0, $r->uri.len, $r->uri.data
continue
end

break ngx_destroy_pool
commands
silent
set $p = (ngx_pool_t *) $rdi
printf "POOL_DESTROY pool=%p last=%p end=%p cleanup=%p large=%p\n", $p, $p->d.last, $p->d.end, $p->cleanup, $p->large
continue
end
