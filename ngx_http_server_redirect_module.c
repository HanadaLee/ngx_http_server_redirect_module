#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static void * ngx_http_server_redirect_create_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_server_redirect_find_virtual_server(
    ngx_http_request_t *r, u_char *host, size_t len);
static char * ngx_http_server_redirect(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_server_redirect_handler(ngx_http_request_t *r);


typedef struct {
    ngx_str_t   new_server;
} ngx_http_server_redirect_conf_t;


static ngx_command_t  ngx_http_server_redirect_commands[] = {

    { ngx_string("server_redirect"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_server_redirect,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_server_redirect_module_ctx = {
    NULL,                                   /* preconfiguration */
    NULL,                                   /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_server_redirect_create_conf,   /* create location configuration */
    NULL,                                   /* merge location configuration */
};


ngx_module_t  ngx_http_server_redirect_module = {
    NGX_MODULE_V1,
    &ngx_http_server_redirect_module_ctx, 	/* module context */
    ngx_http_server_redirect_commands,		/* module directives */
    NGX_HTTP_MODULE,                    	/* module type */
    NULL,                               	/* init master */
    NULL,    							  	/* init module */
    NULL,                                 	/* init process */
    NULL,                                  	/* init thread */
    NULL,                                  	/* exit thread */
    NULL,                                  	/* exit process */
    NULL,                                  	/* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
ngx_http_server_redirect(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *args;
    
    ngx_http_server_redirect_conf_t *srcf = conf;
    ngx_http_core_loc_conf_t  *clcf;
    
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_server_redirect_handler;

    args = cf->args->elts;
    srcf->new_server = args[1];
    
    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_server_redirect_find_virtual_server(ngx_http_request_t *r,
    u_char *host, size_t len)
{
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;

    if (r->virtual_names == NULL) {
        return NGX_DECLINED;
    }

    cscf = ngx_hash_find_combined(&r->virtual_names->names,
                                  ngx_hash_key(host, len), host, len);

    if (cscf) {
        goto found;
    }

#if (NGX_PCRE)

    if (len && r->virtual_names->nregex) {
        ngx_int_t                n;
        ngx_uint_t               i;
        ngx_str_t                name;
        ngx_http_server_name_t  *sn;

        name.len = len;
        name.data = host;

        sn = r->virtual_names->regex;

        for (i = 0; i < r->virtual_names->nregex; i++) {

            n = ngx_http_regex_exec(r, sn[i].regex, &name);

            if (n == NGX_OK) {
                cscf = sn[i].server;
                goto found;
            }

            if (n == NGX_DECLINED) {
                continue;
            }

            return NGX_ERROR;
        }
    }

#endif

    return NGX_DECLINED;

found:
    
    r->srv_conf = cscf->ctx->srv_conf;
    r->loc_conf = cscf->ctx->loc_conf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    r->connection->log->file = clcf->error_log->file;
#if (NGX_SYSLOG)
    r->connection->log->syslog = clcf->error_log->syslog;
#endif

    if (!(r->connection->log->log_level & NGX_LOG_DEBUG_CONNECTION)) {
        r->connection->log->log_level = clcf->error_log->log_level;
    }

    return NGX_OK;
}


void ngx_http_server_redirect_request_handler(ngx_event_t *ev)
{
    ngx_connection_t    *c;
    ngx_http_request_t  *r;
    ngx_http_log_ctx_t  *ctx;

    c = ev->data;
    r = c->data;

    ctx = c->log->data;
    ctx->current_request = r;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http run request: \"%V?%V\"", &r->uri, &r->args);

    if (ev->write) {
        r->write_event_handler(r);

    } else {
        r->read_event_handler(r);
    }

    ngx_http_run_posted_requests(c);
}


static ngx_int_t
ngx_http_server_redirect_handler(ngx_http_request_t *r)
{
    ngx_int_t res;
    ngx_str_t *server;
    ngx_http_server_redirect_conf_t *srcf;

    srcf = ngx_http_get_module_srv_conf(r, ngx_http_server_redirect_module);
    server = &srcf->new_server;
    
    res = ngx_http_server_redirect_find_virtual_server(r,
        server->data, server->len);

    if (res == NGX_OK) {
        ngx_connection_t  *c;

        c = r->connection;

        if (r->plain_http) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                    "client sent plain HTTP request to HTTPS port");
            ngx_http_finalize_request(r, NGX_HTTP_TO_HTTPS);
            return NGX_ERROR;
        }

        if (c->read->timer_set) {
            ngx_del_timer(c->read);
        }

        c->read->handler = ngx_http_server_redirect_request_handler;
        c->write->handler = ngx_http_server_redirect_request_handler;
        r->read_event_handler = ngx_http_handler;

        /* handler will be called in 1ms timeout */
        ngx_add_timer(r->connection->read, 1);
        r->main->count++;
        
        return NGX_DONE;
    }

    return NGX_DECLINED;
}


static void *
ngx_http_server_redirect_create_conf(ngx_conf_t *cf)
{
    ngx_http_server_redirect_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_server_redirect_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->new_server.data = NULL;
    conf->new_server.len = 0;

    return conf;
}
