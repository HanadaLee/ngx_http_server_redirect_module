#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_str_t                  server;
    ngx_http_complex_value_t  *filter;
    ngx_int_t                  negative;
} ngx_http_server_redirect_rule_t;

typedef struct {
    ngx_array_t               *rules;
} ngx_http_server_redirect_conf_t;


static void * ngx_http_server_redirect_create_conf(ngx_conf_t *cf);
static char * ngx_http_server_redirect(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_server_redirect_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_server_redirect_virtual_server(ngx_http_request_t *r,
    ngx_str_t *host);
static ngx_int_t ngx_http_server_redirect_post_config(ngx_conf_t *cf);


static ngx_command_t  ngx_http_server_redirect_commands[] = {

    { ngx_string("server_redirect"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE12,
      ngx_http_server_redirect,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_server_redirect_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_server_redirect_post_config,   /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    ngx_http_server_redirect_create_conf,   /* create server configuration */
    NULL,                                   /* merge server configuration */

    NULL,                                   /* create location configuration */
    NULL                                    /* merge location configuration */
};


ngx_module_t  ngx_http_server_redirect_module = {
    NGX_MODULE_V1,
    &ngx_http_server_redirect_module_ctx,  /* module context */
    ngx_http_server_redirect_commands,     /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
ngx_http_server_redirect(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_server_redirect_conf_t  *srcf = conf;
    ngx_http_server_redirect_rule_t  *rule;

    ngx_str_t                        *value;
    ngx_str_t                         s;
    ngx_http_compile_complex_value_t  ccv;

    if (srcf->rules == NULL) {
        srcf->rules = ngx_array_create(cf->pool, 4,
            sizeof(ngx_http_server_redirect_rule_t));
        if (srcf->rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    rule = ngx_array_push(srcf->rules);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(rule, sizeof(ngx_http_server_redirect_rule_t));

    value = cf->args->elts;
    rule->server = value[1];

    if (cf->args->nelts == 3) {
        if (ngx_strncmp(value[2].data, "if=", 3) == 0) {
            s.len = value[2].len - 3;
            s.data = value[2].data + 3;
            rule->negative = 0;
        } else if (ngx_strncmp(value[2].data, "if!=", 4) == 0){
            s.len = value[2].len - 4;
            s.data = value[2].data + 4;
            rule->negative = 1;
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid parameter \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &s;
        ccv.complex_value = ngx_palloc(cf->pool,
                                    sizeof(ngx_http_complex_value_t));
        if (ccv.complex_value == NULL) {
            return NGX_CONF_ERROR;
        }

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        rule->filter = ccv.complex_value;
    } else {
        rule->negative = 0;
        rule->filter = NULL;
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_server_redirect_create_conf(ngx_conf_t *cf)
{
    ngx_http_server_redirect_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_server_redirect_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static ngx_int_t
ngx_http_server_redirect_post_config(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_handler_pt        *h;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_server_redirect_handler;

    return NGX_OK;
}


static ngx_int_t
ngx_http_server_redirect_handler(ngx_http_request_t *r)
{
    ngx_http_server_redirect_conf_t  *srcf;
    ngx_http_server_redirect_rule_t  *rules;
    ngx_str_t                        *server = NULL;
    ngx_uint_t                        i;

    srcf = ngx_http_get_module_srv_conf(r, ngx_http_server_redirect_module);

    if (srcf->rules == NULL || srcf->rules->nelts == 0) {
        return NGX_DECLINED;
    }

    rules = srcf->rules->elts;

    for (i = 0; i < srcf->rules->nelts; i++) {
        if (rules[i].filter) {
            ngx_str_t  val;
            if (ngx_http_complex_value(r, rules[i].filter, &val)
                    != NGX_OK) {
                return NGX_ERROR;
            }

            if ((val.len == 0 || (val.len == 1 && val.data[0] == '0'))) {
                if (!rules[i].negative) {
                    /* Skip due to filter*/
                    continue;
                }
            } else {
                if (rules[i].negative) {
                    /* Skip due to negative filter*/
                    continue;
                }
            }
        }

        server = &rules[i].server;
        break;
    }

    if (server == NULL || server->data == NULL || server->len == 0) {
        return NGX_DECLINED;
    }

    if (ngx_http_validate_host(server, r->pool, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "server_redirect: ignore server redirect "
                      "due to validate host failure");
        return NGX_DECLINED;
    }

    if (ngx_http_server_redirect_virtual_server(r, server) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "server_redirect: failed to redirect server");
        return NGX_ERROR;
    }

    if (r->headers_in.server.len) {
        r->headers_in.server = *server;
    }

    if (r->headers_in.host) {
        r->headers_in.host->value = *server;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "server_redirect: redirect to new server %V", server);

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_server_redirect_virtual_server(ngx_http_request_t *r,
    ngx_str_t *host)
{
    ngx_int_t                  rc;
    ngx_http_connection_t     *hc;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;

#if (NGX_SUPPRESS_WARN)
    cscf = NULL;
#endif

    hc = r->http_connection;

    rc = ngx_http_find_virtual_server(r->connection,
                                      hc->addr_conf->virtual_names,
                                      host, r, &cscf);

    if (rc == NGX_ERROR) {
        ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    if (rc == NGX_DECLINED) {
        cscf = hc->addr_conf->default_server;
        return NGX_OK;
    }

    r->srv_conf = cscf->ctx->srv_conf;
    r->loc_conf = cscf->ctx->loc_conf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_set_connection_log(r->connection, clcf->error_log);

    return NGX_OK;
}