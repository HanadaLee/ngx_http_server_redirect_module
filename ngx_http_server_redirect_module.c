
/*
 * Copyright (C) Hanada
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_CONDITION)
#include <ngx_http_condition_module.h>
#endif


typedef struct {
    ngx_http_complex_value_t  *server;
#if (NGX_CONDITION)
    ngx_condition_expr_id_t    expr_id;
#else
    ngx_http_complex_value_t  *filter;
    ngx_int_t                  negative;
#endif
} ngx_http_server_redirect_rule_t;


typedef struct {
    ngx_array_t               *rules;
    ngx_flag_t                 schedule_redirect;
} ngx_http_server_redirect_conf_t;


typedef struct {
    ngx_uint_t                 redirect_count;
} ngx_http_server_redirect_ctx_t;


static ngx_int_t ngx_http_server_redirect_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_server_redirect_null_variable(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_server_redirect_create_conf(ngx_conf_t *cf);
static char *ngx_http_server_redirect(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_server_redirect_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_server_redirect_handle_server_redirect(
    ngx_http_request_t *r, ngx_http_server_redirect_conf_t *srcf);
static ngx_int_t ngx_http_server_redirect_handle_schedule_redirect(
    ngx_http_request_t *r);
static ngx_int_t ngx_http_server_redirect_set_virtual_server(
    ngx_http_request_t *r, ngx_str_t *host);
static ngx_int_t ngx_http_server_redirect_find_virtual_server(
    ngx_connection_t *c, ngx_http_virtual_names_t *virtual_names,
    ngx_str_t *host, ngx_http_request_t *r, ngx_http_core_srv_conf_t **cscfp);
static ngx_int_t ngx_http_server_redirect_init(ngx_conf_t *cf);


static ngx_str_t  ngx_http_server_redirect_original_host
                    = ngx_string("server_redirect_original_host");
#if nginx_version >= 1029004
static ngx_str_t  ngx_http_server_redirect_original_port
                    = ngx_string("server_redirect_original_port");
#endif
static ngx_uint_t  ngx_http_server_redirect_original_host_index;
#if nginx_version >= 1029004
static ngx_uint_t  ngx_http_server_redirect_original_port_index;
#endif


static ngx_command_t  ngx_http_server_redirect_commands[] = {

    { ngx_string("server_redirect"),
      NGX_HTTP_SRV_CONF
#if (NGX_CONDITION)
                       |NGX_HTTP_SRV_WHEN_CONF|NGX_CONF_TAKE1,
#else
                       |NGX_CONF_TAKE12,
#endif
      ngx_http_server_redirect,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("schedule_redirect"),
      NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_server_redirect_conf_t, schedule_redirect),
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_server_redirect_module_ctx = {
    ngx_http_server_redirect_add_variables, /* preconfiguration */
    ngx_http_server_redirect_init,          /* postconfiguration */

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


static ngx_int_t
ngx_http_server_redirect_add_variables(ngx_conf_t *cf)
{
    ngx_int_t             n;
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &ngx_http_server_redirect_original_host,
                                NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_server_redirect_null_variable;

    n = ngx_http_get_variable_index(cf,
                                    &ngx_http_server_redirect_original_host);
    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_http_server_redirect_original_host_index = n;

#if nginx_version >= 1029004

    var = ngx_http_add_variable(cf, &ngx_http_server_redirect_original_port,
                                NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_server_redirect_null_variable;

    n = ngx_http_get_variable_index(cf,
                                    &ngx_http_server_redirect_original_port);
    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_http_server_redirect_original_port_index = n;

#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_server_redirect_null_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    *v = ngx_http_variable_null_value;

    return NGX_OK;
}


static char *
ngx_http_server_redirect(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_server_redirect_conf_t  *srcf = conf;
    ngx_http_server_redirect_rule_t  *rule;

    ngx_str_t                        *value;
#if !(NGX_CONDITION)
    ngx_str_t                         s;
#endif
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

#if (NGX_CONDITION)
    rule->expr_id = ngx_condition_get_associated_expr_id(cf);
#endif

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = ngx_palloc(cf->pool,
                                   sizeof(ngx_http_complex_value_t));
    if (ccv.complex_value == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    rule->server = ccv.complex_value;

#if !(NGX_CONDITION)
    if (cf->args->nelts == 3) {
        if (ngx_strncmp(value[2].data, "if=", 3) == 0) {
            s.len = value[2].len - 3;
            s.data = value[2].data + 3;
            rule->negative = 0;

        } else if (ngx_strncmp(value[2].data, "if!=", 4) == 0) {
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
#endif

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

    conf->schedule_redirect = NGX_CONF_UNSET;

    return conf;
}


static ngx_int_t
ngx_http_server_redirect_init(ngx_conf_t *cf)
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

    srcf = ngx_http_get_module_srv_conf(r, ngx_http_server_redirect_module);

    if (srcf->rules
        && ngx_http_server_redirect_handle_server_redirect(r, srcf) == NGX_OK)
    {
        return ngx_http_server_redirect_handler(r);
    }

    if (srcf->schedule_redirect == 1
        && ngx_http_server_redirect_handle_schedule_redirect(r) == NGX_OK)
    {
        return ngx_http_server_redirect_handler(r);
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_server_redirect_handle_server_redirect(ngx_http_request_t *r,
    ngx_http_server_redirect_conf_t *srcf)
{
    ngx_http_server_redirect_rule_t  *rules;
    ngx_str_t                         server;
    ngx_uint_t                        i;
    ngx_http_server_redirect_ctx_t   *ctx;
#if !(NGX_CONDITION)
    ngx_str_t                         val;
#endif
    ngx_int_t                         rc;

    if (srcf->rules == NULL || srcf->rules->nelts == 0) {
        return NGX_DECLINED;
    }

    rules = srcf->rules->elts;

    server.len = 0;
    server.data = NULL;
    for (i = 0; i < srcf->rules->nelts; i++) {
#if (NGX_CONDITION)
        if (ngx_http_condition_get_expr_result(r, rules[i].expr_id)
            != NGX_CONDITION_EXPR_HIT)
        {
            continue;
        }
#else
        if (rules[i].filter) {
            if (ngx_http_complex_value(r, rules[i].filter, &val) != NGX_OK) {
                return NGX_ERROR;
            }

            if (val.len == 0 || (val.len == 1 && val.data[0] == '0')) {
                if (!rules[i].negative) {
                    continue;
                }

            } else {
                if (rules[i].negative) {
                    continue;
                }
            }
        }
#endif

        if (ngx_http_complex_value(r, rules[i].server, &server) != NGX_OK) {
            return NGX_ERROR;
        }

        if (server.len == 0) {
            continue;
        }

        break;
    }

    if (server.len == 0) {
        return NGX_DECLINED;
    }

#if nginx_version >= 1029004

    if (ngx_http_validate_host(&server, NULL, r->pool, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "server redirect: ignore server redirect "
                      "due to validate host failure");
        return NGX_DECLINED;
    }

#else

    if (ngx_http_validate_host(&server, r->pool, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "server redirect: ignore server redirect "
                      "due to validate host failure");
        return NGX_DECLINED;
    }

#endif

    ctx = ngx_http_get_module_ctx(r, ngx_http_server_redirect_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_server_redirect_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_server_redirect_module);
    }

    if (ctx->redirect_count > 3) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "server redirect: too many redirects");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_DONE;
    }

    rc = ngx_http_server_redirect_set_virtual_server(r, &server);
    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "server redirect: failed to redirect server");
        return NGX_ERROR;
    }

    if (rc == NGX_DECLINED) {
        return NGX_DECLINED;
    }

    ctx->redirect_count++;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "server redirect: redirect to new server with host %V",
                  &server);

    return NGX_OK;
}


static ngx_int_t
ngx_http_server_redirect_handle_schedule_redirect(ngx_http_request_t *r)
{
    ngx_http_server_redirect_ctx_t   *ctx;
    size_t                            host_len;
    ngx_str_t                         new_host, new_uri, new_unparsed_uri;
    u_char                           *p;
    ngx_int_t                         rc;

    if (r->uri.len <= 2) {
        return NGX_DECLINED;
    }

    p = (u_char *) ngx_strchr(r->uri.data + 1, '/');

    if (p == NULL) {
        return NGX_DECLINED;
    }

    host_len = p - (r->uri.data + 1);
    if (host_len == 0) {
        return NGX_DECLINED;
    }

    new_host.len = host_len;
    new_host.data = r->uri.data + 1;

#if nginx_version >= 1029004

    if (ngx_http_validate_host(&new_host, NULL, r->pool, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "schedule redirect: invalid host %V", &new_host);
        return NGX_DECLINED;
    }

#else

    if (ngx_http_validate_host(&new_host, r->pool, 0) != NGX_OK) {

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "schedule redirect: invalid host %V", &new_host);
        return NGX_DECLINED;
    }

#endif

    ctx = ngx_http_get_module_ctx(r, ngx_http_server_redirect_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_server_redirect_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_server_redirect_module);
    }

    if (ctx->redirect_count > 3) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "schedule redirect: too many redirects");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_DONE;
    }

    rc = ngx_http_server_redirect_set_virtual_server(r, &new_host);
    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "schedule redirect: failed to redirect server");
        return NGX_ERROR;
    }

    if (rc == NGX_DECLINED) {
        return NGX_DECLINED;
    }

    ctx->redirect_count++;

    new_uri.len = r->uri.len - 1 - host_len;
    new_uri.data = p;

    r->uri = new_uri;

    /* perform the same processing again for r->unparsed_uri */

    p = (u_char *) ngx_strchr(r->unparsed_uri.data + 1, '/');

    if (p == NULL) {
        return NGX_DECLINED;
    }

    host_len = p - (r->unparsed_uri.data + 1);

    if (host_len == 0) {
        return NGX_DECLINED;
    }

    new_unparsed_uri.len = r->unparsed_uri.len - 1 - host_len;
    new_unparsed_uri.data = p;

    r->unparsed_uri = new_unparsed_uri;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "schedule redirect: redirect to new server with "
                  "host %V and uri %V", &new_host, &new_uri);

    return NGX_OK;
}


static ngx_int_t
ngx_http_server_redirect_set_virtual_server(ngx_http_request_t *r,
    ngx_str_t *host)
{
    ngx_int_t                   rc;
    ngx_http_connection_t      *hc;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_core_srv_conf_t   *cscf;
    ngx_http_variable_value_t  *vv;

#if nginx_version >= 1029004
    ngx_uint_t                  port;
#endif

#if (NGX_SUPPRESS_WARN)
    cscf = NULL;
#endif

    hc = r->http_connection;

    /* skip redirect if target host is the same as current host */
    if (r->headers_in.server.len == host->len
        && ngx_strncasecmp(r->headers_in.server.data,
                           host->data, host->len) == 0)
    {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "server redirect: skip redirect to same host %V", host);
        return NGX_DECLINED;
    }

    rc = ngx_http_server_redirect_find_virtual_server(r->connection,
                                                  hc->addr_conf->virtual_names,
                                                  host, r, &cscf);

    if (rc == NGX_ERROR) {
        ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    if (rc == NGX_DECLINED) {
        cscf = hc->addr_conf->default_server;
    }

    r->srv_conf = cscf->ctx->srv_conf;
    r->loc_conf = cscf->ctx->loc_conf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_set_connection_log(r->connection, clcf->error_log);

    vv = ngx_http_get_indexed_variable(r,
                                 ngx_http_server_redirect_original_host_index);

    if (vv) {
        vv->len = r->headers_in.server.len;
        vv->data = r->headers_in.server.data;
        vv->valid = 1;
        vv->no_cacheable = 0;
        vv->not_found = 0;
    }

    if (r->headers_in.server.len) {
        r->headers_in.server = *host;
    }

    if (r->headers_in.host) {
        r->headers_in.host->value = *host;
    }

#if nginx_version >= 1029004

    vv = ngx_http_get_indexed_variable(r,
                                 ngx_http_server_redirect_original_port_index);
    if (vv) {
        vv->len = 0;
        vv->valid = 1;
        vv->no_cacheable = 0;
        vv->not_found = 0;

        vv->data = ngx_pnalloc(r->pool, sizeof("65535") - 1);
        if (vv->data == NULL) {
            return NGX_ERROR;
        }

        port = r->port;

        if (port > 0 && port < 65536) {
            vv->len = ngx_sprintf(vv->data, "%ui", port) - vv->data;
        }
    }

    r->port = ngx_inet_get_port(r->connection->local_sockaddr);

#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_server_redirect_find_virtual_server(ngx_connection_t *c,
    ngx_http_virtual_names_t *virtual_names, ngx_str_t *host,
    ngx_http_request_t *r, ngx_http_core_srv_conf_t **cscfp)
{
    ngx_http_core_srv_conf_t  *cscf;

#if (NGX_PCRE)
    ngx_int_t                  n;
    ngx_uint_t                 i;
    ngx_http_server_name_t    *sn;
#endif

    if (virtual_names == NULL) {
        return NGX_DECLINED;
    }

    cscf = ngx_hash_find_combined(&virtual_names->names,
                                  ngx_hash_key(host->data, host->len),
                                  host->data, host->len);

    if (cscf) {
        *cscfp = cscf;
        return NGX_OK;
    }

#if (NGX_PCRE)

    if (host->len && virtual_names->nregex) {
        sn = virtual_names->regex;

        for (i = 0; i < virtual_names->nregex; i++) {

            n = ngx_http_regex_exec(r, sn[i].regex, host);

            if (n == NGX_DECLINED) {
                continue;
            }

            if (n == NGX_OK) {
                *cscfp = sn[i].server;
                return NGX_OK;
            }

            return NGX_ERROR;
        }
    }

#endif /* NGX_PCRE */

    return NGX_DECLINED;
}
