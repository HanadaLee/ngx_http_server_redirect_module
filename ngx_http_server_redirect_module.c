
/*
 * Copyright (C) Hanada
 */


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
    ngx_flag_t                 schedule_redirect;
} ngx_http_server_redirect_conf_t;


typedef struct {
    ngx_uint_t                 redirect_count;
} ngx_http_server_redirect_ctx_t;


static ngx_int_t ngx_http_server_redirect_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_server_redirect_original_host_variable(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static void * ngx_http_server_redirect_create_conf(ngx_conf_t *cf);
static char * ngx_http_server_redirect(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
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


static ngx_int_t  ngx_http_server_redirect_original_host_index
                    = NGX_CONF_UNSET;
static ngx_str_t  ngx_http_server_redirect_original_host
                    = ngx_string("server_redirect_original_host");


static ngx_command_t  ngx_http_server_redirect_commands[] = {

    { ngx_string("server_redirect"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE12,
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
    ngx_http_variable_t *var;

    var = ngx_http_add_variable(cf, &ngx_http_server_redirect_original_host,
                              NGX_HTTP_VAR_CHANGEABLE);

    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_server_redirect_original_host_variable;
    var->data = 0;

    ngx_http_server_redirect_original_host_index = var->index;

    return NGX_OK;
}


static ngx_int_t
ngx_http_server_redirect_original_host_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "server redirect original host variable");

    v->not_found = 1;

    return NGX_OK;
}


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
    ngx_str_t                        *server = NULL;
    ngx_uint_t                        i;
    ngx_http_server_redirect_ctx_t   *ctx;

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
                      "server redirect: ignore server redirect "
                      "due to validate host failure");
        return NGX_DECLINED;
    }

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

    if (ngx_http_server_redirect_set_virtual_server(r, server) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "server redirect: failed to redirect server");
        return NGX_ERROR;
    }

    ctx->redirect_count++;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "server redirect: redirect to new server with host %V", server);

    return NGX_OK;
}


static ngx_int_t
ngx_http_server_redirect_handle_schedule_redirect(ngx_http_request_t *r)
{
    ngx_http_server_redirect_ctx_t   *ctx;
    size_t                            host_len;
    ngx_str_t                         new_host, new_uri, new_unparsed_uri;
    u_char                           *p;

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

    if (ngx_http_validate_host(&new_host, r->pool, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "schedule redirect: invalid host %V", &new_host);
        return NGX_DECLINED;
    }

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

    if (ngx_http_server_redirect_set_virtual_server(r, &new_host) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "schedule redirect: failed to redirect server");
        return NGX_ERROR;
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
    ngx_int_t                  rc;
    ngx_http_connection_t     *hc;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;
    ngx_http_variable_value_t *vv;

#if (NGX_SUPPRESS_WARN)
    cscf = NULL;
#endif

    hc = r->http_connection;

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

    return NGX_OK;
}


static ngx_int_t
ngx_http_server_redirect_find_virtual_server(ngx_connection_t *c,
    ngx_http_virtual_names_t *virtual_names, ngx_str_t *host,
    ngx_http_request_t *r, ngx_http_core_srv_conf_t **cscfp)
{
    ngx_http_core_srv_conf_t  *cscf;

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
        ngx_int_t                n;
        ngx_uint_t               i;
        ngx_http_server_name_t  *sn;

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