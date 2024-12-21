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
} ngx_http_server_redirect_conf_t;


typedef struct {
    ngx_str_t                  original_host;
    ngx_str_t                  redirect_count;
} ngx_http_server_redirect_ctx_t;


static ngx_int_t ngx_http_server_redirect_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_server_redirect_original_host_variable(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static void * ngx_http_server_redirect_create_conf(ngx_conf_t *cf);
static char * ngx_http_server_redirect(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_server_redirect_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_server_redirect_set_virtual_server(
    ngx_http_request_t *r, ngx_str_t *host);
static ngx_int_t ngx_http_server_redirect_find_virtual_server(
    ngx_connection_t *c, ngx_http_virtual_names_t *virtual_names,
    ngx_str_t *host, ngx_http_request_t *r, ngx_http_core_srv_conf_t **cscfp);
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
    ngx_http_server_redirect_add_variables, /* preconfiguration */
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


static ngx_http_variable_t  ngx_http_server_redirect_vars[] = {

    { ngx_string("server_redirect_original_host"), NULL,
      ngx_http_server_redirect_original_host_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    ngx_http_null_variable
};


static ngx_int_t
ngx_http_server_redirect_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_server_redirect_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_server_redirect_original_host_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_server_redirect_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_server_redirect_module);
    if (ctx == NULL || ctx->original_host.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ctx->original_host.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->original_host.data;

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
    ngx_http_server_redirect_ctx_t   *ctx;

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

    ctx = ngx_http_get_module_ctx(r, ngx_http_server_redirect_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_server_redirect_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_server_redirect_module);
    }

    if (ctx->redirect_count >= 3) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "server redirect: too many redirects");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_validate_host(server, r->pool, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "server redirect: ignore server redirect "
                      "due to validate host failure");
        return NGX_DECLINED;
    }

    if (ngx_http_server_redirect_set_virtual_server(r, server) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "server redirect: failed to redirect server");
        return NGX_ERROR;
    }

    ctx->original_server = r->headers_in.server;
    ctx->redirect_count++;

    if (r->headers_in.server.len) {
        r->headers_in.server = *server;
    }

    if (r->headers_in.host) {
        r->headers_in.host->value = *server;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "server redirect: redirect to new server with host %V", server);

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_server_redirect_set_virtual_server(ngx_http_request_t *r,
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