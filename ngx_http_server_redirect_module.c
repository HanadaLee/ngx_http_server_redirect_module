#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_str_t   new_server;
} ngx_http_server_redirect_conf_t;


static void * ngx_http_server_redirect_create_conf(ngx_conf_t *cf);
static char * ngx_http_server_redirect(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_server_redirect_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_server_redirect_post_config(ngx_conf_t *cf);


static ngx_command_t  ngx_http_server_redirect_commands[] = {

    { ngx_string("server_redirect"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
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


// Configuration directive handler: sets the new server name
static char *
ngx_http_server_redirect(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value;
    ngx_http_server_redirect_conf_t *srcf = conf;

    args = cf->args->elts;
    srcf->new_server = value[1];
    
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

    /*
     * set by ngx_pcalloc():
     *
     *     conf->new_server = { 0, NULL };
     */

    return conf;
}


static ngx_int_t
ngx_http_server_redirect_post_config(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_handler_pt        *h;

    // Retrieve the core module's main configuration
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    // Add the handler to the POST_READ phase
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_server_redirect_handler;

    return NGX_OK;
}


// Callback function to handle the request
static ngx_int_t
ngx_http_server_redirect_handler(ngx_http_request_t *r)
{
    ngx_str_t    *server;

    ngx_http_server_redirect_conf_t *srcf;

    srcf = ngx_http_get_module_srv_conf(r, ngx_http_server_redirect_module);
    server = &srcf->new_server;

    if (server->data == NULL || server->len == 0) {
        return NGX_DECLINED;
    }

    if (ngx_http_set_virtual_server(r, server) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "failed to redirect to new virtual server");
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "Virtual server set to %V", server);

    return NGX_DECLINED;
}