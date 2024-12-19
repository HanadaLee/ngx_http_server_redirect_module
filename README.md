ngx_http_server_redirect_module
=============

Nginx module which redirect server name in one request


## Directives

Syntax: **server_redirect**

Default: `none`

Context: `location, if location`

Description: `If it is set 'server_redirect', request will be redirect to new_server_name in conf. If new_server_name is not found, it will be processed in default server name.`


###Example
http {
	server {
		listen       80;
		server_name  localhost;
		location / {
			server_redirect new;
		}
	}
	
	server {
		listen       80;
		server_name  new;
		location / {
			#do anything ...
		}
	}
}
