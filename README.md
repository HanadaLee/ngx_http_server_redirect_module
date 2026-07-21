# ngx_http_server_redirect_module

## Table of Contents

- [ngx\_http\_server\_redirect\_module](#ngx_http_server_redirect_module)
  - [Table of Contents](#table-of-contents)
  - [Description](#description)
  - [Status](#status)
  - [Installation](#installation)
  - [Conditional Syntax](#conditional-syntax)
  - [Synopsis](#synopsis)
    - [Basic Redirection](#basic-redirection)
    - [Conditional Redirection](#conditional-redirection)
    - [Schedule Redirection](#schedule-redirection)
  - [Configuration](#configuration)
    - [Directive: `server_redirect`](#directive-server_redirect)
    - [Directive: `schedule_redirect`](#directive-schedule_redirect)
    - [Variable: `$server_redirect_original_host`](#variable-server_redirect_original_host)
  - [Author](#author)
  - [License](#license)

---

## Description

The `ngx_http_server_redirect_module` is a custom nginx module designed to facilitate dynamic server redirection based on configurable rules. It allows users to redirect incoming requests to different servers conditionally.

## Status
This Nginx module is currently considered experimental. Issues and PRs are welcome if you encounter any problems.

## Installation

To use theses modules, configure your nginx branch with --add-module=/path/to/ngx_http_server_redirect_module.

To enable named conditions, build `ngx_condition_module` and this module statically in the same nginx configuration.

## Conditional Syntax

Conditional syntax is selected at compile time:

- With `ngx_condition_module`, use named `condition` expressions and place `server_redirect` inside a server-level `when` block. `if=` and `if!=` parameters are rejected.
- Without `ngx_condition_module`, `when` is unavailable and legacy `if=`/`if!=` parameters remain supported. `if=` matches a non-empty value other than `"0"`; `if!=` matches an empty value or `"0"`.

If a condition does not match, that redirect rule is skipped and the next rule can be evaluated.

## Synopsis

### Basic Redirection
Redirect all requests to `newserver.com` unconditionally.

```nginx
http {
    server {
        listen 80;
        server_name example.com;

        server_redirect newserver.com;

        location / {
            proxy_pass http://newserver.com;
        }
    }

    server {
        listen 80;
        server_name newserver.com;

        # You can get original host from this variable.
        add_header x-original-host $server_redirect_original_host;

        location / {
            proxy_pass http://upstream.com;
        }
    }
}
```

### Conditional Redirection

Redirect requests based on the presence of a specific header.

```nginx
http {
    server {
        listen 80;
        server_name example.com;

        # With ngx_condition_module.
        condition redirect_enabled is_not_empty $http_x_redirect;
        when redirect_enabled {
            server_redirect newserver.com;
        }

        # Without ngx_condition_module, use this instead:
        # server_redirect newserver.com if=$http_x_redirect;

        # This module takes effect after the real_ip module,
        # Therefore, the real_ip module's directives will take effect on the server before server redirect.
        # real_ip_header x-client-ip;

        location / {
            proxy_pass http://newserver.com;
        }
    }

    server {
        listen 80;
        server_name newserver.com;

        # You can get original host from this variable.
        add_header x-original-host $server_redirect_original_host;

        location / {
            proxy_pass http://upstream.com;
        }
    }
}
```

### Schedule Redirection

Redirect the current request to another server from the first request path.
If request `http://example.com/newserver.com/test?arg=1`, it will be redirect to `http:///newserver.com/test?arg=1`. This process is internal and no 302 redirection will occur.
```nginx
http {
    server {
        listen 80;
        server_name example.com;

        # Enable schedule redirection.
        schedule_redirect on;

        # Requests will not arrive here unless the first path in the request path does not exist or the host in the first path is invalid.
        return 400 "request path invalid";
    }

    server {
        listen 80;
        server_name newserver.com;

        # You can get original host from this variable.
        add_header x-original-host $server_redirect_original_host;

        location / {
            proxy_pass http://upstream.com;
        }
    }
}
```


## Configuration

### Directive: `server_redirect`

**Syntax:** *server_redirect target_host;*

**Default:** *-*

**Context:** *server, server when*

Redirect the current request to another server. The target server must have the same listening port as the current server. 

The `target_host` value should be a specific host name just like the host in the request header. Even if the target server you want to redirect to is a wildcard domain or a regular expression. The `target_host` value can contain variables. If `target_host` value is empty, it will be skipped.

If the target server cannot be found, the request will be redirected to the default server.

The legacy `if=` and `if!=` parameters are available only when `ngx_condition_module` is not built.

Here is an example:

```nginx
condition redirect_enabled is_not_empty $http_server_redirect;
when redirect_enabled {
    server_redirect newserver.com;
}
```

This example redirects requests to `newserver.com` if the `Server-Redirect` header has value and value is not 0.

### Directive: `schedule_redirect`

**Syntax:** *schedule_redirect on | off*

**Default:** *schedule_redirect off*

**Context:** *server*

Redirect the current request to another server from the first request path.

If enabled, when accessing http://a.com/b.com/, the request will be redirected to http://b.com/. If the target server cannot be found, it will be redirected to the default server.

When server_redirect directive exists and meets the redirection conditions, server_redirect will be executed first.

If the request path does not have the first path (such as the home page), no redirection will be made.

After redirection, even $request_uri will be cleared of the first path. You can only find the original request path in the request line variable $request.

### Variable: `$server_redirect_original_host`

Keeps the original value of variable $host before redirection occurs.

## Author

Hanada im@hanada.info

## License

This Nginx module is licensed under [BSD 2-Clause License](LICENSE).
