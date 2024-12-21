# ngx_http_server_redirect_module

## Table of Contents

- [ngx\_http\_server\_redirect\_module](#ngx_http_server_redirect_module)
  - [Table of Contents](#table-of-contents)
  - [Description](#description)
  - [Status](#status)
  - [Installation](#installation)
  - [Synopsis](#synopsis)
    - [Basic Redirection](#basic-redirection)
    - [Conditional Redirection](#conditional-redirection)
  - [Configuration](#configuration)
    - [Directive: `server_redirect`](#directive-server_redirect)
    - [Variable: `$server_redirect_original_host`](#variable-server_redirect_original_host)
  - [Author](#author)
  - [License](#license)

---

## Description

The `ngx_http_server_redirect_module` is a custom nginx module designed to facilitate dynamic server redirection based on configurable rules. It allows users to redirect incoming requests to different servers conditionally.

## Status
This Nginx module is currently considered experimental. Issues and PRs are welcome if you encounter any problems.

## Installation

To use theses modules, configure your nginx branch with --add-module=/path/to/ngx_http_access_control_module.

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

        # Redirect if request has 'X-Redirect' header and value is not 0 or empty.
        server_redirect newserver.com if=$http_x_redirect;

        # You can use ngx_http_var_module to generate judgment variables based on conditions.
        # https://git.hanada.info/hanada/ngx_http_var_module
        # var $is_ipv6 if_find $remote_addr :;
        # server_redirect newserver.com if=$is_ipv6;

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

        # Only the server rewrite phase and subsequent instructions will take effect in the new server.
        add_header x-original-host $server_redirect_original_host;

        location / {
            proxy_pass http://upstream.com;
        }
    }
}
```

## Configuration

### Directive: `server_redirect`

**Syntax:** *server_redirect target_host [if=condition]*

**Default:** *-*

**Context:** *server*

Redirect the current request to another server. The target server must have the same listening port as the current server. 

The target host should be a specific host name just like the host in the request header. Even if the target server you want to redirect to is a wildcard domain name or a regular expression.

If the target server cannot be found, it will jump to the default server.

The if parameter enables conditional redirection. A request will not be redirected if the condition evaluates to “0” or an empty string. In addition, you can also use the form of `if!=` to make negative judgments.

Here is an example:

```nginx
server_redirect newserver.com if=$http_server_redirect;
```

This example redirects requests to `newserver.com` if the `Server-Redirect` header has value and value is not 0.

### Variable: `$server_redirect_original_host`

Keeps the original value of variable $host before redirection occurs.

## Author

Hanada im@hanada.info

## License

This Nginx module is licensed under [BSD 2-Clause License](LICENSE).
