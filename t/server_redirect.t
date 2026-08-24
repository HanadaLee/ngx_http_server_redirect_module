#!/usr/bin/perl

# Tests for ngx_http_server_redirect_module.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http rewrite ngx_condition_module
	ngx_http_server_redirect_module/)->plan(11);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080 default_server;
        server_name  default.local;
        return 200 "default:$host:$server_redirect_original_host";
    }

    server {
        listen       127.0.0.1:8080;
        server_name  source.local;

        condition blue str_eq $http_x_target blue;
        condition green str_eq $http_x_target green;

        when blue {
            server_redirect blue.local;
        }
        when green {
            server_redirect green.local;
        }
        server_redirect fallback.local;

        return 200 source;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  dynamic.local;

        server_redirect $http_x_destination;
        return 200 dynamic;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  schedule.local;

        schedule_redirect on;
        return 200 schedule;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  same.local;

        server_redirect same.local;
        return 200 same;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  blue.local;
        return 200 "blue:$host:$server_redirect_original_host:$server_redirect_original_port:$request_uri";
    }

    server {
        listen       127.0.0.1:8080;
        server_name  green.local;
        return 200 "green:$host:$server_redirect_original_host";
    }

    server {
        listen       127.0.0.1:8080;
        server_name  fallback.local;
        return 200 "fallback:$host:$server_redirect_original_host";
    }
}

EOF

$t->run();

###############################################################################

sub request {
	my ($host, $uri, %headers) = @_;
	my $request = "GET $uri HTTP/1.0\r\nHost: $host\r\n";

	for my $name (sort keys %headers) {
		$request .= "$name: $headers{$name}\r\n";
	}

	return http($request . "\r\n");
}

sub body_is {
	my ($response, $body, $name) = @_;
	like($response, qr/\x0d\x0a\x0d\x0a\Q$body\E$/, $name);
}

body_is(request('source.local', '/', 'X-Target' => 'blue'),
	'blue:blue.local:source.local::/',
	'first matching conditional rule redirects server');
body_is(request('source.local:8080', '/', 'X-Target' => 'blue'),
	'blue:blue.local:source.local:8080:/',
	'explicit original port is preserved');
body_is(request('source.local', '/', 'X-Target' => 'green'),
	'green:green.local:source.local', 'second conditional rule can match');
body_is(request('source.local', '/'),
	'fallback:fallback.local:source.local',
	'unconditional rule is an ordered fallback');
body_is(request('dynamic.local', '/', 'X-Destination' => 'blue.local'),
	'blue:blue.local:dynamic.local::/',
	'target host supports variables');
body_is(request('dynamic.local', '/'), 'dynamic',
	'empty target skips redirect');
body_is(request('schedule.local', '/blue.local/path?x=1'),
	'blue:blue.local:schedule.local::/path?x=1',
	'schedule redirect changes host and strips first path segment');
body_is(request('schedule.local', '/'), 'schedule',
	'schedule redirect skips root URI');
body_is(request('same.local', '/'), 'same',
	'redirect to current host is skipped');
body_is(request('dynamic.local', '/', 'X-Destination' => 'unknown.local'),
	'default:unknown.local:dynamic.local',
	'unknown target selects default virtual server');
body_is(request('source.local', '/', 'X-Target' => 'other'),
	'fallback:fallback.local:source.local',
	'condition miss reaches fallback');

###############################################################################
