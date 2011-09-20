#!/usr/bin/env perl
use lib 'lib';
use Plack::Test;
use Test::More;
use Plack::Middleware::OAuth;
use Plack::Builder;

# $Plack::Test::Impl = "MockHTTP";

test_psgi
    app => Plack::Util::load_psgi( 't/basic.psgi' ) ,
    client => sub {
        my $cb = shift;
        my $req = HTTP::Request->new(GET => "http://localhost/hello");
        my $res = $cb->($req);
        like $res->content, qr/Hello World/,  'got Hello World';
    };

done_testing;
