#!/usr/bin/env perl
use Test::More skip_all => 'not ready yet';
use Plack::Test;
use Plack::Middleware::OAuth;
use Plack::Middleware::Session;
use Plack::Builder;

BEGIN { 
    use_ok( 'Plack::Middleware::OAuth::GenericHandler' );
    use_ok( 'Plack::Middleware::OAuth::Handler' );
};


# $Plack::Test::Impl = "MockHTTP";

test_psgi
    app => builder { 
        enable 'Session';
        sub {  
            my $env = shift;
            my $req = Plack::Middleware::OAuth::Handler::AccessTokenV2->new( $env );
            ok( $req );
            $req->on_success( sub { 
                
            });
            $req->on_error( sub { 
                
                
            });
            return $req->run();
        };
    },
    client => sub {
        my $cb = shift;
        my $req = HTTP::Request->new(GET => "http://localhost/hello");
        my $res = $cb->($req);
        # warn $res->content;
        like $res->content, qr/Hello World/,  'got Hello World';
    };

done_testing;
