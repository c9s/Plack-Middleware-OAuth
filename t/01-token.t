#!/usr/bin/env perl
use Test::More;
use lib 'lib';
BEGIN {
    use_ok( 'Plack::Middleware::OAuth::AccessToken' );
}


my $token = Plack::Middleware::OAuth::AccessToken->new(
    version      => 1,
    provider     => 'Twitter',
    env          => {  },
    params       => {
        access_token => 'access token',
        code => 'test code',
    });
ok( $token );
ok( $token->params );
ok( $token->version );
ok( $token->provider );

ok( %$token );

is( ''. $token , 'access token' ); # stringfy

done_testing;
