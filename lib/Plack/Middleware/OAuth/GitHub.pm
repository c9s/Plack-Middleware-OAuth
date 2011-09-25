package Plack::Middleware::OAuth::GitHub;
use warnings;
use strict;

sub config { {
	version   => 2,
	authorize_url    => 'https://github.com/login/oauth/authorize',
	access_token_url => 'https://github.com/login/oauth/access_token',
	scope            => 'user,public_repo'
} }

1;
