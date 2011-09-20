package Plack::Middleware::OAuth::Twitter;
use warnings;
use strict;

sub config { {
	version => 1,  # oauth 1.0a
	request_token_url => 'https://api.twitter.com/oauth/request_token',
	request_token_method => 'POST',

	access_token_url  => 'https://api.twitter.com/oauth/access_token',
	access_token_method => 'POST',

	authorize_url     => 'https://api.twitter.com/oauth/authenticate',
} }

1;
