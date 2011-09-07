package Plack::Middleware::OAuth::Twitter;
use warnings;
use strict;

sub config { {
	version => 1,  # oauth 1.0a
	request_token_url => 'https://api.twitter.com/oauth/request_token',
	access_token_url  => 'https://api.twitter.com/oauth/access_token',
	authorize_url     => 'http://api.twitter.com/oauth/authorize',
	request_method   => 'POST',
} }

1;
