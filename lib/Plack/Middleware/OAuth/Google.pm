package Plack::Middleware::OAuth::Google;
use warnings;
use strict;

sub config { +{
	version   => 2,
	authorize_url    => 'https://accounts.google.com/o/oauth2/auth',
	access_token_url => 'https://accounts.google.com/o/oauth2/token',
	response_type    => 'code',
	grant_type       => 'authorization_code',
	request_method   => 'POST',
} }

1;
