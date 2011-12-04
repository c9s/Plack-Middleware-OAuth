package Plack::Middleware::OAuth::Live;

use warnings;
use strict;

sub config { +{
	version   => 2,
	authorize_url    => 'https://oauth.live.com/authorize',
	access_token_url => 'https://oauth.live.com/token',
	response_type    => 'code',
	grant_type       => 'authorization_code',
	request_method   => 'POST',
} }

1;