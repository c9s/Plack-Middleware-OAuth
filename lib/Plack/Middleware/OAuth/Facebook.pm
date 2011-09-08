package Plack::Middleware::OAuth::Facebook;
use warnings;
use strict;

sub config { +{
	version          => 2,
	authorize_url    => 'https://www.facebook.com/dialog/oauth',
	access_token_url => 'https://graph.facebook.com/oauth/access_token',
	scope            => 'email',
} }

1;
