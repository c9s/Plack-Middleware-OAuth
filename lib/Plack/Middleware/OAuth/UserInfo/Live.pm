package Plack::Middleware::OAuth::UserInfo::Live;

use warnings;
use strict;
use parent qw(Plack::Middleware::OAuth::UserInfo);
use LWP::UserAgent;
use JSON;

sub query {
    my $self = shift;

    my $ua = LWP::UserAgent->new;
    my $uri = URI->new( 'https://apis.live.net/v5.0/me' );
    $uri->query_form( access_token => $self->token->access_token );
    my $response = $ua->get( $uri );
    my $body = $response->decoded_content;
    return unless $body;
    my $obj = decode_json( $body ) || {};
    return $obj;
}

1;
