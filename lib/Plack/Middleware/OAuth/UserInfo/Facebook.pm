package Plack::Middleware::OAuth::UserInfo::Facebook;
use warnings;
use strict;
use parent qw(Plack::Middleware::OAuth::UserInfo);
use LWP::UserAgent;
use JSON;

sub query {
    my $self = shift;
    # my $gh = $self->create_handle;

    my $ua = LWP::UserAgent->new;
    my $uri = URI->new( 'https://graph.facebook.com/me' );
    $uri->query_form( access_token => $self->token->access_token );
    my $response = $ua->get( $uri );
    my $body = $response->decoded_content;
    return unless $body;
    return decode_json( $body ) || { };
}

1;
