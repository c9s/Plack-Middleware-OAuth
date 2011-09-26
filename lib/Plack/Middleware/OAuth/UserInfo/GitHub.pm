package Plack::Middleware::OAuth::UserInfo::GitHub;
use warnings;
use strict;
use parent qw(Plack::Middleware::OAuth::UserInfo);
use LWP::UserAgent;
use JSON;
# use Net::GitHub;

sub create_handle {
    my $self = shift;





    # return Net::GitHub->new( access_token => $self->token->access_token );
}

sub query {
    my $self = shift;
    # my $gh = $self->create_handle;

    my $ua = LWP::UserAgent->new;
    my $uri = URI->new( 'http://github.com/api/v2/json/user/show/' );
    $uri->query_form( access_token => $self->token->access_token );

    my $response = $ua->get( $uri );
    my $body = $response->decoded_content;
    return decode_json( $body ) if $body;
    return { };
}

1;
