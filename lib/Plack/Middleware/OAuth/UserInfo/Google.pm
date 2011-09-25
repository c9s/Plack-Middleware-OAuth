package Plack::Middleware::OAuth::UserInfo::Google;
use warnings;
use strict;
use parent qw(Plack::Middleware::OAuth::UserInfo);
use LWP::UserAgent;
use URI;
use JSON::Any;

sub query {
    my $self = shift;
    my $ua = LWP::UserAgent->new;
    my $uri = URI->new( 'https://www.google.com/m8/feeds/contacts/default/full' );
    $uri->query_form( 
        'access_token' => $token->access_token ,
        'max-results' => 0,
        'alt'=> 'json',
    );
    my $res = $ua->get($uri);
    return JSON::Any->new->decode($res->decoded_content) if $res->is_success;
}

1;
