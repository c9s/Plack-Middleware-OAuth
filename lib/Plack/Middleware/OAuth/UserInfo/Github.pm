package Plack::Middleware::OAuth::UserInfo::Github;
use warnings;
use strict;
use parent qw(Plack::Middleware::OAuth::UserInfo);
use Net::GitHub;

sub create_handle {
    my $self = shift;
    return Net::GitHub->new( access_token => $self->token->access_token );
}

sub query {
    my $self = shift;
    my $gh = $self->create_handle;
    return $gh->user->show();
}

1;
