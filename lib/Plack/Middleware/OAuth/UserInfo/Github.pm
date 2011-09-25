package Plack::Middleware::OAuth::UserInfo::Github;
use warnings;
use strict;
use parent qw(Plack::Middleware::OAuth::UserInfo);
use Net::GitHub;

sub query {
    my $self = shift;
    my $gh = Net::GitHub->new( access_token => $self->token->access_token );
    return $gh->user->show();
}

1;
