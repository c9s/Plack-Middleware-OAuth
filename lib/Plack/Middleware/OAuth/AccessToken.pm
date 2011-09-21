package Plack::Middleware::OAuth::AccessToken;
use warnings;
use strict;
use Plack::Session;
use Plack::Util::Accessor qw(params provider version);
use overload 
    '""' => sub { 
        my $self = shift;
        return $self->access_token;
    };

sub new {
    my ($class,%args) = @_;
    return bless \%args , $class;
}

sub has_error {
    my $self = shift;
    return $self->{params}->{error};
}

sub extra_params { 
    return $self->{params}->{extra_params};
}

sub access_token {
    my $self = shift;
    return $self->{params}->{access_token};
}

sub hashref {
    my $self = shift;
    return \%$self;
}

sub register_session {
    my ($self,$env) = @_;
    my $session = Plack::Session->new( $env );
    my $provider_id = lc($self->provider);
    if( $self->version == 2 ) {
        $session->set( 'oauth2.' . $provider_id  . '.access_token' , $self->{params}->{access_token} );
        $session->set( 'oauth2.' . $provider_id  . '.code'         , $self->{params}->{code} );
        $session->set( 'oauth2.' . $provider_id  . '.token_type'         , $self->{params}->{token_type} );
        $session->set( 'oauth2.' . $provider_id  . '.refresh_token'         , $self->{params}->{refresh_token} );
    } 
    elsif( $self->version == 1 ) {
        $session->set( 'oauth.' . $provider_id . '.access_token' , $self->{params}->{access_token} );
        $session->set( 'oauth.' . $provider_id . '.access_token_secret' , $self->{params}->{access_token_secret} );
    }
}

1;
