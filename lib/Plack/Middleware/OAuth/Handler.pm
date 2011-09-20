package Plack::Middleware::OAuth::Handler;
use parent qw(Plack::Middleware::OAuth::GenericHandler);
use warnings;
use strict;
use Plack::Util::Accessor qw(config provider on_success on_error);


sub default_callback {
    my $self = shift;
    my $provider = $self->provider;
    my $env = $self->env;
    # 'REQUEST_URI' => '/oauth/twitter',
    # 'SCRIPT_NAME' => '/oauth',
    # 'PATH_INFO' => '/twitter',
    return URI->new( $env->{'psgi.url_scheme'} . '://' . 
        $env->{HTTP_HOST} . $env->{SCRIPT_NAME} . '/' . lc($provider) . '/callback' );
}

1;

