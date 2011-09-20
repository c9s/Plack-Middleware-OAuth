package Plack::Middleware::OAuth::Handler;
use parent qw(Plack::Middleware::OAuth::GenericHandler);
use warnings;
use strict;
use Plack::Util::Accessor qw(config provider on_success on_error);

=head1 NAME

Plack::Middleware::OAuth::Handler - OAuth Handler

=head1 ACCESSORS

=head2 provider

Provider id.

=head2 config

Provider configuration hash reference.

=head2 on_success

On success handler.

=head2 on_error

On error handler.

=head1 METHODS

=head2 default_callback

return default callback URL.

=cut

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

