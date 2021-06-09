package Plack::Middleware::OAuth::Handler::RequestTokenV2;
use warnings;
use strict;
use parent qw(Plack::Middleware::OAuth::Handler);

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

sub run {
    my $self = shift;
    my $config = $self->config;

	# "https://www.facebook.com/dialog/oauth?client_id=YOUR_APP_ID&redirect_uri=YOUR_URL";
	my $uri = URI->new( $config->{authorize_url} );
    my %query = (
		client_id     => $config->{client_id},
		redirect_uri  => $config->{redirect_uri}  || $self->default_callback,
		response_type => $config->{response_type} || 'code',
		scope         => $config->{scope},
		state         => $config->{state},
    );
	$uri->query_form( %query );
	return $self->redirect( $uri );
}

1;
