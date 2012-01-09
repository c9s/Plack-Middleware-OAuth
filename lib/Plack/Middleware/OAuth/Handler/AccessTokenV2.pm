package Plack::Middleware::OAuth::Handler::AccessTokenV2;
use parent qw(Plack::Middleware::OAuth::Handler);
use URI;
use URI::Query;
use LWP::UserAgent;
use Plack::Middleware::OAuth::AccessToken;
use Try::Tiny;
use JSON::Any;
use warnings;
use strict;

sub build_args {
    my ($self,$code) = @_;
    my $config = $self->config;
	my %args = (
		client_id     => $config->{client_id},
		client_secret => $config->{client_secret},
		redirect_uri  => $config->{redirect_uri} || $self->default_callback,
		scope         => $config->{scope},
		grant_type    => $config->{grant_type},
		code          => $code,
	);
    return %args;
}

sub get_access_token {
    my ($self,$code,%args) = @_;
    my $config = $self->config;
    my $provider = $self->provider;
	my $uri = URI->new( $config->{access_token_url} );
    my $ua = LWP::UserAgent->new;
	my $ua_response;

	my $method = $config->{request_method} || 'GET';
	if( $method eq 'GET' ) {
		$uri->query_form( %args );
		$ua_response = $ua->get( $uri );
	} 
	elsif( $method eq 'POST' ) {
		$ua_response = $ua->post( $uri , \%args );
	}

    # process response content...
	my $response_content = $ua_response->content;

    # warn $response_content;

	my $content_type     = $ua_response->header('Content-Type');
    my %params;

    # we are pretty sure, the response is json format
	if(    $content_type =~ m{json} 
        || $content_type =~ m{javascript} 
        || $response_content =~ m{^\{.*?\}\s*$}s ) 
    {
        try {
            %params = %{ JSON::Any->new->decode( $response_content ) }; # should be hashref.
        } catch {
            # XXX: show exception page for this.
            die "Can not decode json: " . $_;
        };
	} 
    else {
        try {
            my $qq = URI::Query->new( $ua_response->content );
            %params = $qq->hash;
        } catch {
            # XXX: show exception page for this.
            die "Can not decode params: " . $_;
        }
	}

    return Plack::Middleware::OAuth::AccessToken->new(
        version      => $config->{version},  # oauth version
        provider     => $provider,
        params       => {
            %params,
            code => $code,
        }
    );
}

sub run {
    my $self = $_[0];
	my $code = $self->param('code');

	# https://graph.facebook.com/oauth/access_token?
	# 	  client_id=YOUR_APP_ID&redirect_uri=YOUR_URL&
	# 	  client_secret=YOUR_APP_SECRET&code=THE_CODE_FROM_ABOVE
	my %args = $self->build_args($code); 
	my $token = $self->get_access_token( $code , %args );

    if ( $ENV{DEBUG} } {
        use Data::Dumper;
        warn 'Got token';
        warn Dumper( $token );
    }

    $self->on_error->( $self, $token ) 
        if $token->has_error && $self->on_error;

	unless( $token ) {
        return $self->on_error->( $self ) if $self->on_error;
        return $self->render( 'OAuth failed.' );
    }

	# register oauth args to session
    my $env = $self->env;
    my $provider = $self->provider;

    $token->register_session($env);

	my $res;
	$res = $self->on_success->( $self, $token ) if $self->on_success;
	return $res if $res;

	# for testing
	return $self->to_yaml( $token );
}

1;
