package Plack::Middleware::OAuth::Handler::AccessTokenV2;
use parent qw(Plack::Middleware::OAuth::Handler);
use URI;
use URI::Query;
use LWP::UserAgent;

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
	my $content_type     = $ua_response->header('Content-Type');
	my $oauth_data;

	if( $content_type =~ m{json} || $content_type =~ m{javascript} ) {
		my $params = decode_json( $response_content );
		$oauth_data = { 
			version      => $config->{version},  # oauth version
			provider     => $provider,
			params       => $params,
			code         => $code
		};
	} else {
		my $qq = URI::Query->new( $ua_response->content );
		my %params = $qq->hash;
		$oauth_data = { 
			version      => $config->{version},  # oauth version
			provider     => $provider,
			params       => \%params,
			code         => $code
		};
	}
    return $oauth_data;
}

sub run {
    my $self = $_[0];
	my $code = $self->param('code');

	# https://graph.facebook.com/oauth/access_token?
	# 	  client_id=YOUR_APP_ID&redirect_uri=YOUR_URL&
	# 	  client_secret=YOUR_APP_SECRET&code=THE_CODE_FROM_ABOVE
	my %args = $self->build_args($code); 
	my $oauth_data = $self->get_access_token( $code , %args );

    if( $oauth_data->{params}->{error} ) 
    {
        # retry ? 
        # return $self->request_token_v2( $env, $provider, $config);
    }

	unless( $oauth_data ) {
        return $self->on_error->( $self ) if $self->on_error;
        return $self->_response( 'OAuth failed.' );
    }


#     my $session = $env->{'psgix.session'};
#     # my $session = Plack::Session->new( $env );
#     $session->set( 'oauth2.' . lc($provider)  . '.access_token' , $oauth_data->{params}->{access_token} );
#     $session->set( 'oauth2.' . lc($provider)  . '.code'         , $oauth_data->{code} );

	my $res;
	$res = $self->on_success->( $self, $oauth_data ) if $self->on_success;
	return $res if $res;

	# for testing
	return $self->to_yaml( $oauth_data );
}

1;
