package Plack::Middleware::OAuth;
use warnings;
use strict;
use parent qw(Plack::Middleware);
use DateTime;
use Digest::MD5 qw(md5_hex);
use Plack::Util::Accessor qw(providers prefix signin debug);
use Plack::Session;
use Plack::Response;
use URI;
use URI::Query;
use LWP::UserAgent;
use Net::OAuth;
use HTTP::Request::Common;
use DateTime;
use YAML;
use JSON;


our $VERSION = '0.01';



# routes
#    path => { provider => ... , method => .... }
our %routes;


sub prepare_app {
	my $self = shift;

	# setup default api prefix
	$self->prefix('/_oauth') unless $self->prefix;


	my $p = $self->providers;
	for my $provider_name ( keys %$p ) {
		my $config = $p->{$provider_name};

		my $fc = ord(substr( $provider_name , 0 , 1 ));
		if( $fc >= 65 && $fc <= 90 ) {
			my $class = __PACKAGE__ . '::' . $provider_name;
			$class = Plack::Util::load_class( $class );
			my $default_config = $class->config( $self );
			for my $k ( keys %$default_config ) {
				$config->{ $k } ||= $default_config->{ $k };
			}
		}

		$config->{signature_method} ||= 'HMAC-SHA1';
		$config->{version} ||= 1;

		# version 1 checking
		if( $config->{version} == 1 ) {
			for( qw(consumer_key consumer_secret request_token_url access_token_url request_method signature_method) ) 
			{
				die "Please setup $_ for $provider_name" unless $config->{$_};
			}
		}
		elsif( $config->{version} == 2 ) {

			for( qw(client_id client_secret authorize_url access_token_url) ) {
				die "Please setup $_ for $provider_name" unless $config->{$_};
			}
		}

		# mount routes
		my $path = $self->prefix . '/' . lc( $provider_name );
		my $callback_path = $self->prefix . '/' . lc( $provider_name ) . '/callback';
		$self->add_route( $path , { provider => $provider_name , method => 'request_token' } );
		$self->add_route( $callback_path , { provider => $provider_name , method => 'access_token' } );
	}
}

sub get_provider_names { 
	my $self = shift;
	return keys %{ $self->providers };
}


sub add_route { 
	my ($self,$path,$config) = @_;
	# warn 'OAuth route: ' . $path . ' ====> ' . $config->{provider};
	$routes{ $path } = $config;
}

sub dispatch_oauth_call { 
	my ($self,$env) = @_;
	my $path = $env->{PATH_INFO};
	my $n = $routes{ $path };
	return unless $n;
	my $method = $n->{method};
	return $self->$method( $env , $n->{provider} );
}

sub call {
	my ($self,$env) = @_;

	my $res;
	$res = $self->dispatch_oauth_call( $env );
	return $res if $res;

	$res = $self->app->( $env );
	return $res;
}


sub _redirect {
	my ($self,$uri,$code) = @_;
	my $resp = Plack::Response->new( $code );
	$resp->redirect( $uri );
	return $resp->finalize;
}

sub _response {
	my ($self,$content) = @_;
	my $resp = Plack::Response->new( 200 );
	$resp->body( $content );
	return $resp->finalize;
}

sub request_token {
	my ($self,$env,$provider) = @_;
	my $config = $self->providers->{ $provider };
	return $self->request_token_v1( $env, $provider , $config ) if $config->{version} == 1;
	return $self->request_token_v2( $env, $provider , $config ) if $config->{version} == 2;
}






sub request_token_v2 {
	my ($self,$env,$provider,$config) = @_;

	# "https://www.facebook.com/dialog/oauth?client_id=YOUR_APP_ID&redirect_uri=YOUR_URL";
	my $uri = URI->new( $config->{authorize_url} );
	$uri->query_form( 
		client_id     => $config->{client_id},
		redirect_uri  => ( $config->{redirect_uri} || $self->build_callback_uri( $provider, $env ) ),
		response_type => $config->{response_type} || 'code',
		scope         => $config->{scope},
	);
	return $self->_redirect( $uri );
}



sub request_token_v1 { 
	my ($self,$env,$provider,$config) = @_;
    $Net::OAuth::PROTOCOL_VERSION = Net::OAuth::PROTOCOL_VERSION_1_0A;
    my $ua = LWP::UserAgent->new;
    my $request = Net::OAuth->request("request token")->new( 
            %$config,

			request_url => $config->{request_token_url},

			timestamp => DateTime->now->epoch,
			nonce => md5_hex(time),

			callback => $self->build_callback_uri( $provider, $env )
		);
    $request->sign;
    my $res = $ua->request(POST $request->to_url); # Post message to the Service Provider

    if ($res->is_success) {
        my $response = Net::OAuth->response('request token')->from_post_body($res->content);

		# got response token
		my $uri = URI->new( $config->{authorize_url} );
		$uri->query_form( oauth_token => $response->token );

		return $self->_redirect( $uri );
        # print "Got Request Token ", $response->token, "\n";
        # print "Got Request Token Secret ", $response->token_secret, "\n";
    }
    else {
		# failed.
		my $plack_res = Plack::Response->new(200);
		$plack_res->body( $res->content );
        return $plack_res->finialize;
    }
}





sub access_token {
	my ($self,$env,$provider) = @_;
	my $config = $self->providers->{ $provider };
	return $self->access_token_v1( $env, $provider , $config ) if $config->{version} == 1;
	return $self->access_token_v2( $env, $provider , $config ) if $config->{version} == 2;
}

sub access_token_v2 {
	my ($self,$env,$provider,$config) = @_;

	# http://YOUR_URL?code=A_CODE_GENERATED_BY_SERVER
	my $req = Plack::Request->new($env);
	my $code = $req->param('code');

	# https://graph.facebook.com/oauth/access_token?
	# 	client_id=YOUR_APP_ID&redirect_uri=YOUR_URL&
	# 	client_secret=YOUR_APP_SECRET&code=THE_CODE_FROM_ABOVE
	my $method = $config->{request_method} || 'GET';

	my $uri = URI->new( $config->{access_token_url} );
    my $ua = LWP::UserAgent->new;
	my $ua_response;
	my %args = (
		client_id     => $config->{client_id},
		client_secret => $config->{client_secret},
		redirect_uri  => $config->{redirect_uri} || $self->build_callback_uri( $provider , $env ),
		code          => $code,
		scope         => $config->{scope},
		grant_type    => $config->{grant_type},
	);
	if( $method eq 'GET' ) {
		$uri->query_form( %args );
		$ua_response = $ua->get( $uri );
	} 
	elsif( $method eq 'POST' ) {
		$ua_response = $ua->post( $uri , \%args );
	}

	my $response_content = $ua_response->content;
	my $content_type = $ua_response->header('Content-Type');
	my $oauth_data;

	if( $content_type =~ m{json} ) {
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

	die unless $oauth_data;

	my $res;
	$res = $self->signin->( $env, $oauth_data ) if $self->signin;
	return $res if $res;

	# for testing
	return $self->_response( YAML::Dump $oauth_data );
}

sub access_token_v1 {
	my ($self,$env,$provider,$config) = @_;

    # http://app.local:3000/oauth/twitter/callback?
    #   oauth_token=
    #   oauth_verifier=
    # my $response = Net::OAuth->response( 'user auth' )->from_hash( request->params );
	my $req = Plack::Request->new( $env );
    my $response = Net::OAuth->response( 'user auth' )->from_hash( { 
        oauth_token    => $req->param('oauth_token'),
        oauth_verifier => $req->param('oauth_verifier'),
    });

    my $request = Net::OAuth->request( 'access token' )->new(
        %$config,

        timestamp => DateTime->now->epoch,
        nonce => md5_hex(time),

        token => $response->token,
        token_secret => '',
		request_url => $config->{access_token_url},
        verifier    => $req->param('oauth_verifier'),
    );
    $request->sign;

    my $ua = LWP::UserAgent->new;
    my $ua_response = $ua->request( GET $request->to_url );

	# XXX: use Plack::Response...
    die $ua_response->content unless $ua_response->is_success;

#     Catalyst::Exception->throw( $ua_response->status_line.' '.$ua_response->content )
#         unless $ua_response->is_success;

    $response = Net::OAuth->response( 'access token' )->from_post_body( $ua_response->content );

    my $oauth_data = +{
		version             => $config->{version},
		provider            => $provider,
		access_token        => $response->token,
		access_token_secret => $response->token_secret,
		extra_params        => $response->extra_params
    };
	my $res;
	$res = $self->signin->( $env, $oauth_data ) if $self->signin;
	return $res if $res;
	
	# return $res if $res;

	return $self->_response( YAML::Dump( $oauth_data ) );
    # my $user_obj = $realm->find_user( $user, $c );
    # return $user_obj if ref $user_obj;
    # $c->log->debug( 'Verified OAuth identity failed' ) if $self->debug;
}

sub build_callback_uri {
	my ($self,$provider,$env) = @_;
	my $uri = URI->new( $env->{'psgi.url_scheme'} . '://' . $env->{HTTP_HOST} . $self->prefix . '/' . lc($provider) . '/callback' );
	return $uri;
}

sub register_env {
	my ($self,$params) = @_;
	my $prefix = 'oauth.';
}

1;
__END__

=head1 NAME

Plack::Middleware::OAuth - 

=head1 DESCRIPTION




=head1 SYNOPSIS


	use Plack::Builder;

	builder {
	
		enable 'OAuth', prefix => '/_oauth',
			providers => {
				'Twitter' =>     # capital case implies Plack::Middleware::OAuth::Twitter
				{
					consumer_key      => ...
					consumer_secret   => ...
				},

				'Facebook' =>   # captical case implies Plack::Middleware::OAuth::Facebook
				{
					client_id        => ...
					client_secret           => ...
					scope            => 'email,read_stream',
				},

				'Github' => 
				{
					client_id => ...
					client_secret => ...
					scope => 'user,public_repo'
				},

				'custom_provider' => { 
					version => 1,
					....
				}

					# oauth path
					#   /oauth/custom_provider
					#   /oauth/custom_provider/callback
			};

		$app;
	};

The callback/redirect URL is set to {SCHEMA}://{HTTP_HOST}/{prefix}/{provider}/callback by default.

=head1 Reference

OAuth Workflow

L<http://hueniverse.com/oauth/guide/workflow/>

OAuth 2.0 Protocal Draft

L<http://tools.ietf.org/html/draft-ietf-oauth-v2>

Github OAuth 

L<https://github.com/account/applications/2739>

Github - Create A New Client

L<https://github.com/account/applications>

Twitter OAuth

L<https://dev.twitter.com/apps/1225208/show>

Twitter - Create A New App

L<https://dev.twitter.com/apps>


Facebook OAuth

L<http://developers.facebook.com/docs/authentication/>

Facebook - Create A New App

L<https://developers.facebook.com/apps>

Google OAuth

L<http://code.google.com/apis/accounts/docs/OAuth2.html>

Google OAuth Scope:

L<http://code.google.com/apis/gdata/faq.html#AuthScopes>



=cut
