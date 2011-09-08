package Plack::Middleware::OAuth;
use warnings;
use strict;
use parent qw(Plack::Middleware);
use DateTime;
use Digest::MD5 qw(md5_hex);
use Plack::Util::Accessor qw(providers signin debug);
use Plack::Session;
use Plack::Response;
use Plack::Request;
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
		my $path = '/' . lc( $provider_name );
		my $callback_path = '/' . lc( $provider_name ) . '/callback';
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

    my $ses = Plack::Session->new( $env );
    use Data::Dumper; 
    warn Dumper( $ses->keys );

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
    $config->{redirect_uri} ||= $self->build_callback_uri( $provider, $env );

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

    # save it , becase we have to built callback URI from ENV.PATH_FINO and ENV.SCRIPT_NAME
    $config->{callback} ||= $self->build_callback_uri( $provider, $env );
    my $request = Net::OAuth->request("request token")->new( 
            %$config,

			request_url => $config->{request_token_url},

			timestamp => DateTime->now->epoch,
			nonce => md5_hex(time),
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






# Access token methods ....



sub access_token {
	my ($self,$env,$provider) = @_;
	my $config = $self->providers->{ $provider };
	return $self->access_token_v1( $env, $provider , $config ) if $config->{version} == 1;
	return $self->access_token_v2( $env, $provider , $config ) if $config->{version} == 2;
}


sub _oauth2_build_args {
    my ($self,$env,$provider,$config,$code) = @_;
	my %args = (
		client_id     => $config->{client_id},
		client_secret => $config->{client_secret},
		redirect_uri  => $config->{redirect_uri} || $self->build_callback_uri( $provider , $env ),
		scope         => $config->{scope},
		grant_type    => $config->{grant_type},
		code          => $code,
	);
    return %args;
}

sub _oauth2_get_access_token {
    my ($self,$config,$provider,$code,%args) = @_;
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
	my $content_type = $ua_response->header('Content-Type');
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



sub access_token_v2 {
	my ($self,$env,$provider,$config) = @_;

	# http://YOUR_URL?code=A_CODE_GENERATED_BY_SERVER
	my $req = Plack::Request->new($env);
	my $code = $req->param('code');

	# https://graph.facebook.com/oauth/access_token?
	# 	  client_id=YOUR_APP_ID&redirect_uri=YOUR_URL&
	# 	  client_secret=YOUR_APP_SECRET&code=THE_CODE_FROM_ABOVE

	my %args = $self->_oauth2_build_args($env,$provider,$config,$code); 
	my $oauth_data = $self->_oauth2_get_access_token( $config , $provider , $code , %args );

    if( $oauth_data->{params}->{error} ) {  
        # retry ? 
        # return $self->request_token_v2( $env, $provider, $config);
    }

	die unless $oauth_data;


    my $session = Plack::Session->new( $env );
    $session->set( 'oauth2.' . lc($provider)  . '.access_token' , $oauth_data->{params}->{access_token} );
    $session->set( 'oauth2.' . lc($provider)  . '.code'         , $oauth_data->{code} );


	my $res;
	$res = $self->signin->( $self, $env, $oauth_data ) if $self->signin;
	# return $res if $res;

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
		params => {
			access_token        => $response->token,
			access_token_secret => $response->token_secret,
			extra_params        => $response->extra_params
		},
    };

    my $session = Plack::Session->new( $env );
    $session->set( 'oauth.' . lc($provider)  . '.access_token' , $oauth_data->{params}->{access_token} );
    $session->set( 'oauth.' . lc($provider)  . '.access_token_secret' , $oauth_data->{params}->{access_token_secret} );

	my $res;
	$res = $self->signin->( $self, $env, $oauth_data ) if $self->signin;
	return $res if $res;

	return $self->_response( YAML::Dump( $oauth_data ) );
    # my $user_obj = $realm->find_user( $user, $c );
    # return $user_obj if ref $user_obj;
    # $c->log->debug( 'Verified OAuth identity failed' ) if $self->debug;
}

sub build_callback_uri {
	my ($self,$provider,$env) = @_;

    # 'REQUEST_URI' => '/_oauth/twitter',
    # 'SCRIPT_NAME' => '/_oauth',
    # 'PATH_INFO' => '/twitter',
    return URI->new( $env->{'psgi.url_scheme'} . '://' . $env->{HTTP_HOST} . $env->{SCRIPT_NAME} . '/' . lc($provider) . '/callback' );
}

1;
__END__

=head1 NAME

Plack::Middleware::OAuth - Plack middleware for OAuth1, OAuth2 and builtin provider configs. 

=head1 DESCRIPTION

L<Plack::Middleware::OAuth> supports OAuth1 and OAuth2, and provides builtin configs for providers like Twitter, Github, Google, Facebook.
The only need to mount you OAuth service if to setup your C<consumer_key>, C<consumer_secret> (OAuth1) or C<client_id>, C<client_secret>, C<scope> (OAuth2).

L<Plack::Middleware::OAuth> generates authorize url (mount_path/provider_id) and auththorize callback url (mount_path/privder_id/callback). 
If the authorize path matches, then user will be redirected to OAuth provider.

For example, if you mount L<Plack::Middleware::OAuth> on F</oauth>, then you can access L<http://youdomain.com/oauth/twitter> to authorize,
L<Plack::Middleware::OAuth> will redirect you to Twitter, after authorized, then Twitter will redirect you to your callback url
L<http://youdomain.com/oauth/twitter/callback>.

For more details, please check the example psgi in F<eg/> directory.

=head1 SYNOPSIS

	use Plack::Builder;

	builder {

        mount '/oauth' => builder {
            enable 'OAuth', 
                providers => {

                    # capital case implies Plack::Middleware::OAuth::Twitter
                    # authorize path: /oauth/twitter
                    # authorize callback path: /oauth/twitter/callback

                    'Twitter' =>
                    {
                        consumer_key      => ...
                        consumer_secret   => ...
                    },

                    # captical case implies Plack::Middleware::OAuth::Facebook
                    # authorize path: /oauth/facebook
                    # authorize callback path: /oauth/facebook/callback

                    'Facebook' =>
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

                    'Google' =>  { 
                        client_id     => '',
                        client_secret => '',
                        scope         => 'https://www.google.com/m8/feeds/'
                    },

                    # authorize path: /oauth/custom_provider
                    # authorize callback path: /oauth/custom_provider/callback
                    'custom_provider' => { 
                        version => 1,
                        ....
                    }
			};
        };
		$app;
	};

The callback/redirect URL is set to {SCHEMA}://{HTTP_HOST}/{prefix}/{provider}/callback by default.


=head1 Sessions

You can get OAuth1 or OAuth2 access token from Session,

    my $session = Plack::Session->new( $env );
    $session->get( 'oauth.twitter.access_token' );
    $session->get( 'oauth.twitter.access_token_secret' );

    $session->get( 'oauth2.facebook.access_token' );
    $session->get( 'oauth2.custom_provider' );

=head1 Reference

=for 4

=item *

OAuth Workflow 
L<http://hueniverse.com/oauth/guide/workflow/>

=item *

OAuth 2.0 Protocal Draft
L<http://tools.ietf.org/html/draft-ietf-oauth-v2>

=item * 

Github OAuth 
L<https://github.com/account/applications/2739>

=item *

Github - Create A New Client
L<https://github.com/account/applications>

=item *

Twitter OAuth
L<https://dev.twitter.com/apps/1225208/show>

=item *

Twitter - Create A New App
L<https://dev.twitter.com/apps>


=item *

Facebook OAuth
L<http://developers.facebook.com/docs/authentication/>

=item *

Facebook - Create A New App
L<https://developers.facebook.com/apps>

=item *

Facebook - Permissions
L<http://developers.facebook.com/docs/reference/api/permissions/>

=item *

Facebook - How to handle expired access_token
L<https://developers.facebook.com/blog/post/500/>

=item *

Google OAuth
L<http://code.google.com/apis/accounts/docs/OAuth2.html>

=item *

Google OAuth Scope:
L<http://code.google.com/apis/gdata/faq.html#AuthScopes>

=back

=cut
