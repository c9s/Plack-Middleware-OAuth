package Plack::Middleware::OAuth;
use warnings;
use strict;
use parent qw(Plack::Middleware);
use DateTime;
use Digest::MD5 qw(md5_hex);
use Plack::Util::Accessor qw(providers on_signin on_error debug);
use Plack::Session;
use Plack::Response;
use Plack::Request;
use URI;
use URI::Query;
use LWP::UserAgent;
use Net::OAuth;
use HTTP::Request::Common;
use Plack::Middleware::OAuth::Handler::RequestTokenV2;
use DateTime;
use YAML;
use JSON;

our $VERSION = '0.03';

# routes cache
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
	my $res;
	$res = $self->dispatch_oauth_call( $env );
	return $res if $res;

	$res = $self->app->( $env );
	return $res;
}



sub _response {
	my ($self,$content) = @_;
	my $resp = Plack::Response->new( 200 );
	$resp->body( $content );
	return $resp->finalize;
}

sub request_token {
	my ($self,$env,$provider_name) = @_;
	my $config = $self->providers->{ $provider_name };
    my $class = $config->{version} == 1 ? 
                'Plack::Middleware::OAuth::Handler::RequestTokenV1' :
                $config->{version} == 2 ?
                    'Plack::Middleware::OAuth::Handler::RequestTokenV2' : 
                    'Plack::Middleware::OAuth::Handler::RequestTokenV1' ; # default class.
    my $req = $class->new( $env );
    $req->provider( $provider_name );
    $req->config( $config );
    return $req->run();
}


# Access token methods ....
sub access_token {
	my ($self,$env,$provider) = @_;
	my $config = $self->providers->{ $provider };
	return $self->access_token_v1( $env, $provider , $config ) if $config->{version} == 1;
	return $self->access_token_v2( $env, $provider , $config ) if $config->{version} == 2;
}


sub access_token_v2 {
	my ($self,$env,$provider,$config) = @_;

	# http://YOUR_URL?code=A_CODE_GENERATED_BY_SERVER
    my $req = Plack::Middleware::OAuth::Handler::AccessTokenV2->new( $env );
    $req->on_success(sub {  });
    $req->on_error(sub {  });
    $req->provider( $provider );
    $req->config( $config );
    return $req->run();

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

    unless($ua_response->is_success) {
        return $self->on_error->( $self, $env, $provider, $config ) if $self->on_error;
        return $self->_response( $ua_response->status_line . ' ' . $ua_response->content );
    }


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


#     my $session = $env->{'psgix.session'};
#     # my $session = Plack::Session->new( $env );
#     $session->set( 'oauth.' . lc($provider)  . '.access_token' , $oauth_data->{params}->{access_token} );
#     $session->set( 'oauth.' . lc($provider)  . '.access_token_secret' , $oauth_data->{params}->{access_token_secret} );

	my $res;
	$res = $self->on_success->( $self, $env, $oauth_data ) if $self->on_success;
	return $res if $res;


	return $self->_response( YAML::Dump( $oauth_data ) );
}

sub build_callback_uri {
	my ($self,$provider,$env) = @_;

    # 'REQUEST_URI' => '/_oauth/twitter',
    # 'SCRIPT_NAME' => '/_oauth',
    # 'PATH_INFO' => '/twitter',
    return URI->new( $env->{'psgi.url_scheme'} . '://' . $env->{HTTP_HOST} . $env->{SCRIPT_NAME} . '/' . lc($provider) . '/callback' );
}


package Plack::Middleware::OAuth::Handler::AccessToken::V1;
use parent qw(Plack::Middleware::OAuth::Handler);

1;
__END__

=head1 NAME

Plack::Middleware::OAuth - Plack middleware for OAuth1, OAuth2 and builtin provider configs. 

=head1 DESCRIPTION

This module is B<**ALPHA VERSION**> currently.

L<Plack::Middleware::OAuth> supports OAuth1 and OAuth2, and provides builtin configs for providers like Twitter, Github, Google, Facebook.
The only one thing you need to mount your OAuth service is to setup your C<consumer_key>, C<consumer_secret> (OAuth1) or C<client_id>, C<client_secret>, C<scope> (OAuth2).

L<Plack::Middleware::OAuth> generates authorize url (mount_path/provider_id) and auththorize callback url (mount_path/provider_id/callback). 
If the authorize path matches, then user will be redirected to OAuth provider to authorize your application.

For example, if you mount L<Plack::Middleware::OAuth> on F</oauth>, then you can access L<http://youdomain.com/oauth/twitter> to authorize,
L<Plack::Middleware::OAuth> will redirect you to Twitter, after authorized, then Twitter will redirect you to your callback url
L<http://youdomain.com/oauth/twitter/callback>.

For more details, please check the example psgi in F<eg/> directory.

=head1 SYNOPSIS

	use Plack::Builder;

	builder {

        mount '/oauth' => builder {
            enable 'OAuth', 

                on_signin => sub  { 
                    my ($self,$env,$oauth_data) = @_;
                    return [  200 , [ 'Content-type' => 'text/html' ] , 'Signin!' ];
                },

                on_error => sub {  ...  },

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

=head1 Specify Signin Callback

    enable 'OAuth', 
        providers => { .... },
        on_signin => sub  { 
            my ($self,$env,$oauth_data) = @_;
            return [  200 , [ 'Content-type' => 'text/html' ] , 'Signin!' ];
        };

Without specifying C<on_signin>, OAuth middleware will use YAML to dump the response data to page.

=head1 Handle Error

    enable 'OAuth', 
        providers => { .... },
        on_error => sub {
            my ($self,$env,$provider,$config) = @_;

        };

=head1 Supported Providers

=for 4

=item

Google

=item

Twitter

=item

Facebook

=item

Github

=back

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
