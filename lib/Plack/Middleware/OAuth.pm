package Plack::Middleware::OAuth;
use warnings;
use strict;
use parent qw(Plack::Middleware);
use DateTime;
use Digest::MD5 qw(md5_hex);
use Plack::Util::Accessor qw(providers on_success on_error debug);
use Plack::Session;
use Plack::Response;
use Plack::Request;
use URI;
use URI::Query;
use Plack::Middleware::OAuth::UserInfo;
use Plack::Middleware::OAuth::Handler::RequestTokenV1;
use Plack::Middleware::OAuth::Handler::RequestTokenV2;
use Plack::Middleware::OAuth::Handler::AccessTokenV1;
use Plack::Middleware::OAuth::Handler::AccessTokenV2;
use DateTime;
use feature qw(switch say);

our $VERSION = '0.071';

# routes cache
#    path => { provider => ... , method => .... }
our %routes;


sub version1_required {
    qw(consumer_key consumer_secret request_token_url access_token_url request_token_method access_token_method signature_method);
}

sub version2_required {
    qw(client_id client_secret authorize_url access_token_url);
}


sub arguments_checking {
    my ($self,$provider_name,$config) = @_;
    # version 1 checking
    given ( $config->{version} ) {
        when(2) {  
            for( $self->version2_required ) { die "Please setup $_ for $provider_name" unless $config->{$_}; }
        }
        when(1) {
            for( $self->version1_required ) { die "Please setup $_ for $provider_name" unless $config->{$_}; }
        }
    }
}

sub load_config_from_pkg {
    my ($self,$provider_name) = @_;
    my $class = __PACKAGE__ . '::' . $provider_name;
    $class = Plack::Util::load_class( $class );
    return $class->config( $self );
}

sub prepare_app {
	my $self = shift;
	my $p = $self->providers;

    unless( ref($p) ) {
        if( $p =~ /\.yml$/ ) {
            use YAML::Any;
            say STDERR "Loading Provider YAML File: $p";
            $p = YAML::Any::LoadFile( $p );
            $self->providers( $p );
        }
    }

	for my $provider_name ( keys %$p ) {
		my $config = $p->{$provider_name};

		my $fc = ord(substr( $provider_name , 0 , 1 ));
		if( $fc >= 65 && $fc <= 90 ) {
			my $default_config = $self->load_config_from_pkg( $provider_name );
			for my $k ( keys %$default_config ) {
				$config->{ $k } ||= $default_config->{ $k };
			}
		}

		$config->{signature_method} ||= 'HMAC-SHA1';
		$config->{version} ||= 1;

        $self->arguments_checking( $provider_name , $config );

		# mount routes
		my $path = '/' . lc( $provider_name );
		my $callback_path = '/' . lc( $provider_name ) . '/callback';

        say STDERR "[OAuth] Mounting $provider_name to $path ...";
		$self->add_route( $path , { provider => $provider_name , method => 'request_token' } );

        say STDERR "[OAuth] Mounting $provider_name callback to $callback_path ...";
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

sub request_token {
	my ($self,$env,$provider) = @_;  # env and provider id
	my $config = $self->providers->{ $provider };
    my $class;
    given( $config->{version} ) {
        when (2) { $class = 'Plack::Middleware::OAuth::Handler::RequestTokenV2' }
        default  { $class = 'Plack::Middleware::OAuth::Handler::RequestTokenV1' }
    }

    my $req = $class->new( $env );
    $req->provider( $provider );
    $req->config( $config );
    return $req->run();
}


# Access token methods ....
sub access_token {
	my ($self,$env,$provider) = @_;
	my $config = $self->providers->{ $provider };

    my $class;
    given( $config->{version} ) {
        when (2) { $class = 'Plack::Middleware::OAuth::Handler::AccessTokenV2' }
        default  { $class = 'Plack::Middleware::OAuth::Handler::AccessTokenV1' }
    }

    my $req = $class->new( $env );
    $req->on_success( $self->on_success );
    $req->on_error( $self->on_error );
    $req->provider( $provider );
    $req->config( $config );
    return $req->run();
}

1;
__END__

=head1 NAME

Plack::Middleware::OAuth - Plack middleware for OAuth1, OAuth2 and builtin provider configs. 

=head1 DESCRIPTION

This module is still in B<**BETA**> , B<DO NOT USE THIS FOR PRODUCTION!>

L<Plack::Middleware::OAuth> supports OAuth1 and OAuth2, and provides builtin config for providers like Twitter, Github, Google, Facebook.
The only one thing you need to mount your OAuth service is to setup your C<consumer_key>, C<consumer_secret> (for OAuth1) or C<client_id>, C<client_secret>, C<scope> (for OAuth2).

This middleware also generates authorize url (mount_path/provider_id) and auththorize callback url (mount_path/provider_id/callback). 
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

                on_success => sub  { 
                    my ($self,$token) = @_;
                    my $env = $self->env;

                    my $config = $self->config;   # provider config


                    return $self->render( '..html content..' );
                    return $self->redirect( .... URL ... );

                    return [  200 , [ 'Content-type' => 'text/html' ] , 'Signin!' ];


                },

                on_error => sub {  ...  },

                providers => 'providers.yml',   # also works

                providers => {

                    # capital case implies Plack::Middleware::OAuth::Twitter
                    'Twitter' =>
                    {
                        consumer_key      => ...
                        consumer_secret   => ...
                    },

                    # captical case implies Plack::Middleware::OAuth::Facebook
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

                    'custom_provider' => { 
                        version => 1,
                        ....
                    }
			};
        };
		$app;
	};

The callback/redirect URL is set to {SCHEMA}://{HTTP_HOST}/{prefix}/{provider}/callback by default.

=head1 OAuth URL and Callback URL

For a defined key in providers hashref, and you mounted OAuth middleware at F</oauth>, 
the generated URLs will be like:

    authorize path: /oauth/custom_provider
    authorize callback path: /oauth/custom_provider/callback

The provider id (key) will be converted into lower-case.

For example, Github's URLs will be like:

    /oauth/github
    /oauth/github/callback

Facebook,

    /oauth/facebook
    /oauth/facebook/callback

You can also specify custom callback URL in a provider config.


=head1 Specify Success Callback

When access token is got, success handler will be called: 

    enable 'OAuth', 
        providers => { .... },
        on_success => sub  { 
            my ($self,$token) = @_;

            # $self: Plack::Middleware::OAuth::Handler (isa Plack::Request) object

            return $self->render( .... );

            return $self->redirect( .... );

            return $self->to_yaml( .... );

            return $self->to_json( .... );

            # or just return a raw arrayref
            return [  200 , [ 'Content-type' => 'text/html' ] , 'Signin!' ];
        };

Without specifying C<on_success>, OAuth middleware will use YAML to dump the response data to page.

To use access token to get user information, the following example demonstracte how to get corresponding user information:

    on_success => sub {
        my ($self,$token) = @_;

        if( $token->is_provider('Twitter') ) {
            my $config = $self->config;

            # return $self->to_yaml( $config );

            # get twitter user infomation with (api)
            my $twitter = Net::Twitter->new(
                traits              => [qw/OAuth API::REST/],
                consumer_key        => $config->{consumer_key},
                consumer_secret     => $config->{consumer_secret},
                access_token        => $token->access_token,
                access_token_secret => $token->access_token_secret,
            );

            return $self->to_yaml( { 
                account_settings => $twitter->account_settings,
                account_totals => $twitter->account_totals,
                show_user => $twitter->show_user( $token->params->{extra_params}->{screen_name} )
            } );
        }
    }

=head1 User Info Query Interface

To query user info from OAuth provider, you can use L<Plack::Middleware::OAuth::UserInfo> to help you.

    my $userinfo = Plack::Middleware::OAuth::UserInfo->new( 
        token =>  $token , 
        config => $provider_config
    );
    my $info_hash = $userinfo->ask( 'Twitter' );   # load Plack::Middleware::OAuth::UserInfo::Twitter

In you oauth success handler, it would be like:

    on_success => sub {
        my ($self,$token) = @_;

        my $userinfo = Plack::Middleware::OAuth::UserInfo->new( 
            token =>  $token , 
            config => $self->config
        );
        my $info_hash = $userinfo->ask( 'Twitter' );   # load Plack::Middleware::OAuth::UserInfo::Twitter
        return $self->to_yaml( $info_hash );
    };

=head1 Error Handler

An error handler should return a response data, it should be an array reference, for be finalized from L<Plack::Response>:

    enable 'OAuth', 
        providers => { .... },
        on_error => sub {
            my ($self,$token) = @_;

            $self->render( 'Error' ) unless $token;

            # $self: Plack::Middleware::OAuth::Handler (isa Plack::Request) object

        };

=head1 OAuth1 AccessToken Callback Data Structure

Twitter uses OAuth 1.0a, and the access token callback returns data like this:

    ---
    params:
        access_token: {{string}}
        access_token_secret: {{string}}
        extra_params:
            screen_name: {{screen name}}
            user_id: {{user id}}
    provider: Twitter
    version: 1


=head1 OAuth2 AccessToken Callback Data Structure

Github uses OAuth 2.0, and the access token callback returns data like this:

    ---
    params:
        code: {{string}}
        access_token: {{string}}
        token_type: bearer
    provider: Github
    version: 2

Google returns:

    ---
    params:
        access_token: {{string}}
        code: {{string}}
        expires_in: 3600
        refresh_token: {{string}}
        token_type: Bearer
    provider: Google
    version: 2

=head1 Sessions

You can get OAuth1 or OAuth2 access token from L<Plack::Session>,

    my $session = Plack::Session->new( $env );
    $session->get( 'oauth.twitter.access_token' );
    $session->get( 'oauth.twitter.access_token_secret' );

    $session->get( 'oauth2.facebook.access_token' );
    $session->get( 'oauth2.custom_provider' );


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

=head1 See Also

L<Net::OAuth>, L<Net::OAuth2>

=head1 Reference

=for 4

=item *

OAuth Workflow 
L<http://hueniverse.com/oauth/guide/workflow/>

=item *

OAuth 2.0 Protocal Draft
L<http://tools.ietf.org/html/draft-ietf-oauth-v2>

=item *

Github - Create A New Client
L<https://github.com/account/applications>

=item *

Twitter - Using OAuth 1.0a
L<https://dev.twitter.com/docs/auth/oauth>

=item *

Twitter - Moving from Basic Auth to OAuth
L<https://dev.twitter.com/docs/auth/moving-from-basic-auth-to-oauth>

=item *

Single-user OAuth with Examples
L<https://dev.twitter.com/docs/auth/oauth/single-user-with-examples>

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
