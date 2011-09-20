package Plack::Middleware::OAuth::Handler::RequestTokenV1;
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


    $Net::OAuth::PROTOCOL_VERSION = Net::OAuth::PROTOCOL_VERSION_1_0A;
    my $ua = LWP::UserAgent->new;

    # save it , becase we have to built callback URI from ENV.PATH_FINO and ENV.SCRIPT_NAME
    $config->{callback} ||= $self->default_callback;
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

		return $self->redirect( $uri );
        # print "Got Request Token ", $response->token, "\n";
        # print "Got Request Token Secret ", $response->token_secret, "\n";
    }

	# failed.
	return $self->render( $res->content );
}

1;
