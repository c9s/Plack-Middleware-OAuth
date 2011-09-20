package Plack::Middleware::OAuth::Handler::RequestTokenV1;
use warnings;
use strict;
use parent qw(Plack::Middleware::OAuth::Handler);
use Net::OAuth;
use Digest::MD5 qw(md5_hex);
use HTTP::Request::Common;
use LWP::UserAgent;
use DateTime;

sub build_args {
	my $self = $_[0];
	my $config = $self->config;
	return (
		$self->build_v1_common_args,
		request_url      => $config->{request_token_url},
		request_method   => $config->{request_token_method},
		callback         => $config->{callback} || $self->default_callback,
	);
}

sub run {
    my $self = shift;
    my $config = $self->config;

    $Net::OAuth::PROTOCOL_VERSION = Net::OAuth::PROTOCOL_VERSION_1_0A;
    my $ua = LWP::UserAgent->new;

    # save it , becase we have to built callback URI from ENV.PATH_FINO and ENV.SCRIPT_NAME
    my $request = Net::OAuth->request("request token")->new( $self->build_args );
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

	$self->on_error->( $self ) if $self->on_error;

	# failed.
	return $self->render( $res->content );
}

1;
