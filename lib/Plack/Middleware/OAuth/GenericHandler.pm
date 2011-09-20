package Plack::Middleware::OAuth::GenericHandler;
use parent qw(Plack::Request);
use warnings;
use strict;
use YAML::Any;
use JSON::Any;

our $json_any;

sub run { 
    my $self = $_[0];
    # get method or post method ?
    return $self->get if $self->method eq 'GET';
    return $self->post if $self->method eq 'POST';
}


# get method handler
sub get {  }

# get post handler
sub post {  }

# default content_type
sub content_type { 'text/html' }

sub to_json { 
    my ($self, $obj) = @_;
    $json_any ||= JSON::Any->new;
    return $self->render( $json_any->encode($obj) , 'text/json' );
}

sub to_yaml {
    my ($self, $obj) = @_;
    return $self->render( Dump( $obj ) , 'text/yaml' );
}

sub render {
    my ($self,$body,$content_type) = @_;
    my $resp = $self->new_response( 200 );
    $resp->content_type( $content_type || $self->content_type );
    $resp->body( $body );
    return $resp->finalize;
}

sub redirect {
	my ($self,$uri,$code) = @_;
	my $resp = $self->new_response( $code );
	$resp->redirect( $uri );
	return $resp->finalize;
}

1;
