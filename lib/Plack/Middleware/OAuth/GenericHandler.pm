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
    my $res;
    $res = $self->get if $self->method eq 'GET';
    return $res if $res;

    $res = $self->post if $self->method eq 'POST';
    return $res if $res;

    $res = $self->any;
    return $res if $res;

    return $self->render( ref($self) . ': handler is not defined.' );
}


# get method handler
sub get { }

# get post handler
sub post { }

sub any { }

# default content_type
sub content_type { 'text/html' }

sub to_json { 
    my ($self, $obj) = @_;
    $json_any ||= JSON::Any->new;
    return $self->render( $json_any->encode($obj) , 'text/json' );
}

sub to_yaml {
    my ($self, $obj) = @_;
    return $self->render( Dump( $obj ) , 'text/plain' );
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
__END__

=head1 NAME

Plack::Middleware::OAuth::GenericHandler - 

=head1 DESCRIPTION

=head1 SYNOPSIS


=head1 METHODS

=head2 redirect( $URI | String )

=head2 render( $body | String , $content_type | String )

=head2 to_yaml( $obj )

=head2 to_json( $obj )

=head2 post 

POST handler, abstract method.

=head2 get

GET handler, abstract method.

=head2 any

Any handler, abstract method.

=head2 run

dispatcher method to POST or GET

=cut
