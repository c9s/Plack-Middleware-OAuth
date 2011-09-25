package Plack::Middleware::OAuth::UserInfo;
use warnings;
use strict;
use Plack::Util::Accessor qw(token config);

sub new { 
    my $class = shift;
    my %args = @_;
    bless \%args, $class;
}

# config: provider config hashref
# token:  access token object

sub ask {
    my ($self,$provider_name) = @_;
    if( $provider_name =~ m/^\+/ ) {
        my $info_class = Plack::Util::load_class( $provider_name );
        return $info_class->new( token => $self->token , config => $self->config )->query;
    } else {
        my $info_class = Plack::Util::load_class( $provider_name , __PACKAGE__ );
        return $info_class->new( token => $self->token , config => $self->config )->query;
    }
}

sub query { ... }

1;
__END__

=head1 NAME

Plack::Middleware::OAuth::UserInfo

=head1 DESCRIPTION


=head1 SYNOPSIS

    my $userinfo = Plack::Middleware::OAuth::UserInfo->new( 
        token => $token , 
        config => $provider_config
    );

    my $info_hash = $userinfo->ask( 'Twitter' );   # load Plack::Middleware::OAuth::UserInfo::Twitter
    my $info_hash = $userinfo->ask( 'Github' );    # load Plack::Middleware::OAuth::UserInfo::GitHub
    my $info_hash = $userinfo->ask( '+FullQualified::CustomUserInfoQuery' );

In the customized user info query class should implement query method for querying user info.

=cut

