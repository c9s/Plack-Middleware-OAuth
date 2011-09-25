use Plack;
use Plack::Builder;
use lib 'lib';

my $app = sub {
    my $env = $_[0];
    my $resp = Plack::Response->new(200);
    $resp->body(  'OAuth Demo'  );
    return $resp->finalize;
};

builder {
    mount '/oauth' => builder {
        enable 'OAuth', 
            on_success => sub {
                my ( $self, $token ) = @_;

                my $userinfo = Plack::Middleware::OAuth::UserInfo->new( config => $self->config , token => $token );
                if( $token->is_provider('Twitter')  || $token->is_provider('Github') || $token->is_provider('Google') ) {
                    my $info = $userinfo->ask( $token->provider );
                    return $self->to_yaml( $info );
                }
                return $self->render( 'Error' );
            },

            # providers => 'eg/providers.yml',  # this also works
            providers => 
            {
                'Twitter' => {
                    consumer_key     => '',
                    consumer_secret  => '',
                },
                'Facebook' => {
                    client_id     => '',
                    client_secret => '',
                    scope     => 'email,read_stream',
                },
                'Google' =>  { 
                    client_id     => '',
                    client_secret => '',
                    scope         => 'https://www.google.com/m8/feeds/'
                },
                'Github' => {
                    client_id => '',
                    client_secret => '',
                    scope => 'user,public_repo'
                },
            };
        $app;
    };
};
