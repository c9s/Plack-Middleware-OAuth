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
                my ( $self, $oauth_data ) = @_;

                $self->render( 'Success' );
                $self->to_json( $oauth_data );
                $self->to_yaml( $oauth_data );
                $self->redirect( '/another_path' );
            },
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
