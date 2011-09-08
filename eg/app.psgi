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
            signin => sub {
                my ( $self, $env, $oauth_data ) = @_;

                # find user

                # update user auth

                return 0;
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
