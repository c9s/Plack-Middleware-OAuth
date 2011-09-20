use Plack::Builder;
use Plack::Middleware::OAuth;
my $app = sub { 
    my $env = shift;
    return [ 200, [ 'Content-Type' => 'text/plain' ], [ "Hello World" ] ];
};
builder {
    mount '/oauth' => builder { 
        enable 'OAuth', providers => {  };
    };
    mount '/' => builder { $app };
};
