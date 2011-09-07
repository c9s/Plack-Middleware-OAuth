#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'Plack::Middleware::OAuth' ) || print "Bail out!\n";
}

diag( "Testing Plack::Middleware::OAuth $Plack::Middleware::OAuth::VERSION, Perl $], $^X" );
