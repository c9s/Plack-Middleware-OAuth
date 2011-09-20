package Plack::Middleware::OAuth::Handler;
use parent qw(Plack::Middleware::OAuth::GenericHandler);
use warnings;
use strict;
use Plack::Util::Accessor qw(config provider on_success on_error);

1;

