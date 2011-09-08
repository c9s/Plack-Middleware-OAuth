use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;
use inc::Module::Install;

# Define metadata
all_from       'lib/Plack/Middleware/OAuth.pm';
readme_markdown_from 'lib/Plack/Middleware/OAuth.pm';

requires       
    'File::Spec'  => 0,
    'DateTime' => 0,
    'Digest::MD5' => 0,
    'URI' => 0,
    'URI::Query' => 0,
    'LWP::UserAgent' => 0,
    'Net::OAuth' => 0,
    'HTTP::Request::Common' => 0,
    'DateTime' => 0,
    'YAML' => 0,
    'JSON' => 0;

# test_requires  'Test::More'  => '0.42';
# recommends     'Text::CSV_XS'=> '0.50';
# no_index       'directory'   => 'demos';
# install_script 'myscript';

WriteAll;
