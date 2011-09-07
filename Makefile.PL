use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;
use inc::Module::Install;

# Define metadata
all_from       'lib/Plack/Middleware/OAuth.pm';
readme_markdown_from 'lib/Plack/Middleware/OAuth.pm';

# Specific dependencies
requires       'File::Spec'  => '0.80';
# test_requires  'Test::More'  => '0.42';
# recommends     'Text::CSV_XS'=> '0.50';
# no_index       'directory'   => 'demos';
# install_script 'myscript';

WriteAll;
