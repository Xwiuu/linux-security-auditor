use strict;
use warnings;
use Test::More;
use File::Basename qw(dirname);
use File::Spec;

my $t_dir = dirname(File::Spec->rel2abs(__FILE__));
my $lib_dir = File::Spec->catdir($t_dir, '..', 'lib');
my $bin_file = File::Spec->catfile($t_dir, '..', 'bin', 'sec-cli');

unshift @INC, $lib_dir;

require_ok('LSA::SecEng::DNS');
require_ok('LSA::SecEng::TCP');
require_ok('LSA::SecEng::Hash');
require_ok('LSA::SecEng::Logger');
require_ok('LSA::SecEng::Integrity');
require_ok('LSA::SecEng::HostMetrics');

# Test sec-cli syntax via perl -c
my $cmd = "$^X -I$lib_dir -c $bin_file 2>&1";
my $output = `$cmd`;
is($?, 0, "sec-cli binary compiles with syntax OK");

done_testing();
