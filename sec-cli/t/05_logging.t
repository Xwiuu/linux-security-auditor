use strict;
use warnings;
use Test::More;
use File::Basename qw(dirname);
use File::Spec;
use JSON::PP;

my $t_dir = dirname(File::Spec->rel2abs(__FILE__));
my $lib_dir = File::Spec->catdir($t_dir, '..', 'lib');
my $bin = File::Spec->catfile($t_dir, '..', 'bin', 'sec-cli');

unshift @INC, $lib_dir;
require_ok('LSA::SecEng::Logger');

# 1. Direct unit test of Logger module
my ($entry, $err) = LSA::SecEng::Logger::create_log_entry(
    level   => 'info',
    message => 'Test message',
    context => { task_id => 42 },
);

ok(defined $entry, "Log entry created successfully");
is($err, undef, "No error on valid entry");
is($entry->{level}, 'INFO', "Log level normalized to uppercase INFO");
is($entry->{message}, 'Test message', "Log message stored");
is($entry->{context}->{task_id}, 42, "Context preserved in entry");
like($entry->{timestamp}, qr/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/, "UTC ISO-8601 timestamp format");
ok(defined $entry->{pid}, "PID present");
ok(defined $entry->{hostname}, "Hostname present");

# 2. CLI execution test for log command
my $cli_out = `$bin log "Security audit initiated" --level warn --context '{"scan_id":"123"}'`;
is($?, 0, "sec-cli log command exits with code 0");

my $parsed = eval { JSON::PP->new->decode($cli_out) };
ok(defined $parsed, "CLI log command emits valid JSON line");
is($parsed->{level}, 'WARN', "Level is WARN");
is($parsed->{context}->{scan_id}, '123', "Context correctly parsed and serialized");

# 3. Invalid context JSON
my $inv_out = `$bin log "Message" --context 'invalid-json' 2>&1`;
is($? >> 8, 2, "Malformed context JSON exits with code 2");

done_testing();
