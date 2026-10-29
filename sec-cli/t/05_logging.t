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

# 2. CLI execution test for log command (Sprint 01A FIX-01: wrapped in root sec-ops.v1 envelope)
my $cli_out = `$bin log "Security audit initiated" --level warn --context '{"scan_id":"123"}' --format json`;
is($?, 0, "sec-cli log command exits with code 0");

my $parsed = eval { JSON::PP->new->decode($cli_out) };
ok(defined $parsed, "CLI log command emits valid JSON line");
is($parsed->{schema_version}, '1.0.0', "Root schema version matches 1.0.0");
is($parsed->{component}, 'sec-cli', "Root component matches sec-cli");
is($parsed->{command}, 'log', "Root command matches log");
is($parsed->{status}, 'success', "Status is success");
is($parsed->{exit_code}, 0, "Exit code is 0");
ok(ref($parsed->{data}) eq 'HASH', "Data payload is a HASH");
is($parsed->{data}->{level}, 'WARN', "Data payload level is WARN");
is($parsed->{data}->{message}, 'Security audit initiated', "Data payload message matches");
is($parsed->{data}->{context}->{scan_id}, '123', "Context correctly parsed and serialized");
ok(defined $parsed->{data}->{pid}, "PID present in data payload");
ok(defined $parsed->{data}->{hostname}, "Hostname present in data payload");

# 3. CLI execution with --format text
my $text_out = `$bin log "Text audit message" --level info --format text`;
is($?, 0, "sec-cli log with --format text exits with code 0");
like($text_out, qr/\[INFO\] Text audit message/, "Text output format displays timestamp, level, and message");

# 4. Invalid context JSON
my $inv_out = `$bin log "Message" --context 'invalid-json' 2>&1`;
is($? >> 8, 2, "Malformed context JSON exits with code 2");
my $inv_json = eval { JSON::PP->new->decode($inv_out) };
ok(defined $inv_json, "Malformed context returns valid JSON error envelope");
is($inv_json->{exit_code}, 2, "Error envelope exit_code is 2");
is($inv_json->{status}, 'error', "Error envelope status is error");

done_testing();
