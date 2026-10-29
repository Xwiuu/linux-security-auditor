use strict;
use warnings;
use Test::More;
use File::Basename qw(dirname);
use File::Spec;
use IO::Socket::IP;
use JSON::PP;

my $t_dir = dirname(File::Spec->rel2abs(__FILE__));
my $bin = File::Spec->catfile($t_dir, '..', 'bin', 'sec-cli');

# 1. Version output
my $ver_out = `$bin --version`;
is($?, 0, "--version exits with code 0");
like($ver_out, qr/sec-cli version 1\.0\.0/, "Version output format is correct");

# 2. Help output
my $help_out = `$bin --help`;
is($?, 0, "--help exits with code 0");
like($help_out, qr/sec-cli <command>/, "Help output displays usage");

# 3. Unknown command
my $unk_out = `$bin unknown-subcmd 2>&1`;
is($? >> 8, 2, "Unknown command exits with code 2");
my $unk_json = eval { JSON::PP->new->decode($unk_out) };
ok(defined $unk_json, "Unknown command outputs JSON error envelope by default");
is($unk_json->{status}, 'error', "Status is error");
is($unk_json->{exit_code}, 2, "Exit code in JSON envelope matches 2");

# 4. JSON contract validation on all 4 commands (Sprint 01A FIX-01)
sub verify_envelope {
    my ($json, $expected_cmd) = @_;
    ok(defined $json, "$expected_cmd output is valid JSON");
    is($json->{schema_version}, '1.0.0', "$expected_cmd schema_version is 1.0.0");
    is($json->{component}, 'sec-cli', "$expected_cmd component is sec-cli");
    is($json->{command}, $expected_cmd, "$expected_cmd command matches $expected_cmd");
    is($json->{status}, 'success', "$expected_cmd status is success");
    is($json->{exit_code}, 0, "$expected_cmd exit_code is 0");
    ok(ref($json->{data}) eq 'HASH', "$expected_cmd data payload is a HASH");
    ok(ref($json->{errors}) eq 'ARRAY', "$expected_cmd errors field is an ARRAY");
    like($json->{timestamp}, qr/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/, "$expected_cmd timestamp is UTC ISO-8601");
}

# 4a. hash command envelope
my $hash_out = `$bin hash $bin --format json`;
is($?, 0, "hash $bin exits with code 0");
my $hash_json = eval { JSON::PP->new->decode($hash_out) };
verify_envelope($hash_json, 'hash');
ok(defined $hash_json->{data}->{hash}, "hash data contains hash field");

# 4b. dns command envelope
my $dns_out = `$bin dns localhost --format json`;
is($?, 0, "dns localhost exits with code 0");
my $dns_json = eval { JSON::PP->new->decode($dns_out) };
verify_envelope($dns_json, 'dns');
ok(defined $dns_json->{data}->{resolved_ips}, "dns data contains resolved_ips");

# 4c. tcp-check command envelope
# Bind a temporary local port to connect to
my $server = IO::Socket::IP->new(LocalHost => '127.0.0.1', LocalPort => 0, Listen => 1);
SKIP: {
    skip "Cannot bind local test listener", 11 unless $server;
    my $srv_port = $server->sockport;
    my $tcp_out = `$bin tcp-check 127.0.0.1 $srv_port --format json`;
    is($?, 0, "tcp-check 127.0.0.1 $srv_port exits with code 0");
    my $tcp_json = eval { JSON::PP->new->decode($tcp_out) };
    verify_envelope($tcp_json, 'tcp-check');
    is($tcp_json->{data}->{reachable}, JSON::PP::true, "tcp-check data indicates reachable");
    close($server);
}

# 4d. log command envelope (Sprint 01A FIX-01: wrapped in root sec-ops.v1 envelope)
my $log_out = `$bin log "Audit event test" --level info --context '{"scan":1}' --format json`;
is($?, 0, "log exits with code 0");
my $log_json = eval { JSON::PP->new->decode($log_out) };
verify_envelope($log_json, 'log');
is($log_json->{data}->{level}, 'INFO', "log data payload contains normalized level INFO");
is($log_json->{data}->{message}, "Audit event test", "log data payload contains log message");
is($log_json->{data}->{context}->{scan}, 1, "log data payload preserves context");
ok(defined $log_json->{data}->{pid}, "log data payload contains PID");
ok(defined $log_json->{data}->{hostname}, "log data payload contains hostname");

# 5. Strict Positional Arguments (Sprint 01A FIX-05)

# 5a. dns: expects 1 argument
my $dns_extra = `$bin dns localhost unexpected_extra_arg --format json 2>&1`;
is($? >> 8, 2, "dns with unexpected extra argument exits with code 2");
my $dns_extra_json = eval { JSON::PP->new->decode($dns_extra) };
is($dns_extra_json->{exit_code}, 2, "dns error envelope has exit_code 2");
like($dns_extra_json->{errors}->[0], qr/Unexpected extra argument: 'unexpected_extra_arg'/, "dns extra argument error message");

# 5b. tcp-check: expects 2 arguments
my $tcp_extra = `$bin tcp-check 127.0.0.1 80 extra_arg --format json 2>&1`;
is($? >> 8, 2, "tcp-check with unexpected extra argument exits with code 2");
my $tcp_extra_json = eval { JSON::PP->new->decode($tcp_extra) };
is($tcp_extra_json->{exit_code}, 2, "tcp-check error envelope has exit_code 2");
like($tcp_extra_json->{errors}->[0], qr/Unexpected extra argument: 'extra_arg'/, "tcp-check extra argument error message");

# 5c. hash: expects 1 argument
my $hash_extra = `$bin hash $bin extra_arg --format json 2>&1`;
is($? >> 8, 2, "hash with unexpected extra argument exits with code 2");
my $hash_extra_json = eval { JSON::PP->new->decode($hash_extra) };
is($hash_extra_json->{exit_code}, 2, "hash error envelope has exit_code 2");
like($hash_extra_json->{errors}->[0], qr/Unexpected extra argument: 'extra_arg'/, "hash extra argument error message");

# 5d. log: expects 1 argument
my $log_extra = `$bin log "message" extra_arg --format json 2>&1`;
is($? >> 8, 2, "log with unexpected extra argument exits with code 2");
my $log_extra_json = eval { JSON::PP->new->decode($log_extra) };
is($log_extra_json->{exit_code}, 2, "log error envelope has exit_code 2");
like($log_extra_json->{errors}->[0], qr/Unexpected extra argument: 'extra_arg'/, "log extra argument error message");

# 6. Options placed before or after command arguments
my $opt_after = `$bin dns localhost --timeout 2 --format json`;
is($?, 0, "Options placed after positional argument work correctly");
my $opt_after_json = eval { JSON::PP->new->decode($opt_after) };
is($opt_after_json->{command}, 'dns', "Command parsed with options after positional");

my $opt_before = `$bin --timeout 2 --format json dns localhost`;
is($?, 0, "Options placed before command work correctly");
my $opt_before_json = eval { JSON::PP->new->decode($opt_before) };
is($opt_before_json->{command}, 'dns', "Command parsed with options before command");

done_testing();
