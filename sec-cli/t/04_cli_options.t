use strict;
use warnings;
use Test::More;
use File::Basename qw(dirname);
use File::Spec;
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

# 4. JSON contract validation on valid command
my $hash_out = `$bin hash $bin --format json`;
is($?, 0, "hash $bin exits with code 0");
my $hash_json = eval { JSON::PP->new->decode($hash_out) };
ok(defined $hash_json, "Output is valid JSON");

# Contract checks
is($hash_json->{schema_version}, '1.0.0', "Schema version is 1.0.0");
is($hash_json->{component}, 'sec-cli', "Component is sec-cli");
is($hash_json->{command}, 'hash', "Command is hash");
is($hash_json->{status}, 'success', "Status is success");
ok(defined $hash_json->{data}->{hash}, "Data payload contains hash digest");

done_testing();
