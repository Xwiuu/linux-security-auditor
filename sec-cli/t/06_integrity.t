use strict;
use warnings;
use Test::More;
use File::Basename qw(dirname);
use File::Spec;
use File::Temp qw(tempdir);
use Digest::SHA qw(sha256_hex);
use JSON::PP;

my $t_dir = dirname(File::Spec->rel2abs(__FILE__));
my $lib_dir = File::Spec->catdir($t_dir, '..', 'lib');
my $bin = File::Spec->catfile($t_dir, '..', 'bin', 'sec-cli');
unshift @INC, $lib_dir;

require_ok('LSA::SecEng::Integrity');

my $test_root = tempdir(CLEANUP => 1);
my $audit_dir = File::Spec->catdir($test_root, 'audited_tree');
mkdir $audit_dir or die "Cannot create $audit_dir: $!";

my $out_dir = File::Spec->catdir($test_root, 'baselines');
mkdir $out_dir or die "Cannot create $out_dir: $!";

# -------------------------------------------------------------
# 1. Empty Directory
# -------------------------------------------------------------
my $empty_dir = File::Spec->catdir($test_root, 'empty_dir');
mkdir $empty_dir or die "Cannot create $empty_dir: $!";

my $empty_baseline = File::Spec->catfile($out_dir, 'empty_baseline.json');
my ($init_empty_res, $init_empty_err) = LSA::SecEng::Integrity::init_baseline(
    directory => $empty_dir,
    output    => $empty_baseline,
);

ok(defined $init_empty_res, "init_baseline on empty directory succeeds");
is($init_empty_err, undef, "No error on empty directory initialization");
is($init_empty_res->{files_indexed}, 0, "Empty directory has 0 files indexed");
ok(-f $empty_baseline, "Empty baseline file created on disk");

my ($ver_empty_res, $ver_empty_err) = LSA::SecEng::Integrity::verify_baseline(
    directory => $empty_dir,
    baseline  => $empty_baseline,
);

ok(defined $ver_empty_res, "verify_baseline on empty directory succeeds");
is($ver_empty_err, undef, "No difference or error on empty tree verification");
is($ver_empty_res->{summary}->{unchanged}, 0, "0 unchanged files in empty tree");
is($ver_empty_res->{summary}->{modified}, 0, "0 modified files in empty tree");

# -------------------------------------------------------------
# 2. Single Regular File & Known SHA-256
# -------------------------------------------------------------
my $file1 = File::Spec->catfile($audit_dir, 'alpha.txt');
open(my $f1, '>:raw', $file1) or die "Cannot write $file1: $!";
print $f1 "The quick brown fox jumps over the lazy dog";
close($f1);
chmod 0644, $file1;

my $expected_hash1 = sha256_hex("The quick brown fox jumps over the lazy dog");

# -------------------------------------------------------------
# 3. Nested Directories
# -------------------------------------------------------------
my $sub_dir = File::Spec->catdir($audit_dir, 'subdir', 'nested');
mkdir File::Spec->catdir($audit_dir, 'subdir') or die $!;
mkdir $sub_dir or die $!;

my $file2 = File::Spec->catfile($sub_dir, 'beta.txt');
open(my $f2, '>:raw', $file2) or die "Cannot write $file2: $!";
print $f2 "nested content for integrity verification";
close($f2);
chmod 0644, $file2;

my $expected_hash2 = sha256_hex("nested content for integrity verification");

# Initialize baseline for audit_dir
my $main_baseline = File::Spec->catfile($out_dir, 'main_baseline.json');
my ($init_res, $init_err) = LSA::SecEng::Integrity::init_baseline(
    directory => $audit_dir,
    output    => $main_baseline,
);

ok(defined $init_res, "init_baseline on audit_dir succeeds");
is($init_err, undef, "No error on init_baseline");
is($init_res->{files_indexed}, 2, "Exactly 2 regular files indexed");

# -------------------------------------------------------------
# 4. Atomic Output Behavior & Restrictive Permissions
# -------------------------------------------------------------
ok(-f $main_baseline, "Baseline file exists at output path");
my $mode_val = (stat($main_baseline))[2] & 0777;
is(sprintf("0%o", $mode_val), "0600", "Baseline file created with restrictive 0600 permissions");

# -------------------------------------------------------------
# 5. Deterministic Ordering & Known Hash Verification
# -------------------------------------------------------------
my $base_raw = do {
    open(my $bfh, '<:raw', $main_baseline) or die $!;
    local $/;
    <$bfh>;
};
my $base_json = JSON::PP->new->decode($base_raw);
is($base_json->{schema_version}, '1.0.0', "Baseline schema_version is 1.0.0");
is(scalar(@{$base_json->{files}}), 2, "Baseline contains 2 file entries");
is($base_json->{files}->[0]->{path}, 'alpha.txt', "First entry is 'alpha.txt' (alphabetical)");
is($base_json->{files}->[0]->{sha256}, $expected_hash1, "Known SHA-256 for alpha.txt matches");
is($base_json->{files}->[1]->{path}, 'subdir/nested/beta.txt', "Second entry is 'subdir/nested/beta.txt'");
is($base_json->{files}->[1]->{sha256}, $expected_hash2, "Known SHA-256 for beta.txt matches");

# -------------------------------------------------------------
# 6. Unchanged Tree Verification
# -------------------------------------------------------------
my ($ver_res1, $ver_err1) = LSA::SecEng::Integrity::verify_baseline(
    directory => $audit_dir,
    baseline  => $main_baseline,
);

ok(defined $ver_res1, "verify_baseline on unchanged tree returns payload");
is($ver_err1, undef, "No errors or warnings on unchanged tree (exit code 0)");
is($ver_res1->{summary}->{unchanged}, 2, "2 files unchanged");
is($ver_res1->{summary}->{modified}, 0, "0 modified files");
is($ver_res1->{summary}->{added}, 0, "0 added files");
is($ver_res1->{summary}->{removed}, 0, "0 removed files");
is($ver_res1->{summary}->{error}, 0, "0 inspection errors");

# -------------------------------------------------------------
# 7. Added File Detection
# -------------------------------------------------------------
my $added_file = File::Spec->catfile($audit_dir, 'gamma.txt');
open(my $fa, '>:raw', $added_file) or die $!;
print $fa "newly added file content";
close($fa);

my ($ver_add_res, $ver_add_err) = LSA::SecEng::Integrity::verify_baseline(
    directory => $audit_dir,
    baseline  => $main_baseline,
);

ok(defined $ver_add_res, "verify_baseline detects additions");
is($ver_add_err->{code}, 1, "Exit code 1 on difference detection");
is($ver_add_res->{summary}->{added}, 1, "1 added file detected");
is($ver_add_res->{summary}->{unchanged}, 2, "2 unchanged files remain");

# Cleanup added file
unlink $added_file or die $!;

# -------------------------------------------------------------
# 8. Modified Content Detection
# -------------------------------------------------------------
open(my $fm, '>>:raw', $file1) or die $!;
print $fm " - modified content";
close($fm);

my ($ver_mod_res, $ver_mod_err) = LSA::SecEng::Integrity::verify_baseline(
    directory => $audit_dir,
    baseline  => $main_baseline,
);

ok(defined $ver_mod_res, "verify_baseline detects modification");
is($ver_mod_err->{code}, 1, "Exit code 1 on modification");
is($ver_mod_res->{summary}->{modified}, 1, "1 modified file detected");
my ($mod_finding) = grep { $_->{path} eq 'alpha.txt' } @{$ver_mod_res->{findings}};
is($mod_finding->{status}, 'MODIFIED', "alpha.txt status is MODIFIED");
ok(defined $mod_finding->{details}->{sha256_current}, "Current SHA-256 reported");

# Restore content
open(my $fr, '>:raw', $file1) or die $!;
print $fr "The quick brown fox jumps over the lazy dog";
close($fr);

# -------------------------------------------------------------
# 9. Removed File Detection
# -------------------------------------------------------------
unlink $file2 or die $!;

my ($ver_rem_res, $ver_rem_err) = LSA::SecEng::Integrity::verify_baseline(
    directory => $audit_dir,
    baseline  => $main_baseline,
);

ok(defined $ver_rem_res, "verify_baseline detects removal");
is($ver_rem_err->{code}, 1, "Exit code 1 on removal");
is($ver_rem_res->{summary}->{removed}, 1, "1 removed file detected");
my ($rem_finding) = grep { $_->{path} eq 'subdir/nested/beta.txt' } @{$ver_rem_res->{findings}};
is($rem_finding->{status}, 'REMOVED', "beta.txt status is REMOVED");

# -------------------------------------------------------------
# 10. Symlink Replacement Detection
# -------------------------------------------------------------
# Replace missing file2 with a symbolic link to file1
eval { symlink($file1, $file2) };
SKIP: {
    skip "Symlink creation unsupported", 2 unless -l $file2;

    my ($ver_sym_res, $ver_sym_err) = LSA::SecEng::Integrity::verify_baseline(
        directory => $audit_dir,
        baseline  => $main_baseline,
    );

    ok(defined $ver_sym_res, "verify_baseline inspects symlink replacement");
    is($ver_sym_err->{code}, 1, "Exit code 1 when file replaced by symlink");
    my ($sym_finding) = grep { $_->{path} eq 'subdir/nested/beta.txt' } @{$ver_sym_res->{findings}};
    is($sym_finding->{status}, 'MODIFIED', "Symlink replacement flagged as MODIFIED");
    like($sym_finding->{details}->{type_change}, qr/symbolic link/i, "Details note replacement by symbolic link");
    unlink $file2;
}

# Restore file2
open(my $fr2, '>:raw', $file2) or die $!;
print $fr2 "nested content for integrity verification";
close($fr2);

# -------------------------------------------------------------
# 11. Security Control: Output Collision Protection
# -------------------------------------------------------------
my ($coll_res, $coll_err) = LSA::SecEng::Integrity::init_baseline(
    directory => $audit_dir,
    output    => $main_baseline, # already exists
    force     => 0,
);

is($coll_res, undef, "Output collision rejected");
is($coll_err->{code}, 2, "Exit code 2 on output collision without force");
like($coll_err->{error}, qr/already exists/, "Collision error message explains restriction");

# -------------------------------------------------------------
# 12. Security Control: Reject Output Located Inside Audited Tree
# -------------------------------------------------------------
my $inside_output = File::Spec->catfile($audit_dir, 'inside_baseline.json');
my ($ins_res, $ins_err) = LSA::SecEng::Integrity::init_baseline(
    directory => $audit_dir,
    output    => $inside_output,
);

is($ins_res, undef, "Output inside audited tree rejected");
is($ins_err->{code}, 2, "Exit code 2 when output resides inside audited tree");
like($ins_err->{error}, qr/cannot be located inside the audited directory tree/, "Containment error message");
ok(!-e $inside_output, "No output file created inside audited tree");

# -------------------------------------------------------------
# 13. Malformed Baseline Rejection
# -------------------------------------------------------------
my $malformed_file = File::Spec->catfile($out_dir, 'malformed.json');
open(my $mfh, '>:raw', $malformed_file) or die $!;
print $mfh "{ corrupted json content: missing quotes ...";
close($mfh);

my ($mal_res, $mal_err) = LSA::SecEng::Integrity::verify_baseline(
    directory => $audit_dir,
    baseline  => $malformed_file,
);

is($mal_res, undef, "Malformed baseline rejected");
is($mal_err->{code}, 2, "Exit code 2 on malformed baseline JSON");
like($mal_err->{error}, qr/Malformed baseline JSON/, "Error describes JSON syntax failure");

# -------------------------------------------------------------
# 14. Path Traversal & Duplicate Entry Rejection in Baseline
# -------------------------------------------------------------
my $traversal_file = File::Spec->catfile($out_dir, 'traversal.json');
my $traversal_json = {
    schema_version   => '1.0.0',
    target_directory => $audit_dir,
    files => [
        { path => '../../etc/passwd', sha256 => 'a' x 64, size_bytes => 10, mode => '0644' },
    ],
};
open(my $tfh, '>:raw', $traversal_file) or die $!;
print $tfh JSON::PP->new->encode($traversal_json);
close($tfh);

my ($trav_res, $trav_err) = LSA::SecEng::Integrity::verify_baseline(
    directory => $audit_dir,
    baseline  => $traversal_file,
);

is($trav_res, undef, "Path traversal baseline rejected");
is($trav_err->{code}, 2, "Exit code 2 on traversal path");
like($trav_err->{error}, qr/Invalid or unsafe path entry/, "Traversal error message");

# Duplicate entry
my $dup_file = File::Spec->catfile($out_dir, 'duplicate.json');
my $dup_json = {
    schema_version   => '1.0.0',
    target_directory => $audit_dir,
    files => [
        { path => 'alpha.txt', sha256 => 'a' x 64, size_bytes => 10, mode => '0644' },
        { path => 'alpha.txt', sha256 => 'b' x 64, size_bytes => 20, mode => '0644' },
    ],
};
open(my $dfh, '>:raw', $dup_file) or die $!;
print $dfh JSON::PP->new->encode($dup_json);
close($dfh);

my ($dup_res, $dup_err) = LSA::SecEng::Integrity::verify_baseline(
    directory => $audit_dir,
    baseline  => $dup_file,
);

is($dup_res, undef, "Duplicate entry in baseline rejected");
is($dup_err->{code}, 2, "Exit code 2 on duplicate path entry");
like($dup_err->{error}, qr/Duplicate path entry in baseline/, "Duplicate error message");

# -------------------------------------------------------------
# 15. CLI Execution Tests with Envelope Validation
# -------------------------------------------------------------
my $cli_out_init = `$bin integrity-init $audit_dir --output $out_dir/cli_base.json --format json`;
is($?, 0, "CLI integrity-init exits with code 0");
my $cli_init_data = eval { JSON::PP->new->decode($cli_out_init) };
ok(defined $cli_init_data, "CLI integrity-init emits valid JSON");
is($cli_init_data->{schema_version}, '1.0.0', "Envelope schema_version is 1.0.0");
is($cli_init_data->{command}, 'integrity-init', "Envelope command is integrity-init");
is($cli_init_data->{status}, 'success', "Envelope status is success");
is($cli_init_data->{exit_code}, 0, "Envelope exit_code is 0");
ok(defined $cli_init_data->{data}->{baseline_sha256}, "Envelope data contains baseline_sha256");

# CLI verify success
my $cli_out_ver = `$bin integrity-verify $audit_dir --baseline $out_dir/cli_base.json --format json`;
is($?, 0, "CLI integrity-verify exits with code 0 on matching tree");
my $cli_ver_data = eval { JSON::PP->new->decode($cli_out_ver) };
ok(defined $cli_ver_data, "CLI integrity-verify emits valid JSON");
is($cli_ver_data->{command}, 'integrity-verify', "Envelope command is integrity-verify");
is($cli_ver_data->{status}, 'success', "Envelope status is success");
is($cli_ver_data->{data}->{summary}->{unchanged}, 2, "Summary indicates 2 unchanged files");

# CLI strict positional extra argument rejection
my $extra_init = `$bin integrity-init $audit_dir extra_arg --output $out_dir/extra.json 2>&1`;
is($? >> 8, 2, "CLI integrity-init with extra argument exits with code 2");
like($extra_init, qr/Unexpected extra argument: 'extra_arg'/, "Error describes extra argument");

my $extra_ver = `$bin integrity-verify $audit_dir extra_arg --baseline $out_dir/cli_base.json 2>&1`;
is($? >> 8, 2, "CLI integrity-verify with extra argument exits with code 2");
like($extra_ver, qr/Unexpected extra argument: 'extra_arg'/, "Error describes extra argument");

# CLI text format
my $cli_text_ver = `$bin integrity-verify $audit_dir --baseline $out_dir/cli_base.json --format text`;
is($?, 0, "CLI integrity-verify with --format text exits with code 0");
like($cli_text_ver, qr/Summary:/, "Text output displays summary section");
like($cli_text_ver, qr/Unchanged:\s+2/, "Text output displays unchanged count");

done_testing();
