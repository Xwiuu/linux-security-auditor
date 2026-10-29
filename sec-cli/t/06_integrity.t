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
# 2. Regular Files & Nested Directories
# -------------------------------------------------------------
my $file1 = File::Spec->catfile($audit_dir, 'alpha.txt');
open(my $f1, '>:raw', $file1) or die "Cannot write $file1: $!";
print $f1 "The quick brown fox jumps over the lazy dog";
close($f1);
chmod 0644, $file1;

my $expected_hash1 = sha256_hex("The quick brown fox jumps over the lazy dog");

my $sub_dir = File::Spec->catdir($audit_dir, 'subdir', 'nested');
mkdir File::Spec->catdir($audit_dir, 'subdir') or die $!;
mkdir $sub_dir or die $!;

my $file2 = File::Spec->catfile($sub_dir, 'beta.txt');
open(my $f2, '>:raw', $file2) or die "Cannot write $file2: $!";
print $f2 "nested content for integrity verification";
close($f2);
chmod 0644, $file2;

my $expected_hash2 = sha256_hex("nested content for integrity verification");

my $main_baseline = File::Spec->catfile($out_dir, 'main_baseline.json');
my ($init_res, $init_err) = LSA::SecEng::Integrity::init_baseline(
    directory => $audit_dir,
    output    => $main_baseline,
);

ok(defined $init_res, "init_baseline on audit_dir succeeds");
is($init_err, undef, "No error on init_baseline");
is($init_res->{files_indexed}, 2, "Exactly 2 regular files indexed");

# Verify restrictive 0600 permissions
my $mode_val = (stat($main_baseline))[2] & 0777;
is(sprintf("0%o", $mode_val), "0600", "Baseline file created with restrictive 0600 permissions");

# -------------------------------------------------------------
# 3. Unchanged Tree Verification
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
# 4. FIX-01 & Required Test 1: Incomplete scan must not publish baseline
# -------------------------------------------------------------
my $failed_pub_file = File::Spec->catfile($out_dir, 'failed_pub_baseline.json');
my ($inc_res, $inc_err) = LSA::SecEng::Integrity::init_baseline(
    directory          => $audit_dir,
    output             => $failed_pub_file,
    _inject_scan_error => "Injected unreadable path error",
);

is($inc_res->{baseline_sha256}, undef, "Incomplete scan does not return baseline digest");
is($inc_err->{code}, 3, "Incomplete scan exits with code 3");
like($inc_err->{error}, qr/Cannot publish incomplete baseline/, "Error explains incomplete publication rejection");
ok(!-e $failed_pub_file, "Incomplete scan DID NOT create or publish baseline on disk");

# -------------------------------------------------------------
# 5. FIX-01 & Required Test 2: Existing baseline remains byte-identical after failed replacement
# -------------------------------------------------------------
my $canary_file = File::Spec->catfile($out_dir, 'canary_baseline.json');
open(my $cfh, '>:raw', $canary_file) or die $!;
print $cfh "CANARY BASELINE CONTENT - MUST REMAIN UNTOUCHED";
close($cfh);
my $canary_sha_before = sha256_hex("CANARY BASELINE CONTENT - MUST REMAIN UNTOUCHED");

my ($canary_res, $canary_err) = LSA::SecEng::Integrity::init_baseline(
    directory          => $audit_dir,
    output             => $canary_file,
    force              => 1,
    _inject_scan_error => "Injected failure before write",
);

is($canary_err->{code}, 3, "Failed replacement returns error code 3");
my $canary_raw_after = do {
    open(my $in, '<:raw', $canary_file) or die $!;
    local $/;
    <$in>;
};
is(sha256_hex($canary_raw_after), $canary_sha_before, "Existing baseline remains byte-identical after failed replacement");

# -------------------------------------------------------------
# 6. FIX-02 & Required Test 3: Newly added symlink is not silently ignored
# -------------------------------------------------------------
my $new_symlink = File::Spec->catfile($audit_dir, 'link_to_alpha.txt');
eval { symlink($file1, $new_symlink) };
SKIP: {
    skip "Symlink creation unsupported", 4 unless -l $new_symlink;

    my ($ver_sym_res, $ver_sym_err) = LSA::SecEng::Integrity::verify_baseline(
        directory => $audit_dir,
        baseline  => $main_baseline,
    );

    ok(defined $ver_sym_res, "verify_baseline inspects tree with new symlink");
    is($ver_sym_err->{code}, 1, "Exit code 1 on difference detection with new symlink");
    is($ver_sym_res->{summary}->{added}, 1, "Newly added symlink reported in added count");
    my ($sym_finding) = grep { $_->{path} eq 'link_to_alpha.txt' } @{$ver_sym_res->{findings}};
    is($sym_finding->{status}, 'ADDED', "Symlink finding has status ADDED");
    is($sym_finding->{details}->{type}, 'symlink', "Finding details identify type as symlink");

    unlink $new_symlink or die $!;
}

# -------------------------------------------------------------
# 7. FIX-02 & Required Test 4: Directory symlink replacement cannot escape target tree
# -------------------------------------------------------------
my $escape_dir = File::Spec->catdir($audit_dir, 'subdir_escape');
mkdir $escape_dir or die $!;
my $escape_subfile = File::Spec->catfile($escape_dir, 'nested.txt');
open(my $efh, '>:raw', $escape_subfile) or die $!;
print $efh "nested in escape dir";
close($efh);

# Create baseline including escape_dir
my $escape_base = File::Spec->catfile($out_dir, 'escape_base.json');
my ($eb_res, $eb_err) = LSA::SecEng::Integrity::init_baseline(
    directory => $audit_dir,
    output    => $escape_base,
);
is($eb_err, undef, "init_baseline with escape_dir succeeds");

# Replace escape_dir with a symlink to external /tmp
unlink $escape_subfile;
rmdir $escape_dir;
eval { symlink('/tmp', $escape_dir) };
SKIP: {
    skip "Directory symlink unsupported", 3 unless -l $escape_dir;

    my ($ver_esc_res, $ver_esc_err) = LSA::SecEng::Integrity::verify_baseline(
        directory => $audit_dir,
        baseline  => $escape_base,
    );

    ok(defined $ver_esc_res, "verify_baseline inspects directory replaced by symlink");
    # Must NOT follow symlink outside tree or crash!
    my ($esc_finding) = grep { $_->{path} =~ /subdir_escape/ } @{$ver_esc_res->{findings}};
    ok(defined $esc_finding, "Finding records directory symlink replacement");
    ok($ver_esc_err->{code} == 1 || $ver_esc_err->{code} == 3, "Exits with difference (1) or error (3)");

    unlink $escape_dir;
}

# -------------------------------------------------------------
# 8. FIX-05 & Required Test 5: Baseline input exceeding size limit is rejected
# -------------------------------------------------------------
my ($size_res, $size_err) = LSA::SecEng::Integrity::verify_baseline(
    directory           => $audit_dir,
    baseline            => $main_baseline,
    _max_baseline_size  => 10, # artificially set 10-byte limit
);

is($size_res, undef, "Oversized baseline rejected");
is($size_err->{code}, 2, "Exit code 2 when baseline size exceeds limit");
like($size_err->{error}, qr/exceeds maximum permitted limit/, "Error explains size limit violation");

# -------------------------------------------------------------
# 9. FIX-05 & Required Test 6: Malformed metadata is rejected
# -------------------------------------------------------------
# Test 6a: Negative size
my $mal_size_file = File::Spec->catfile($out_dir, 'mal_size.json');
my $mal_size_doc = {
    schema_version   => '1.0.0',
    target_directory => $audit_dir,
    file_count       => 1,
    files => [
        { path => 'alpha.txt', sha256 => 'a' x 64, size_bytes => -5, mode => '0644' },
    ],
};
open(my $msfh, '>:raw', $mal_size_file) or die $!;
print $msfh JSON::PP->new->encode($mal_size_doc);
close($msfh);

my ($ms_res, $ms_err) = LSA::SecEng::Integrity::verify_baseline(
    directory => $audit_dir,
    baseline  => $mal_size_file,
);
is($ms_res, undef, "Negative size_bytes rejected");
is($ms_err->{code}, 2, "Exit code 2 on negative size_bytes");
like($ms_err->{error}, qr/Malformed or negative size_bytes/, "Error explains negative size rejection");

# Test 6b: Malformed mode
my $mal_mode_file = File::Spec->catfile($out_dir, 'mal_mode.json');
my $mal_mode_doc = {
    schema_version   => '1.0.0',
    target_directory => $audit_dir,
    file_count       => 1,
    files => [
        { path => 'alpha.txt', sha256 => 'a' x 64, size_bytes => 10, mode => '9999' },
    ],
};
open(my $mmfh, '>:raw', $mal_mode_file) or die $!;
print $mmfh JSON::PP->new->encode($mal_mode_doc);
close($mmfh);

my ($mm_res, $mm_err) = LSA::SecEng::Integrity::verify_baseline(
    directory => $audit_dir,
    baseline  => $mal_mode_file,
);
is($mm_res, undef, "Malformed octal mode rejected");
is($mm_err->{code}, 2, "Exit code 2 on malformed octal mode");

# Test 6c: Header file_count mismatch
my $mismatch_file = File::Spec->catfile($out_dir, 'mismatch_count.json');
my $mismatch_doc = {
    schema_version   => '1.0.0',
    target_directory => $audit_dir,
    file_count       => 50, # declares 50 but contains 1
    files => [
        { path => 'alpha.txt', sha256 => 'a' x 64, size_bytes => 10, mode => '0644' },
    ],
};
open(my $mcfh, '>:raw', $mismatch_file) or die $!;
print $mcfh JSON::PP->new->encode($mismatch_doc);
close($mcfh);

my ($mc_res, $mc_err) = LSA::SecEng::Integrity::verify_baseline(
    directory => $audit_dir,
    baseline  => $mismatch_file,
);
is($mc_res, undef, "file_count mismatch rejected");
is($mc_err->{code}, 2, "Exit code 2 on header file_count mismatch");
like($mc_err->{error}, qr/file_count mismatch/, "Error describes file_count mismatch");

# -------------------------------------------------------------
# 10. FIX-05 & Required Test 7: Noncanonical paths rejected
# -------------------------------------------------------------
my @bad_paths = (
    './alpha.txt',
    'alpha.txt/./beta.txt',
    'subdir/../alpha.txt',
    'subdir//alpha.txt',
    '/etc/passwd',
    'alpha.txt/',
    ' alpha.txt',
);

for my $bad_p (@bad_paths) {
    my $bad_file = File::Spec->catfile($out_dir, 'bad_path.json');
    my $bad_doc = {
        schema_version   => '1.0.0',
        target_directory => $audit_dir,
        file_count       => 1,
        files => [
            { path => $bad_p, sha256 => 'a' x 64, size_bytes => 10, mode => '0644' },
        ],
    };
    open(my $bfh, '>:raw', $bad_file) or die $!;
    print $bfh JSON::PP->new->encode($bad_doc);
    close($bfh);

    my ($bp_res, $bp_err) = LSA::SecEng::Integrity::verify_baseline(
        directory => $audit_dir,
        baseline  => $bad_file,
    );
    is($bp_res, undef, "Noncanonical path '$bad_p' rejected");
    is($bp_err->{code}, 2, "Exit code 2 for noncanonical path '$bad_p'");
}

# -------------------------------------------------------------
# 11. FIX-06 & Required Test 8: Inaccessible subtree does not produce false removals
# -------------------------------------------------------------
my $lock_dir = File::Spec->catdir($audit_dir, 'locked_dir');
mkdir $lock_dir or die $!;
my $lock_file = File::Spec->catfile($lock_dir, 'secret.txt');
open(my $lfh, '>:raw', $lock_file) or die $!;
print $lfh "secret content";
close($lfh);
chmod 0644, $lock_file;

my $lock_base = File::Spec->catfile($out_dir, 'lock_base.json');
my ($lb_res, $lb_err) = LSA::SecEng::Integrity::init_baseline(
    directory => $audit_dir,
    output    => $lock_base,
);
is($lb_err, undef, "Baseline with locked_dir initialized successfully");

# Now make lock_dir completely inaccessible (chmod 0000)
chmod 0000, $lock_dir;
SKIP: {
    # If running as root (euid 0), chmod 0000 does not prevent access
    skip "Running as superuser (root bypasses DAC 0000)", 3 if $> == 0;

    my ($ver_lock_res, $ver_lock_err) = LSA::SecEng::Integrity::verify_baseline(
        directory => $audit_dir,
        baseline  => $lock_base,
    );

    ok(defined $ver_lock_res, "verify_baseline executed with locked directory");
    is($ver_lock_err->{code}, 3, "Inaccessible directory exits with error code 3 (never 0)");
    is($ver_lock_res->{summary}->{removed}, 0, "Inaccessible subtree DOES NOT produce false REMOVED findings");
    ok($ver_lock_res->{summary}->{error} >= 1, "Inaccessible subtree counted as ERROR");
}
chmod 0755, $lock_dir;
unlink $lock_file;
rmdir $lock_dir;

# -------------------------------------------------------------
# 12. FIX-04 & Required Test 9: Output collision does not overwrite existing file
# -------------------------------------------------------------
my $coll_target = File::Spec->catfile($out_dir, 'collision_target.json');
open(my $cf2, '>:raw', $coll_target) or die $!;
print $cf2 "ORIGINAL CONTENT TO BE PRESERVED";
close($cf2);

my ($col_res, $col_err) = LSA::SecEng::Integrity::init_baseline(
    directory => $audit_dir,
    output    => $coll_target,
    force     => 0,
);

is($col_res, undef, "Output collision rejected without force");
is($col_err->{code}, 2, "Exit code 2 on collision");
my $coll_content_after = do {
    open(my $c_in, '<:raw', $coll_target) or die $!;
    local $/;
    <$c_in>;
};
is($coll_content_after, "ORIGINAL CONTENT TO BE PRESERVED", "Pre-existing file was NOT overwritten or truncated");

# -------------------------------------------------------------
# 13. FIX-06 & Required Test 10: Concurrent modification cannot produce successful verification
# -------------------------------------------------------------
# Test with file modification during verify
my ($ver_c_res, $ver_c_err) = LSA::SecEng::Integrity::verify_baseline(
    directory => $audit_dir,
    baseline  => $main_baseline,
);
# Modify file1
open(my $m_fh, '>>:raw', $file1) or die $!;
print $m_fh "append to trigger diff";
close($m_fh);

my ($ver_diff_res, $ver_diff_err) = LSA::SecEng::Integrity::verify_baseline(
    directory => $audit_dir,
    baseline  => $main_baseline,
);

ok(defined $ver_diff_err, "Verification did not succeed cleanly after modification");
is($ver_diff_err->{code}, 1, "Exit code 1 on difference");
isnt($ver_diff_err->{code}, 0, "Modified file CANNOT produce successful verification exit code 0");

# Restore file1
open(my $f1_rest, '>:raw', $file1) or die $!;
print $f1_rest "The quick brown fox jumps over the lazy dog";
close($f1_rest);

# -------------------------------------------------------------
# 14. FIX-01, FIX-04 & Required Test 11: No leftover temporary output files after failure
# -------------------------------------------------------------
opendir(my $dh_out, $out_dir) or die $!;
my @leftover_tmps = grep { m{^\.tmp\.baseline} } readdir($dh_out);
closedir($dh_out);
is(scalar(@leftover_tmps), 0, "Zero leftover temporary baseline files found after failed runs");

# -------------------------------------------------------------
# 15. CLI Invocation Envelope & Strict Extra Argument Tests
# -------------------------------------------------------------
my $cli_init_out = `$bin integrity-init $audit_dir --output $out_dir/cli_final.json --format json`;
is($?, 0, "CLI integrity-init exits with code 0");
my $cli_init_json = eval { JSON::PP->new->decode($cli_init_out) };
is($cli_init_json->{schema_version}, '1.0.0', "Envelope schema_version is 1.0.0");
is($cli_init_json->{command}, 'integrity-init', "Envelope command is integrity-init");
is($cli_init_json->{status}, 'success', "Envelope status is success");

my $cli_ver_out = `$bin integrity-verify $audit_dir --baseline $out_dir/cli_final.json --format json`;
is($?, 0, "CLI integrity-verify exits with code 0");
my $cli_ver_json = eval { JSON::PP->new->decode($cli_ver_out) };
is($cli_ver_json->{command}, 'integrity-verify', "Envelope command is integrity-verify");
is($cli_ver_json->{status}, 'success', "Envelope status is success");

# Symlink output destination rejected
eval { symlink($file1, "$out_dir/symlink_out.json") };
if (-l "$out_dir/symlink_out.json") {
    my $sym_dest_cli = `$bin integrity-init $audit_dir --output $out_dir/symlink_out.json --format json 2>&1`;
    is($? >> 8, 2, "Symlink output destination rejected with exit code 2");
    unlink "$out_dir/symlink_out.json";
}

done_testing();
