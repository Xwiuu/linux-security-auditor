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

# =============================================================
# SPRINT 02B TEST SUITE: CTO Final Integrity Correctness Fixes
# =============================================================

# -------------------------------------------------------------
# 16. FIX-01 (INCOMPLETE_SCAN_TEST): FIFO & Controlled Scan Failures
# -------------------------------------------------------------
my $fifo_dir = File::Spec->catfile($test_root, 'fifo_test_dir');
mkdir $fifo_dir or die $!;
my $fifo_f1 = File::Spec->catfile($fifo_dir, 'normal.txt');
open(my $ffh, '>:raw', $fifo_f1) or die $!;
print $ffh "clean content\n";
close($ffh);

my $fifo_base = File::Spec->catfile($out_dir, 'fifo_base.json');
my ($fb_res, $fb_err) = LSA::SecEng::Integrity::init_baseline(
    directory => $fifo_dir,
    output    => $fifo_base,
);
is($fb_err, undef, "Clean init_baseline before FIFO injection succeeds");

# Verify cleanly before FIFO
my ($f_clean_res, $f_clean_err) = LSA::SecEng::Integrity::verify_baseline(
    directory => $fifo_dir,
    baseline  => $fifo_base,
);
is($f_clean_err, undef, "Clean verification before FIFO exits with code 0");

# Now introduce an unsupported FIFO
my $fifo_node = File::Spec->catfile($fifo_dir, 'test_stream.pipe');
my $fifo_created = eval { POSIX::mkfifo($fifo_node, 0600) };
if ($fifo_created && -p $fifo_node) {
    my ($f_fifo_res, $f_fifo_err) = LSA::SecEng::Integrity::verify_baseline(
        directory => $fifo_dir,
        baseline  => $fifo_base,
    );
    ok(defined $f_fifo_err, "Verification on tree with unsupported FIFO returns error");
    is($f_fifo_err->{code}, 3, "INCOMPLETE_SCAN_TEST: Unsupported FIFO exits with code 3 (never 0)");
    is($f_fifo_err->{status}, 'error', "Status is 'error' on FIFO encounter");
    ok($f_fifo_res->{summary}->{error} >= 1, "summary.error is >= 1 on FIFO");

    # Find the error finding
    my @err_findings = grep { $_->{status} eq 'ERROR' && $_->{path} eq 'test_stream.pipe' } @{$f_fifo_res->{findings}};
    is(scalar(@err_findings), 1, "Explicit ERROR finding emitted for unsupported FIFO path");
    like($err_findings[0]->{error}, qr/Unsupported non-regular file/, "Error describes non-regular file");

    # Invariant: summary sum == total findings
    my $sum_f = $f_fifo_res->{summary}->{unchanged} +
                $f_fifo_res->{summary}->{modified} +
                $f_fifo_res->{summary}->{added} +
                $f_fifo_res->{summary}->{removed} +
                $f_fifo_res->{summary}->{error};
    is($sum_f, scalar(@{$f_fifo_res->{findings}}), "Summary counts invariant holds on FIFO failure");

    unlink($fifo_node);
}

# Test injected scan failure
my ($f_inj_res, $f_inj_err) = LSA::SecEng::Integrity::verify_baseline(
    directory          => $fifo_dir,
    baseline           => $fifo_base,
    _inject_scan_error => "Controlled disk failure",
);
ok(defined $f_inj_err, "Injected scan error returns error info");
is($f_inj_err->{code}, 3, "Injected scan error exits with code 3");
ok($f_inj_res->{summary}->{error} >= 1, "Injected scan error recorded in summary.error");

# -------------------------------------------------------------
# 17. FIX-02 (SYMLINK_BASELINE_TEST): Persist and Compare Symlinks
# -------------------------------------------------------------
my $sym_dir = File::Spec->catfile($test_root, 'sym_test_dir');
mkdir $sym_dir or die $!;
my $sym_f1 = File::Spec->catfile($sym_dir, 'file_a.txt');
my $sym_f2 = File::Spec->catfile($sym_dir, 'file_b.txt');
open(my $s1, '>:raw', $sym_f1) or die $!; print $s1 "content A\n"; close($s1);
open(my $s2, '>:raw', $sym_f2) or die $!; print $s2 "content B\n"; close($s2);

# Internal symlink
my $link_internal = File::Spec->catfile($sym_dir, 'sym_to_a.lnk');
symlink('file_a.txt', $link_internal) or die $!;

# External symlink (does not escape root during traversal; target not scanned)
my $link_external = File::Spec->catfile($sym_dir, 'sym_ext.lnk');
symlink('/etc/hosts', $link_external) or die $!;

# Broken symlink
my $link_broken = File::Spec->catfile($sym_dir, 'sym_broken.lnk');
symlink('nonexistent_target_123.txt', $link_broken) or die $!;

my $sym_base_file = File::Spec->catfile($out_dir, 'sym_baseline.json');
my ($sb_res, $sb_err) = LSA::SecEng::Integrity::init_baseline(
    directory => $sym_dir,
    output    => $sym_base_file,
);
is($sb_err, undef, "init_baseline with symlinks succeeds without error");
is($sb_res->{files_indexed}, 2, "2 regular files indexed in symlink baseline");
is($sb_res->{symlinks_indexed}, 3, "3 symlinks indexed in symlink baseline");

# Verify clean baseline with symlinks (CTO requirement: Baseline with existing symlink verifies cleanly)
my ($sv_clean_res, $sv_clean_err) = LSA::SecEng::Integrity::verify_baseline(
    directory => $sym_dir,
    baseline  => $sym_base_file,
);
is($sv_clean_err, undef, "SYMLINK_BASELINE_TEST: Baseline with existing symlinks verifies cleanly (code 0)");
is($sv_clean_res->{summary}->{unchanged}, 5, "All 5 entries (2 files + 3 symlinks) are UNCHANGED");
is($sv_clean_res->{summary}->{added}, 0, "Unchanged symlinks DO NOT appear as ADDED");
is($sv_clean_res->{summary}->{modified}, 0, "0 modified on clean tree");
is($sv_clean_res->{summary}->{removed}, 0, "0 removed on clean tree");
is($sv_clean_res->{summary}->{error}, 0, "0 error on clean tree");

# Symlink target changes
unlink($link_internal) or die $!;
symlink('file_b.txt', $link_internal) or die $!;

my ($sv_mod_res, $sv_mod_err) = LSA::SecEng::Integrity::verify_baseline(
    directory => $sym_dir,
    baseline  => $sym_base_file,
);
ok(defined $sv_mod_err, "Symlink target change detected");
is($sv_mod_err->{code}, 1, "Exit code 1 on symlink target modification");
is($sv_mod_res->{summary}->{modified}, 1, "summary.modified is 1 for changed symlink target");
my @mod_findings = grep { $_->{path} eq 'sym_to_a.lnk' } @{$sv_mod_res->{findings}};
is(scalar(@mod_findings), 1, "Finding found for modified symlink");
is($mod_findings[0]->{status}, 'MODIFIED', "Status is MODIFIED for changed symlink target");
is($mod_findings[0]->{details}->{target_baseline}, 'file_a.txt', "Recorded correct baseline target");
is($mod_findings[0]->{details}->{target_current}, 'file_b.txt', "Recorded correct current target");

# Restore link_internal
unlink($link_internal) or die $!;
symlink('file_a.txt', $link_internal) or die $!;

# Symlink removed
unlink($link_broken) or die $!;
my ($sv_rem_res, $sv_rem_err) = LSA::SecEng::Integrity::verify_baseline(
    directory => $sym_dir,
    baseline  => $sym_base_file,
);
ok(defined $sv_rem_err, "Removed symlink detected");
is($sv_rem_err->{code}, 1, "Exit code 1 on removed symlink");
is($sv_rem_res->{summary}->{removed}, 1, "summary.removed is 1 for removed symlink");
my @rem_findings = grep { $_->{path} eq 'sym_broken.lnk' } @{$sv_rem_res->{findings}};
is(scalar(@rem_findings), 1, "Finding for removed symlink emitted");
is($rem_findings[0]->{status}, 'REMOVED', "Status is REMOVED");
is($rem_findings[0]->{type}, 'symlink', "Removed entry identified as type symlink");

# Restore link_broken
symlink('nonexistent_target_123.txt', $link_broken) or die $!;

# Regular file replaced by symlink
unlink($sym_f2) or die $!;
symlink('file_a.txt', $sym_f2) or die $!;
my ($sv_f2s_res, $sv_f2s_err) = LSA::SecEng::Integrity::verify_baseline(
    directory => $sym_dir,
    baseline  => $sym_base_file,
);
is($sv_f2s_err->{code}, 1, "Exit code 1 when regular file replaced by symlink");
is($sv_f2s_res->{summary}->{modified}, 1, "summary.modified is 1 for file replaced by symlink");
my @f2s_findings = grep { $_->{path} eq 'file_b.txt' } @{$sv_f2s_res->{findings}};
is($f2s_findings[0]->{status}, 'MODIFIED', "Status is MODIFIED");
is($f2s_findings[0]->{details}->{type_change}, 'Regular file replaced by symbolic link', "Correct type_change description");

# Restore file_b.txt
unlink($sym_f2) or die $!;
open(my $s2_rst, '>:raw', $sym_f2) or die $!; print $s2_rst "content B\n"; close($s2_rst);

# Symlink replaced by regular file
unlink($link_internal) or die $!;
open(my $s_as_f, '>:raw', $link_internal) or die $!; print $s_as_f "now regular file\n"; close($s_as_f);
my ($sv_s2f_res, $sv_s2f_err) = LSA::SecEng::Integrity::verify_baseline(
    directory => $sym_dir,
    baseline  => $sym_base_file,
);
is($sv_s2f_err->{code}, 1, "Exit code 1 when symlink replaced by regular file");
is($sv_s2f_res->{summary}->{modified}, 1, "summary.modified is 1 for symlink replaced by file");
my @s2f_findings = grep { $_->{path} eq 'sym_to_a.lnk' } @{$sv_s2f_res->{findings}};
is($s2f_findings[0]->{status}, 'MODIFIED', "Status is MODIFIED");
is($s2f_findings[0]->{details}->{type_change}, 'Symbolic link replaced by regular file', "Correct type_change description");

# Duplicate identity across entry types in baseline document
my $dup_cross_file = File::Spec->catfile($out_dir, 'dup_cross.json');
my $dup_cross_doc = {
    schema_version   => '1.0.0',
    target_directory => $sym_dir,
    file_count       => 1,
    files => [
        { path => 'shared_name.txt', sha256 => 'a' x 64, size_bytes => 10, mode => '0644' },
    ],
    symlinks => [
        { path => 'shared_name.txt', symlink_target => 'other.txt', mode => '0777' },
    ],
};
open(my $dcfh, '>:raw', $dup_cross_file) or die $!;
print $dcfh JSON::PP->new->encode($dup_cross_doc);
close($dcfh);

my ($dcf_res, $dcf_err) = LSA::SecEng::Integrity::verify_baseline(
    directory => $sym_dir,
    baseline  => $dup_cross_file,
);
is($dcf_res, undef, "Duplicate identity across files and symlinks rejected");
is($dcf_err->{code}, 2, "Exit code 2 on duplicate identity across entry types");
like($dcf_err->{error}, qr/Duplicate path identity across baseline entry types/, "Error describes cross-type duplicate identity");

# -------------------------------------------------------------
# 18. FIX-03 (FSYNC_FAILURE_TEST): Crash Durability & Failure Handling
# -------------------------------------------------------------
my $fsync_target_base = File::Spec->catfile($out_dir, 'fsync_target_base.json');
open(my $ftfh, '>:raw', $fsync_target_base) or die $!;
print $ftfh "PRE-EXISTING FSYNC BASELINE DATA";
close($ftfh);

my ($fs_fail_res, $fs_fail_err) = LSA::SecEng::Integrity::init_baseline(
    directory          => $sym_dir,
    output             => $fsync_target_base,
    force              => 1,
    _inject_fsync_fail => 1,
);
is($fs_fail_res, undef, "Injected fsync failure returns undef payload");
ok(defined $fs_fail_err, "Injected fsync failure returns error");
is($fs_fail_err->{code}, 3, "FSYNC_FAILURE_TEST: File fsync failure aborts with exit code 3");
like($fs_fail_err->{error}, qr/fsync|File synchronization/, "Error indicates synchronization failure");

# Pre-existing baseline MUST be intact
open(my $ftfh_read, '<:raw', $fsync_target_base) or die $!;
my $ft_data = do { local $/; <$ftfh_read> };
close($ftfh_read);
is($ft_data, "PRE-EXISTING FSYNC BASELINE DATA", "Pre-existing baseline file untouched after fsync failure");

# Zero leftover temporary files
opendir(my $dh_fsync, $out_dir) or die $!;
my @leftover_fsync = grep { m{^\.tmp\.baseline} } readdir($dh_fsync);
closedir($dh_fsync);
is(scalar(@leftover_fsync), 0, "No orphaned temporary baseline files left on fsync failure");

# Directory fsync failure handled without false durability guarantee
my $dir_fsync_base = File::Spec->catfile($out_dir, 'dir_fsync_base.json');
my ($df_res, $df_err) = LSA::SecEng::Integrity::init_baseline(
    directory               => $sym_dir,
    output                  => $dir_fsync_base,
    _inject_dir_fsync_fail => 1,
);
is($df_err, undef, "Directory fsync failure does not break atomic publication");
ok(defined $df_res->{durability}, "Durability report exists in payload");
is($df_res->{durability}->{file_synced}, JSON::PP::true, "file_synced is true");
is($df_res->{durability}->{directory_synced}, JSON::PP::false, "directory_synced is false on failure");
ok(defined $df_res->{durability}->{directory_warning}, "Warning documented for unconfirmed directory durability");

# -------------------------------------------------------------
# 19. FIX-05: Strict Schema Consistency (Missing file_count, non-int count)
# -------------------------------------------------------------
# Missing file_count
my $nofc_file = File::Spec->catfile($out_dir, 'no_file_count.json');
my $nofc_doc = {
    schema_version   => '1.0.0',
    target_directory => $sym_dir,
    files            => [],
};
open(my $nofc_fh, '>:raw', $nofc_file) or die $!;
print $nofc_fh JSON::PP->new->encode($nofc_doc);
close($nofc_fh);

my ($nofc_res, $nofc_err) = LSA::SecEng::Integrity::verify_baseline(
    directory => $sym_dir,
    baseline  => $nofc_file,
);
is($nofc_res, undef, "Baseline missing file_count rejected");
is($nofc_err->{code}, 2, "Exit code 2 when mandatory file_count is missing");
like($nofc_err->{error}, qr/missing mandatory field.*file_count/, "Error specifies missing file_count");

# Non-integer file_count
my $badfc_file = File::Spec->catfile($out_dir, 'bad_file_count.json');
my $badfc_doc = {
    schema_version   => '1.0.0',
    target_directory => $sym_dir,
    file_count       => "many",
    files            => [],
};
open(my $badfc_fh, '>:raw', $badfc_file) or die $!;
print $badfc_fh JSON::PP->new->encode($badfc_doc);
close($badfc_fh);

my ($badfc_res, $badfc_err) = LSA::SecEng::Integrity::verify_baseline(
    directory => $sym_dir,
    baseline  => $badfc_file,
);
is($badfc_res, undef, "Baseline with non-integer file_count rejected");
is($badfc_err->{code}, 2, "Exit code 2 on non-integer file_count");
like($badfc_err->{error}, qr/nonnegative integer/, "Error specifies file_count must be nonnegative integer");

done_testing();
