use strict;
use warnings;
use Test::More;
use File::Basename qw(dirname);
use File::Spec;
use File::Temp qw(tempdir);
use JSON::PP;

my $t_dir = dirname(File::Spec->rel2abs(__FILE__));
my $lib_dir = File::Spec->catdir($t_dir, '..', 'lib');
my $bin = File::Spec->catfile($t_dir, '..', 'bin', 'sec-cli');

unshift @INC, $lib_dir;
require_ok('LSA::SecEng::HostMetrics');

my $tmp_dir = tempdir(CLEANUP => 1);

# --- 1. Valid /proc/meminfo parsing ---
{
    my $meminfo_file = File::Spec->catfile($tmp_dir, 'meminfo_valid');
    open(my $fh, '>', $meminfo_file) or die "Cannot write $meminfo_file: $!";
    print $fh <<'EOF';
MemTotal:       16384000 kB
MemFree:         4096000 kB
MemAvailable:   12288000 kB
Buffers:          512000 kB
Cached:          7680000 kB
SwapTotal:       8192000 kB
SwapFree:        6144000 kB
EOF
    close($fh);

    my ($mem_data, $errs) = LSA::SecEng::HostMetrics::parse_meminfo($meminfo_file);
    ok(!$errs, "parse_meminfo succeeded without errors");
    ok(defined $mem_data, "parse_meminfo returned data hash");
    is($mem_data->{mem_total_kib}, 16384000, "mem_total_kib parsed accurately");
    is($mem_data->{mem_free_kib}, 4096000, "mem_free_kib parsed accurately");
    is($mem_data->{mem_available_kib}, 12288000, "mem_available_kib parsed accurately");
    is($mem_data->{swap_total_kib}, 8192000, "swap_total_kib parsed accurately");
    is($mem_data->{swap_free_kib}, 6144000, "swap_free_kib parsed accurately");
}

# --- 2. Missing required memory fields ---
{
    my $meminfo_missing = File::Spec->catfile($tmp_dir, 'meminfo_missing');
    open(my $fh, '>', $meminfo_missing) or die "Cannot write $meminfo_missing: $!";
    print $fh <<'EOF';
MemTotal:       16384000 kB
MemFree:         4096000 kB
Buffers:          512000 kB
Cached:          7680000 kB
SwapTotal:       8192000 kB
SwapFree:        6144000 kB
EOF
    close($fh);

    my ($mem_data, $errs) = LSA::SecEng::HostMetrics::parse_meminfo($meminfo_missing);
    ok(!defined $mem_data, "parse_meminfo returns undef when MemAvailable is missing");
    ok(defined $errs && @$errs > 0, "parse_meminfo reports error when required field is missing");
    like($errs->[0], qr/Missing required memory field 'MemAvailable'/, "Error explicitly names missing MemAvailable");
}

# --- 3. Malformed numeric values in meminfo ---
{
    my $meminfo_malformed = File::Spec->catfile($tmp_dir, 'meminfo_malformed');
    open(my $fh, '>', $meminfo_malformed) or die "Cannot write $meminfo_malformed: $!";
    print $fh <<'EOF';
MemTotal:       invalid_number kB
MemFree:         4096000 kB
MemAvailable:   12288000 kB
SwapTotal:       8192000 kB
SwapFree:        6144000 kB
EOF
    close($fh);

    my ($mem_data, $errs) = LSA::SecEng::HostMetrics::parse_meminfo($meminfo_malformed);
    ok(!defined $mem_data, "parse_meminfo returns undef on non-numeric value");
    ok(defined $errs && @$errs > 0, "parse_meminfo reports malformed error");
    like($errs->[0], qr/Malformed numeric value for 'MemTotal'/, "Error flags non-numeric value");
}

# --- 4. Valid load averages ---
{
    my $loadavg_file = File::Spec->catfile($tmp_dir, 'loadavg_valid');
    open(my $fh, '>', $loadavg_file) or die "Cannot write $loadavg_file: $!";
    print $fh "0.42 1.15 2.50 2/950 12345\n";
    close($fh);

    my ($load_data, $errs) = LSA::SecEng::HostMetrics::parse_loadavg($loadavg_file);
    ok(!$errs, "parse_loadavg succeeded without errors");
    ok(defined $load_data, "parse_loadavg returned data");
    cmp_ok(abs($load_data->{load_1m} - 0.42), '<', 0.001, "load_1m is 0.42");
    cmp_ok(abs($load_data->{load_5m} - 1.15), '<', 0.001, "load_5m is 1.15");
    cmp_ok(abs($load_data->{load_15m} - 2.50), '<', 0.001, "load_15m is 2.50");
}

# --- 5. Invalid loadavg content ---
{
    my $loadavg_empty = File::Spec->catfile($tmp_dir, 'loadavg_empty');
    open(my $fh, '>', $loadavg_empty) or die "Cannot write: $!";
    close($fh);

    my ($load_empty, $errs1) = LSA::SecEng::HostMetrics::parse_loadavg($loadavg_empty);
    ok(!defined $load_empty, "Empty loadavg returns undef");
    like($errs1->[0], qr/Empty load average file/, "Error flags empty loadavg");

    my $loadavg_short = File::Spec->catfile($tmp_dir, 'loadavg_short');
    open(my $fh2, '>', $loadavg_short) or die "Cannot write: $!";
    print $fh2 "0.42 1.15\n";
    close($fh2);

    my ($load_short, $errs2) = LSA::SecEng::HostMetrics::parse_loadavg($loadavg_short);
    ok(!defined $load_short, "Short loadavg (< 3 fields) returns undef");
    like($errs2->[0], qr/expected at least 3 fields/, "Error flags missing load fields");

    my $loadavg_nan = File::Spec->catfile($tmp_dir, 'loadavg_nan');
    open(my $fh3, '>', $loadavg_nan) or die "Cannot write: $!";
    print $fh3 "0.42 not_a_number 2.50 1/100 123\n";
    close($fh3);

    my ($load_nan, $errs3) = LSA::SecEng::HostMetrics::parse_loadavg($loadavg_nan);
    ok(!defined $load_nan, "Non-numeric loadavg returns undef");
    like($errs3->[0], qr/Malformed numeric value for load_5m/, "Error flags non-numeric load_5m");
}

# --- 6. Standard mountinfo entries & field boundaries ---
{
    my $mountinfo_file = File::Spec->catfile($tmp_dir, 'mountinfo_std');
    open(my $fh, '>', $mountinfo_file) or die "Cannot write: $!";
    print $fh <<'EOF';
40 1 0:37 /root / rw,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro
42 40 0:27 / /dev/shm rw,nosuid,nodev shared:3 - tmpfs tmpfs rw,size=8192k
44 40 0:28 / /dev/pts rw,nosuid,noexec,relatime shared:4 - devpts devpts rw,gid=5,mode=620
EOF
    close($fh);

    my ($mounts, $errs) = LSA::SecEng::HostMetrics::parse_mountinfo($mountinfo_file);
    ok(!$errs, "parse_mountinfo succeeded on standard entries");
    is(scalar(@$mounts), 3, "Parsed exactly 3 mount entries");

    my $m0 = $mounts->[0];
    is($m0->{mount_point}, '/', "Root mount point");
    is($m0->{filesystem_type}, 'ext4', "Root filesystem type");
    is($m0->{mount_source}, '/dev/sda1', "Root mount source");
    is($m0->{mount_root}, '/root', "Root mount root within fs");
    is($m0->{nodev}, JSON::PP::false, "Root does not have nodev");
    is($m0->{nosuid}, JSON::PP::false, "Root does not have nosuid");
    is($m0->{noexec}, JSON::PP::false, "Root does not have noexec");

    my $m1 = $mounts->[1];
    is($m1->{mount_point}, '/dev/shm', "/dev/shm mount point");
    is($m1->{filesystem_type}, 'tmpfs', "/dev/shm fs type");
    is($m1->{nodev}, JSON::PP::true, "/dev/shm has nodev");
    is($m1->{nosuid}, JSON::PP::true, "/dev/shm has nosuid");
    is($m1->{noexec}, JSON::PP::false, "/dev/shm lacks noexec");

    my $m2 = $mounts->[2];
    is($m2->{mount_point}, '/dev/pts', "/dev/pts mount point");
    is($m2->{nodev}, JSON::PP::false, "/dev/pts lacks nodev");
    is($m2->{nosuid}, JSON::PP::true, "/dev/pts has nosuid");
    is($m2->{noexec}, JSON::PP::true, "/dev/pts has noexec");
}

# --- 7. Mount points with escaped spaces and characters ---
{
    my $mountinfo_escaped = File::Spec->catfile($tmp_dir, 'mountinfo_escaped');
    open(my $fh, '>', $mountinfo_escaped) or die "Cannot write: $!";
    print $fh <<'EOF';
100 40 8:16 / /media/Backup\040Drive rw,nosuid,nodev,noexec shared:10 - vfat /dev/sdb1 rw
101 40 8:17 / /mnt/tab\011path rw,nodev shared:11 - ext4 /dev/sdc1 rw
102 40 8:18 / /mnt/back\134slash rw,nodev shared:12 - ext4 /dev/sdd1 rw
EOF
    close($fh);

    my ($mounts, $errs) = LSA::SecEng::HostMetrics::parse_mountinfo($mountinfo_escaped);
    ok(!$errs, "parse_mountinfo handled escaped characters");
    is(scalar(@$mounts), 3, "Parsed 3 escaped mounts");
    is($mounts->[0]->{mount_point}, '/media/Backup Drive', "Octal space \\040 unescaped to space");
    is($mounts->[1]->{mount_point}, "/mnt/tab\tpath", "Octal tab \\011 unescaped to tab");
    is($mounts->[2]->{mount_point}, '/mnt/back\\slash', "Octal backslash \\134 unescaped to backslash");
}

# --- 8. FIX-01: Correct mount security flag semantics (per-mount vs superblock) ---
{
    # Fixture A: 'noexec' appears ONLY in superblock options (field 11), NOT in mount options (field 6)
    my $file_super_only = File::Spec->catfile($tmp_dir, 'mountinfo_super_only');
    open(my $fhA, '>', $file_super_only) or die "Cannot write: $!";
    print $fhA <<'EOF';
300 40 8:1 / /mnt/super_noexec rw,relatime shared:30 - ext4 /dev/sda1 rw,noexec,data=ordered
EOF
    close($fhA);

    my ($mountsA, $errsA) = LSA::SecEng::HostMetrics::parse_mountinfo($file_super_only);
    ok(!$errsA, "Parsed super_only fixture without error");
    my $mA = $mountsA->[0];
    is($mA->{noexec}, JSON::PP::false, "Per-mount noexec is FALSE when noexec only appears in superblock options");
    is($mA->{flags}->{noexec}, JSON::PP::false, "Nested flags->noexec is FALSE when noexec only in superblock");
    ok((grep { $_ eq 'noexec' } @{$mA->{super_options}}), "noexec is preserved in raw super_options telemetry");

    # Fixture B: 'noexec' appears in per-mount options (field 6)
    my $file_mount_only = File::Spec->catfile($tmp_dir, 'mountinfo_mount_only');
    open(my $fhB, '>', $file_mount_only) or die "Cannot write: $!";
    print $fhB <<'EOF';
301 40 8:1 / /mnt/mount_noexec rw,noexec,relatime shared:31 - ext4 /dev/sda1 rw,data=ordered
EOF
    close($fhB);

    my ($mountsB, $errsB) = LSA::SecEng::HostMetrics::parse_mountinfo($file_mount_only);
    ok(!$errsB, "Parsed mount_only fixture without error");
    my $mB = $mountsB->[0];
    is($mB->{noexec}, JSON::PP::true, "Per-mount noexec is TRUE when noexec appears in per-mount options");
    is($mB->{flags}->{noexec}, JSON::PP::true, "Nested flags->noexec is TRUE when noexec in per-mount options");

    # Fixture C: 'nodev' and 'nosuid' appear only in superblock options vs per-mount options
    my $file_super_nodev = File::Spec->catfile($tmp_dir, 'mountinfo_super_nodev');
    open(my $fhC, '>', $file_super_nodev) or die "Cannot write: $!";
    print $fhC <<'EOF';
302 40 8:1 / /mnt/super_nodev rw,relatime shared:32 - ext4 /dev/sda1 rw,nodev,nosuid
EOF
    close($fhC);

    my ($mountsC, $errsC) = LSA::SecEng::HostMetrics::parse_mountinfo($file_super_nodev);
    ok(!$errsC, "Parsed super_nodev fixture without error");
    my $mC = $mountsC->[0];
    is($mC->{nodev}, JSON::PP::false, "nodev is FALSE when only in superblock options");
    is($mC->{nosuid}, JSON::PP::false, "nosuid is FALSE when only in superblock options");

    my $file_mount_nodev = File::Spec->catfile($tmp_dir, 'mountinfo_mount_nodev');
    open(my $fhD, '>', $file_mount_nodev) or die "Cannot write: $!";
    print $fhD <<'EOF';
303 40 8:1 / /mnt/mount_nodev rw,nodev,nosuid,relatime shared:33 - ext4 /dev/sda1 rw
EOF
    close($fhD);

    my ($mountsD, $errsD) = LSA::SecEng::HostMetrics::parse_mountinfo($file_mount_nodev);
    ok(!$errsD, "Parsed mount_nodev fixture without error");
    my $mD = $mountsD->[0];
    is($mD->{nodev}, JSON::PP::true, "nodev is TRUE when in per-mount options");
    is($mD->{nosuid}, JSON::PP::true, "nosuid is TRUE when in per-mount options");
}

# --- 9. FIX-02: Strict mountinfo field validation & fail-closed behavior ---
{
    # 9a. Non-numeric mount ID
    my $f_bad_id = File::Spec->catfile($tmp_dir, 'bad_mount_id');
    open(my $fh1, '>', $f_bad_id) or die "Cannot write: $!";
    print $fh1 "abc 40 0:27 / /dev/shm rw,nosuid,nodev - tmpfs tmpfs rw\n";
    close($fh1);
    my ($m1, $e1) = LSA::SecEng::HostMetrics::parse_mountinfo($f_bad_id);
    ok(!defined $m1, "Non-numeric mount ID rejected");
    like($e1->[0], qr/invalid numeric mount ID/, "Error flags invalid mount ID");

    # 9b. Non-numeric parent ID
    my $f_bad_parent = File::Spec->catfile($tmp_dir, 'bad_parent_id');
    open(my $fh2, '>', $f_bad_parent) or die "Cannot write: $!";
    print $fh2 "42 xyz 0:27 / /dev/shm rw,nosuid,nodev - tmpfs tmpfs rw\n";
    close($fh2);
    my ($m2, $e2) = LSA::SecEng::HostMetrics::parse_mountinfo($f_bad_parent);
    ok(!defined $m2, "Non-numeric parent ID rejected");
    like($e2->[0], qr/invalid numeric parent ID/, "Error flags invalid parent ID");

    # 9c. Invalid device identifier
    my $f_bad_dev = File::Spec->catfile($tmp_dir, 'bad_dev');
    open(my $fh3, '>', $f_bad_dev) or die "Cannot write: $!";
    print $fh3 "42 40 bad_dev_format / /dev/shm rw,nosuid,nodev - tmpfs tmpfs rw\n";
    close($fh3);
    my ($m3, $e3) = LSA::SecEng::HostMetrics::parse_mountinfo($f_bad_dev);
    ok(!defined $m3, "Invalid device format rejected");
    like($e3->[0], qr/invalid device identifier/, "Error flags invalid device identifier");

    # 9d. Invalid mount point (not starting with /)
    my $f_bad_mp = File::Spec->catfile($tmp_dir, 'bad_mp');
    open(my $fh4, '>', $f_bad_mp) or die "Cannot write: $!";
    print $fh4 "42 40 0:27 / relative_path rw,nosuid,nodev - tmpfs tmpfs rw\n";
    close($fh4);
    my ($m4, $e4) = LSA::SecEng::HostMetrics::parse_mountinfo($f_bad_mp);
    ok(!defined $m4, "Relative mount point rejected");
    like($e4->[0], qr/invalid mount point/, "Error flags invalid mount point");

    # 9e. Missing '-' separator
    my $f_no_sep = File::Spec->catfile($tmp_dir, 'no_sep');
    open(my $fh5, '>', $f_no_sep) or die "Cannot write: $!";
    print $fh5 "42 40 0:27 / /dev/shm rw,nosuid,nodev tmpfs tmpfs rw\n";
    close($fh5);
    my ($m5, $e5) = LSA::SecEng::HostMetrics::parse_mountinfo($f_no_sep);
    ok(!defined $m5, "Missing '-' separator rejected");
    like($e5->[0], qr/missing '-' separator/, "Error flags missing separator");

    # 9f. Truncated fields after '-' separator
    my $f_trunc = File::Spec->catfile($tmp_dir, 'trunc_after_sep');
    open(my $fh6, '>', $f_trunc) or die "Cannot write: $!";
    print $fh6 "42 40 0:27 / /dev/shm rw,nosuid,nodev - tmpfs\n";
    close($fh6);
    my ($m6, $e6) = LSA::SecEng::HostMetrics::parse_mountinfo($f_trunc);
    ok(!defined $m6, "Truncated fields after '-' separator rejected");
    like($e6->[0], qr/truncated fields after '-' separator/, "Error flags truncated fields");
}

# --- 10. Missing or unreadable input files ---
{
    my ($data_m, $err_m) = LSA::SecEng::HostMetrics::collect_host_metrics(
        meminfo_path   => "$tmp_dir/nonexistent_meminfo",
        loadavg_path   => "$tmp_dir/loadavg_valid",
        mountinfo_path => "$tmp_dir/mountinfo_std",
    );
    ok(!defined $data_m, "collect_host_metrics fails when meminfo is missing");
    is($err_m->{code}, 3, "Exit code is 3 for missing meminfo file");
    is($err_m->{status}, 'error', "Status is error for missing meminfo file");
    like($err_m->{errors}->[0], qr/does not exist/, "Error mentions missing file");

    my ($data_l, $err_l) = LSA::SecEng::HostMetrics::collect_host_metrics(
        meminfo_path   => "$tmp_dir/meminfo_valid",
        loadavg_path   => "$tmp_dir/nonexistent_loadavg",
        mountinfo_path => "$tmp_dir/mountinfo_std",
    );
    ok(!defined $data_l, "collect_host_metrics fails when loadavg is missing");
    is($err_l->{code}, 3, "Exit code is 3 for missing loadavg file");

    my ($data_mnt, $err_mnt) = LSA::SecEng::HostMetrics::collect_host_metrics(
        meminfo_path   => "$tmp_dir/meminfo_valid",
        loadavg_path   => "$tmp_dir/loadavg_valid",
        mountinfo_path => "$tmp_dir/nonexistent_mountinfo",
    );
    ok(!defined $data_mnt, "collect_host_metrics fails when mountinfo is missing");
    is($err_mnt->{code}, 3, "Exit code is 3 for missing mountinfo file");
}

# --- 11. Output envelope structure and full collection ---
{
    my ($data, $err) = LSA::SecEng::HostMetrics::collect_host_metrics(
        meminfo_path   => "$tmp_dir/meminfo_valid",
        loadavg_path   => "$tmp_dir/loadavg_valid",
        mountinfo_path => "$tmp_dir/mountinfo_std",
    );
    ok(!$err, "Full collection succeeded with valid fixtures");
    ok(defined $data, "Returned data payload");
    is($data->{mem_total_kib}, 16384000, "Top-level mem_total_kib present");
    is($data->{memory}->{mem_total_kib}, 16384000, "Nested memory->mem_total_kib present");
    cmp_ok($data->{load_1m}, '==', 0.42, "Top-level load_1m present");
    cmp_ok($data->{load_average}->{load_1m}, '==', 0.42, "Nested load_average->load_1m present");
    is($data->{mount_count}, 3, "mount_count matches array length");
    is(ref($data->{mounts}), 'ARRAY', "mounts is an array reference");
}

# --- 12. Correct CLI exit codes and live Linux smoke test ---
{
    # Optional live Linux smoke test
    if (-r '/proc/meminfo' && -r '/proc/loadavg' && -r '/proc/self/mountinfo') {
        my $cli_out = `$bin host-metrics --format json`;
        is($?, 0, "sec-cli host-metrics exits with 0 on live system");
        my $json = eval { JSON::PP->new->decode($cli_out) };
        ok(defined $json, "CLI output is valid JSON");
        is($json->{'$schema'}, 'https://lsa.security/schemas/sec-ops.v1.json', "Schema is sec-ops.v1.json");
        is($json->{schema_version}, '1.0.0', "schema_version is 1.0.0");
        is($json->{component}, 'sec-cli', "component is sec-cli");
        is($json->{command}, 'host-metrics', "command is host-metrics");
        is($json->{status}, 'success', "status is success");
        is($json->{exit_code}, 0, "exit_code is 0");
        ok($json->{data}->{mem_total_kib} > 0, "mem_total_kib is positive");
        ok($json->{data}->{mount_count} > 0, "mount_count is positive");

        # Text format output
        my $cli_text = `$bin host-metrics --format text`;
        is($?, 0, "sec-cli host-metrics --format text exits with 0");
        like($cli_text, qr/Memory \(KiB\):/, "Text output includes Memory header");
        like($cli_text, qr/Load Average:/, "Text output includes Load Average");
        like($cli_text, qr/Mounts \(\d+ total\):/, "Text output includes Mounts list");
    } else {
        pass("Skipping live /proc inspection: kernel interfaces not readable in test environment");
    }

    # Exit 2 on invalid usage (unexpected arguments)
    my $err_out = `$bin host-metrics unexpected_arg --format json 2>&1`;
    is($? >> 8, 2, "sec-cli host-metrics with extra arguments exits with code 2");
    my $err_json = eval { JSON::PP->new->decode($err_out) };
    is($err_json->{exit_code}, 2, "Error JSON exit_code is 2");
    is($err_json->{status}, 'error', "Error JSON status is error");
    like($err_json->{errors}->[0], qr/Unexpected extra argument: 'unexpected_arg'/, "Error message identifies unexpected argument");

    # Exit 2 on invalid format
    my $fmt_err = `$bin host-metrics --format yaml 2>&1`;
    is($? >> 8, 2, "sec-cli host-metrics with invalid format exits with code 2");
}

# --- 13. FIX-04: Existing commands remain fully compatible without network/DNS reliance ---
{
    # 1. hash
    my $h_out = `$bin hash $bin --format json`;
    is($?, 0, "sec-cli hash remains operational");

    # 2. dns usage (deterministic, no network call)
    my $d_usage = `$bin dns 2>&1`;
    is($? >> 8, 2, "sec-cli dns usage intact without network calls");

    # 3. log
    my $l_out = `$bin log "Sprint 04 telemetry test" --format json`;
    is($?, 0, "sec-cli log remains operational");

    # 4. tcp-check (usage, no network call)
    my $tcp_usage = `$bin tcp-check 2>&1`;
    is($? >> 8, 2, "sec-cli tcp-check usage intact without network calls");

    # 5. integrity-init (help/usage)
    my $init_usage = `$bin integrity-init 2>&1`;
    is($? >> 8, 2, "sec-cli integrity-init usage intact");

    # 6. integrity-verify (help/usage)
    my $ver_usage = `$bin integrity-verify 2>&1`;
    is($? >> 8, 2, "sec-cli integrity-verify usage intact");
}

done_testing();
