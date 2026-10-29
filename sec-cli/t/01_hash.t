use strict;
use warnings;
use Test::More;
use File::Basename qw(dirname);
use File::Spec;
use File::Temp qw(tempdir);
use POSIX qw(mkfifo);
use JSON::PP;

my $t_dir = dirname(File::Spec->rel2abs(__FILE__));
my $lib_dir = File::Spec->catdir($t_dir, '..', 'lib');
unshift @INC, $lib_dir;

require_ok('LSA::SecEng::Hash');

my $tmpdir = tempdir(CLEANUP => 1);

# 1. NIST Test Vector 1: Empty file
my $empty_file = File::Spec->catfile($tmpdir, 'empty.txt');
open(my $fh1, '>:raw', $empty_file) or die "Cannot create $empty_file: $!";
close($fh1);

my ($res1, $err1) = LSA::SecEng::Hash::hash_file(path => $empty_file);
ok(defined $res1, "Hash empty file succeeds");
is($err1, undef, "No error on empty file");
is($res1->{hash}, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', "SHA-256 of empty file matches NIST vector");
is($res1->{size_bytes}, 0, "Empty file size is 0 bytes");

# 2. NIST Test Vector 2: "abc"
my $abc_file = File::Spec->catfile($tmpdir, 'abc.txt');
open(my $fh2, '>:raw', $abc_file) or die "Cannot create $abc_file: $!";
print $fh2 "abc";
close($fh2);

my ($res2, $err2) = LSA::SecEng::Hash::hash_file(path => $abc_file);
ok(defined $res2, "Hash 'abc' file succeeds");
is($res2->{hash}, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', "SHA-256 of 'abc' matches NIST vector");
is($res2->{size_bytes}, 3, "Size of 'abc' is 3 bytes");

# 3. Binary file
my $bin_file = File::Spec->catfile($tmpdir, 'binary.bin');
open(my $fh3, '>:raw', $bin_file) or die "Cannot create $bin_file: $!";
for my $b (0 .. 255) {
    print $fh3 chr($b);
}
close($fh3);

my ($res3, $err3) = LSA::SecEng::Hash::hash_file(path => $bin_file);
ok(defined $res3, "Hash binary file succeeds");
is($res3->{size_bytes}, 256, "Binary file size is 256 bytes");

# 4. Large file processed incrementally (> 64 KB chunk size)
my $large_file = File::Spec->catfile($tmpdir, 'large.bin');
open(my $fh4, '>:raw', $large_file) or die "Cannot create $large_file: $!";
my $chunk = "A" x 65536; # 64 KB
for (1 .. 4) { # 256 KB total = 4 chunks
    print $fh4 $chunk;
}
close($fh4);

my ($res4, $err4) = LSA::SecEng::Hash::hash_file(path => $large_file);
ok(defined $res4, "Hash 256KB file across multiple streaming chunks succeeds");
is($res4->{size_bytes}, 262144, "Large file size is 262144 bytes");

# 5. Reject directory
my ($res_dir, $err_dir) = LSA::SecEng::Hash::hash_file(path => $tmpdir);
is($res_dir, undef, "Directory hashing rejected");
is($err_dir->{code}, 2, "Directory rejection returns exit code 2");
like($err_dir->{error}, qr/Cannot hash directory/, "Directory rejection error message");

# 6. Missing file
my ($res_miss, $err_miss) = LSA::SecEng::Hash::hash_file(path => File::Spec->catfile($tmpdir, 'missing_file.xyz'));
is($res_miss, undef, "Missing file returns error");
is($err_miss->{code}, 3, "Missing file returns exit code 3");

# 7. Symlink rejection policy (Sprint 01A FIX-02)
my $symlink_file = File::Spec->catfile($tmpdir, 'link_to_abc.txt');
eval { symlink($abc_file, $symlink_file) };
SKIP: {
    skip "Symlink creation unsupported on host", 3 unless -l $symlink_file;
    my ($res_sym, $err_sym) = LSA::SecEng::Hash::hash_file(path => $symlink_file);
    is($res_sym, undef, "Symlink is rejected per security policy");
    is($err_sym->{code}, 2, "Symlink rejection returns exit code 2");
    like($err_sym->{error}, qr/symlink/i, "Symlink error explains policy rejection");
}

# 8. Broken symlink rejection
my $broken_symlink = File::Spec->catfile($tmpdir, 'broken_link.txt');
eval { symlink(File::Spec->catfile($tmpdir, 'nonexistent_target.txt'), $broken_symlink) };
SKIP: {
    skip "Broken symlink creation unsupported on host", 2 unless -l $broken_symlink;
    my ($res_bsym, $err_bsym) = LSA::SecEng::Hash::hash_file(path => $broken_symlink);
    is($res_bsym, undef, "Broken symlink is rejected");
    is($err_bsym->{code}, 2, "Broken symlink rejection returns exit code 2");
}

# 9. Non-regular file rejection: FIFO (Named Pipe)
my $fifo_path = File::Spec->catfile($tmpdir, 'test_fifo.pipe');
my $fifo_created = eval { POSIX::mkfifo($fifo_path, 0600) };
SKIP: {
    skip "FIFO creation unsupported on host", 3 unless $fifo_created && -p $fifo_path;
    my ($res_fifo, $err_fifo) = LSA::SecEng::Hash::hash_file(path => $fifo_path);
    is($res_fifo, undef, "FIFO hashing rejected without blocking");
    is($err_fifo->{code}, 2, "FIFO rejection returns exit code 2");
    like($err_fifo->{error}, qr/non-regular file/, "FIFO rejected as non-regular file");
}

# 10. Non-regular file rejection: Character device
if (-c '/dev/null') {
    my ($res_dev, $err_dev) = LSA::SecEng::Hash::hash_file(path => '/dev/null');
    is($res_dev, undef, "Character device /dev/null rejected");
    is($err_dev->{code}, 2, "Character device rejection returns exit code 2");
}

# 11. Concurrent modification detection during reading
my $concur_file = File::Spec->catfile($tmpdir, 'concur.txt');
open(my $fhc, '>:raw', $concur_file) or die "Cannot create $concur_file: $!";
print $fhc "initial content";
close($fhc);

my ($res_concur, $err_concur) = LSA::SecEng::Hash::hash_file(
    path => $concur_file,
    _post_read_hook => sub {
        my ($fh_open, $fpath) = @_;
        # Modify file size concurrently while open handle exists
        open(my $append_fh, '>>:raw', $fpath) or die "Cannot append: $!";
        print $append_fh " - concurrently appended bytes";
        close($append_fh);
    },
);

ok(defined $res_concur, "Hash result returned with warning on concurrent modification");
ok(defined $err_concur, "Warning info returned");
is($err_concur->{code}, 1, "Exit code 1 returned on concurrent modification");
like($err_concur->{warning}, qr/modified concurrently/, "Warning message explains modification");
is($res_concur->{modified_during_read}, JSON::PP::true, "modified_during_read flag is true");

# 12. Sprint 01B FIX-03: Deterministic descriptor setup failure (fcntl FD_CLOEXEC failure)
my ($res_fcntl_fail, $err_fcntl_fail) = LSA::SecEng::Hash::hash_file(
    path      => $empty_file,
    _fcntl_fn => sub {
        $! = POSIX::EINVAL;
        return 0; # Simulate fcntl failure
    },
);

is($res_fcntl_fail, undef, "Descriptor setup failure returns undef result");
ok(defined $err_fcntl_fail, "Descriptor setup failure returns error info");
is($err_fcntl_fail->{code}, 3, "Descriptor setup failure returns environmental error code 3");
like($err_fcntl_fail->{error}, qr/Failed to set FD_CLOEXEC/, "Error explains FD_CLOEXEC failure");

done_testing();
