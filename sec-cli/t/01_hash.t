use strict;
use warnings;
use Test::More;
use File::Basename qw(dirname);
use File::Spec;
use File::Temp qw(tempdir tempfile);

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
like($err_dir->{error}, qr/Cannot hash directory/, "Directory rejection error message");

# 6. Missing file
my ($res_miss, $err_miss) = LSA::SecEng::Hash::hash_file(path => File::Spec->catfile($tmpdir, 'missing_file.xyz'));
is($res_miss, undef, "Missing file returns error");
is($err_miss->{code}, 3, "Missing file returns exit code 3");

# 7. Symlink behavior
my $symlink_file = File::Spec->catfile($tmpdir, 'link_to_abc.txt');
eval { symlink($abc_file, $symlink_file) };
if (-l $symlink_file) {
    my ($res_sym, $err_sym) = LSA::SecEng::Hash::hash_file(path => $symlink_file);
    ok(defined $res_sym, "Symlink to file hashes target successfully");
    is($res_sym->{hash}, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', "Symlink hash matches target hash");
} else {
    pass("Symlinks not supported in environment");
    pass("Symlinks not supported in environment");
}

done_testing();
