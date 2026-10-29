package LSA::SecEng::Hash;

use strict;
use warnings;
use Digest::SHA;
use Fcntl qw(:mode);
use JSON::PP;

our $VERSION = '1.0.0';
use constant CHUNK_SIZE => 65536; # 64 KB streaming buffer

sub hash_file {
    my (%args) = @_;
    my $path = $args{path};
    my $algo = lc($args{algo} || 'sha256');

    unless (defined $path && length($path)) {
        return (undef, { error => "File path cannot be empty", code => 2 });
    }

    unless ($algo eq 'sha256') {
        return (undef, { error => "Unsupported hashing algorithm: $algo. Only sha256 is supported.", code => 2 });
    }

    # Inspect path with lstat to examine symlink state without following immediately
    my @lstat_info = lstat($path);
    unless (@lstat_info) {
        return (undef, { error => "Cannot stat '$path': $!", code => 3 });
    }

    my $is_symlink = S_ISLNK($lstat_info[2]);
    my $symlink_target = undef;

    if ($is_symlink) {
        $symlink_target = readlink($path);
        unless (defined $symlink_target) {
            return (undef, { error => "Cannot read symlink '$path': $!", code => 3 });
        }
    }

    # Verify if target path is a directory
    if (-d $path) {
        return (undef, { error => "Cannot hash directory: '$path'", code => 2 });
    }

    # Check target stat
    my @initial_stat = stat($path);
    unless (@initial_stat) {
        return (undef, { error => "Cannot access target file '$path': $!", code => 3 });
    }

    my $initial_size  = $initial_stat[7];
    my $initial_mtime = $initial_stat[9];
    my $initial_mode  = sprintf("0%o", $initial_stat[2] & 07777);

    # Open file for raw binary streaming read
    my $fh;
    unless (open($fh, '<:raw', $path)) {
        return (undef, { error => "Cannot open file '$path': $!", code => 3 });
    }

    my $sha = Digest::SHA->new(256);
    my $bytes_read_total = 0;
    my $buffer;

    while (1) {
        my $read_bytes = sysread($fh, $buffer, CHUNK_SIZE);
        unless (defined $read_bytes) {
            my $err = $!;
            close($fh);
            return (undef, { error => "Error reading file '$path': $err", code => 3 });
        }
        last if $read_bytes == 0; # EOF

        $sha->add($buffer);
        $bytes_read_total += $read_bytes;
    }

    close($fh);

    # Post-read stat check to detect concurrent modification during reading
    my @final_stat = stat($path);
    my $modified_during_read = 0;
    if (@final_stat) {
        if ($final_stat[7] != $initial_size || $final_stat[9] != $initial_mtime) {
            $modified_during_read = 1;
        }
    }

    my $digest = $sha->hexdigest;

    my $result = {
        file_path            => $path,
        algorithm            => 'sha256',
        hash                 => $digest,
        size_bytes           => $bytes_read_total,
        mode                 => $initial_mode,
        modified_epoch       => $initial_mtime,
        is_symlink           => $is_symlink ? JSON::PP::true : JSON::PP::false,
        modified_during_read => $modified_during_read ? JSON::PP::true : JSON::PP::false,
    };

    if ($is_symlink && defined $symlink_target) {
        $result->{symlink_target} = $symlink_target;
    }

    if ($modified_during_read) {
        return ($result, { warning => "File was modified concurrently during read", code => 1 });
    }

    return ($result, undef);
}

1;
