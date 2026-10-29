package LSA::SecEng::Hash;

use strict;
use warnings;
use Digest::SHA;
use Fcntl qw(O_RDONLY O_NOFOLLOW O_NONBLOCK F_SETFD FD_CLOEXEC :mode);
use Errno qw(ELOOP);
use JSON::PP;

our $VERSION = '1.0.0';
use constant CHUNK_SIZE => 65536; # 64 KB streaming buffer

=head1 NAME

LSA::SecEng::Hash - Cryptographic File Hashing with Concurrency and Symlink Protections

=head1 SYMLINK AND RACE-CONDITION POLICY

Per Sprint 01 security baseline requirements, symbolic links are explicitly rejected.
To eliminate Time-of-Check to Time-of-Use (TOCTOU) race conditions between path inspection
and file opening:

1. Files are opened directly using C<sysopen> with atomic flags:
   C<O_RDONLY | O_NOFOLLOW | O_NONBLOCK>.
   On Linux and POSIX systems supporting C<O_NOFOLLOW>, attempting to open a symlink
   fails immediately at the system call boundary with C<ELOOP>, preventing symlink
   traversal races without requiring prior C<lstat> checks.
2. C<O_NONBLOCK> ensures opening special files (such as named pipes / FIFOs) does not block
   indefinitely waiting for a writer.
3. Close-on-exec (C<FD_CLOEXEC>) is enforced on the descriptor immediately upon opening.
4. Once opened, the file descriptor itself is validated via C<fstat> (Perl C<stat($fh)>).
   Directories (C<S_ISDIR>) and non-regular files (FIFOs, character/block devices, sockets)
   are rejected before any read operations occur.
5. Content is streamed into SHA-256 via C<sysread> on the verified descriptor.
6. A post-read C<fstat> check is performed on the same descriptor, comparing file size,
   modification time (mtime), device ID, and inode number against the pre-read metadata.
   If any property changed during reading, a concurrent modification warning is issued.

=head1 CONCURRENCY LIMITATIONS

While open-time no-follow, descriptor-based fstat validation, and pre/post-read stat comparisons
prevent symlink redirection and detect size/mtime modifications, callers must note:
- Operating systems do not guarantee file data block read atomicity across multi-chunk reads
  without exclusive mandatory filesystem locks (which are deprecated and fragile).
- Modifications in-place that preserve exact byte length and occur within the timestamp
  granularity of the filesystem (or where mtime is restored) cannot be detected by stat alone.
- Atomic snapshots require filesystem-level or volume-level snapshots (e.g. LVM/btrfs/ZFS).

=cut

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

    # Open-time no-follow and non-blocking open to eliminate TOCTOU races
    my $flags = O_RDONLY | O_NOFOLLOW | O_NONBLOCK;
    my $opened = sysopen(my $fh, $path, $flags);

    unless ($opened) {
        my $err_num = $!;
        if ($err_num == ELOOP) {
            return (undef, {
                error => "Cannot hash symlink '$path': symlinks are rejected by security policy",
                code  => 2,
            });
        }
        return (undef, {
            error => "Cannot open file '$path': $err_num",
            code  => 3,
        });
    }

    # Set close-on-exec on descriptor
    fcntl($fh, F_SETFD, FD_CLOEXEC);

    # Inspect file descriptor metadata directly via fstat
    my @initial_stat = stat($fh);
    unless (@initial_stat) {
        my $stat_err = $!;
        close($fh);
        return (undef, {
            error => "Cannot fstat opened file '$path': $stat_err",
            code  => 3,
        });
    }

    my $initial_dev   = $initial_stat[0];
    my $initial_ino   = $initial_stat[1];
    my $mode_val      = $initial_stat[2];
    my $initial_size  = $initial_stat[7];
    my $initial_mtime = $initial_stat[9];
    my $initial_mode  = sprintf("0%o", $mode_val & 07777);

    # Reject directories
    if (S_ISDIR($mode_val)) {
        close($fh);
        return (undef, {
            error => "Cannot hash directory: '$path'",
            code  => 2,
        });
    }

    # Reject non-regular files (FIFOs, devices, sockets)
    unless (S_ISREG($mode_val)) {
        close($fh);
        return (undef, {
            error => "Cannot hash non-regular file: '$path'",
            code  => 2,
        });
    }

    # Stream SHA-256 calculation directly from the verified file descriptor
    my $sha = Digest::SHA->new(256);
    my $bytes_read_total = 0;
    my $buffer;

    while (1) {
        my $read_bytes = sysread($fh, $buffer, CHUNK_SIZE);
        unless (defined $read_bytes) {
            my $read_err = $!;
            close($fh);
            return (undef, {
                error => "Error reading file '$path': $read_err",
                code  => 3,
            });
        }
        last if $read_bytes == 0; # EOF

        $sha->add($buffer);
        $bytes_read_total += $read_bytes;
    }

    # Optional test hook for deterministic concurrent modification simulation
    if ($args{_post_read_hook}) {
        $args{_post_read_hook}->($fh, $path);
    }

    # Post-read stat check on the same descriptor
    my @final_stat = stat($fh);
    my $modified_during_read = 0;

    if (@final_stat) {
        if ($final_stat[0] != $initial_dev ||
            $final_stat[1] != $initial_ino ||
            $final_stat[7] != $initial_size ||
            $final_stat[9] != $initial_mtime) {
            $modified_during_read = 1;
        }
    } else {
        $modified_during_read = 1;
    }

    # Close file handle and check for close error
    unless (close($fh)) {
        my $close_err = $!;
        return (undef, {
            error => "Error closing file '$path': $close_err",
            code  => 3,
        });
    }

    my $digest = $sha->hexdigest;

    my $result = {
        file_path            => $path,
        algorithm            => 'sha256',
        hash                 => $digest,
        size_bytes           => $bytes_read_total,
        mode                 => $initial_mode,
        modified_epoch       => $initial_mtime,
        modified_during_read => $modified_during_read ? JSON::PP::true : JSON::PP::false,
    };

    if ($modified_during_read) {
        return ($result, {
            warning => "File was modified concurrently during read",
            code    => 1,
        });
    }

    return ($result, undef);
}

1;
