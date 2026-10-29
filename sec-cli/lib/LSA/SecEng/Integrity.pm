package LSA::SecEng::Integrity;

use strict;
use warnings;
use Cwd qw(realpath);
use Digest::SHA qw(sha256_hex);
use Errno qw(ELOOP EEXIST ENOENT EACCES EPERM EIO);
use Fcntl qw(O_RDONLY O_WRONLY O_CREAT O_EXCL O_NOFOLLOW O_NONBLOCK :mode);
use File::Basename qw(dirname basename);
use File::Spec;
use IO::Handle;
use JSON::PP;
use POSIX qw(:errno_h);

use LSA::SecEng::Hash;
use LSA::SecEng::Logger;

our $VERSION = '1.0.0';

use constant MAX_RECURSION_DEPTH       => 64;
use constant MAX_TOTAL_FILES           => 100_000;
use constant DEFAULT_MAX_BASELINE_SIZE => 50 * 1024 * 1024; # 50 MB
use constant MAX_BASELINE_ENTRIES      => 100_000;

=head1 NAME

LSA::SecEng::Integrity - File Integrity Auditing and Baseline Verification

=head1 ARCHITECTURAL & SECURITY CONTEXT

This module implements read-only file integrity inventory (C<init_baseline>) and
reference verification (C<verify_baseline>) for the Security Engineering CLI.

=head2 SECURITY CONTROLS & ASSUMPTIONS

1. B<Read-Only Inspection:> Audited directories and files are never modified.
2. B<Symlink Safety Policy (FIX-02, FIX-04):> Directory symlinks are never followed
   during traversal or hashing to prevent filesystem cycles and escapes. Symlinks
   in the target tree are explicitly tracked with their identity and link target,
   and compared deterministically across baseline and live filesystem state.
   External symlink targets are never scanned, and broken symlinks within the
   audited tree are recorded consistently without dereferencing.
3. B<Containment Verification:> The baseline output file cannot be placed inside
   the audited tree, preventing self-referential baseline poisoning and feedback loops.
4. B<Incomplete Baseline Protection (FIX-01):> Baselines are never written, published,
   or overwritten if any traversal error, unreadable path, cycle, or concurrent
   modification occurs during inventory. The entire snapshot must be 100% complete.
5. B<Atomic No-Replace Publication & Durability (FIX-03, FIX-04):> Baselines are written
   to an exclusive temporary file in the destination directory with restrictive permissions
   (0600), flushed and synchronized to hardware storage using descriptor synchronization
   (C<IO::Handle::sync()>), and published using atomic no-replace link(2). If the destination
   already exists and --force is not specified, publication fails without truncating the
   pre-existing file. Destination directory entries are synchronized where supported.
   If file synchronization fails, publication aborts and temporary files are unlinked.
6. B<Directory Traversal Race Protection (FIX-03, FIX-04):> Traversal verifies directory
   descriptors (fstat on dirhandle vs lstat on path) to detect replacement races, fails closed
   if dev/ino mismatches, and enforces directory containment.
7. B<Bounded Baseline Input & Strict Schema (FIX-05):> Verification opens baseline files using
   O_NOFOLLOW | O_NONBLOCK, validates descriptor metadata via fstat, enforces a 50MB size limit
   and 100k entry limit, validates mandatory header fields including nonnegative integer file_count
   matching the files array length, validates symlinks array, enforces unique path identities
   across entry types, and rejects non-canonical or traversal paths (e.g. '.', '..', empty components).
8. B<Verification Correctness & Incomplete Scan Rejection (FIX-01, FIX-06):> Every inspection failure,
   unsupported non-regular file (FIFO/socket), or inaccessible directory is incorporated as an
   explicit ERROR finding. Verification summary counts strictly match emitted findings. If any
   inspection error occurs, verification returns exit code 3 and never exit code 0.

=head1 KNOWN LIMITATIONS

A baseline is a cryptographic integrity reference, not proof that the initial system
state was untampered or secure. Users must protect stored baseline files with external
integrity mechanisms (e.g. read-only mounts, digital signatures, or remote storage).
Under POSIX without kernel-level atomic path resolution (such as openat2 RESOLVE_NO_SYMLINKS),
userland path traversal cannot completely eliminate theoretical TOCTOU races between path
inspection and descriptor acquisition. The engine minimizes this window via O_NOFOLLOW | O_NONBLOCK,
descriptor verification (fstat on opendir handles and file handles), and fails closed upon
detecting any discrepancy. Furthermore, crash durability across power loss requires filesystem
and hardware support for fsync on both files and directories; if directory fsync is unsupported
by the underlying filesystem, atomic publication succeeds but durable directory entry persistence
cannot be guaranteed.

=cut

sub is_path_inside_directory {
    my ($file_path, $dir_path) = @_;

    my $real_dir = realpath($dir_path);
    return 0 unless defined $real_dir;

    my $parent = dirname($file_path);
    my $real_parent = realpath($parent);
    return 0 unless defined $real_parent;

    my $real_file = -l $file_path ? undef : realpath($file_path);
    my $check_path = defined $real_file
        ? $real_file
        : File::Spec->catfile($real_parent, basename($file_path));

    if ($check_path eq $real_dir) {
        return 1;
    }

    my $prefix = $real_dir;
    $prefix .= '/' unless $prefix =~ m{/$};
    if (index($check_path, $prefix) == 0) {
        return 1;
    }

    return 0;
}

sub validate_relative_path {
    my ($path) = @_;

    return 0 unless defined $path && length($path);
    return 0 if $path =~ /\0/;
    return 0 if $path =~ m{^/};                     # Absolute UNIX path
    return 0 if $path =~ m{^[a-zA-Z]:};             # Windows drive letter
    return 0 if $path =~ m{\\\\};                   # Double backslash
    return 0 if $path =~ m{^/|/$};                  # Leading or trailing slash
    return 0 if $path =~ m{^\s|\s$};                # Leading or trailing whitespace
    return 0 if $path =~ m{//};                     # Empty path components (double slashes)

    # Check each path segment: reject '.', '..', or empty segments
    my @segments = split(m{/}, $path, -1);
    return 0 unless @segments;
    for my $seg (@segments) {
        return 0 if length($seg) == 0;
        return 0 if $seg eq '.';
        return 0 if $seg eq '..';
    }

    return 1;
}

sub _scan_directory {
    my (%args) = @_;
    my $root_dir       = $args{root_dir};
    my $current_dir    = $args{current_dir};
    my $depth          = $args{depth} || 0;
    my $visited_dirs   = $args{visited_dirs};
    my $files_list     = $args{files_list};
    my $symlinks_list  = $args{symlinks_list};
    my $errors_list    = $args{errors_list};
    my $inaccessible_subtrees = $args{inaccessible_subtrees};
    my $state          = $args{state};

    if ($depth > MAX_RECURSION_DEPTH) {
        push @$errors_list, {
            path  => $current_dir,
            error => "Maximum recursion depth exceeded (" . MAX_RECURSION_DEPTH . ")",
        };
        $inaccessible_subtrees->{$current_dir} = "Maximum recursion depth exceeded";
        return;
    }

    my @dir_lstat = lstat($current_dir);
    unless (@dir_lstat) {
        my $err = $!;
        push @$errors_list, {
            path  => $current_dir,
            error => "Cannot lstat directory: $err",
        };
        $inaccessible_subtrees->{$current_dir} = "Cannot lstat directory: $err";
        return;
    }

    # Anti-Symlink Traversal: Never follow directory symlinks
    if (S_ISLNK($dir_lstat[2])) {
        push @$errors_list, {
            path  => $current_dir,
            error => "Directory path is a symbolic link (symlink traversal prohibited)",
        };
        $inaccessible_subtrees->{$current_dir} = "Directory path is a symbolic link";
        return;
    }

    unless (S_ISDIR($dir_lstat[2])) {
        push @$errors_list, {
            path  => $current_dir,
            error => "Path is not a directory",
        };
        $inaccessible_subtrees->{$current_dir} = "Path is not a directory";
        return;
    }

    my $dir_key = "$dir_lstat[0]:$dir_lstat[1]";
    if ($visited_dirs->{$dir_key}) {
        push @$errors_list, {
            path  => $current_dir,
            error => "Directory loop detected (already visited inode $dir_lstat[1])",
        };
        $inaccessible_subtrees->{$current_dir} = "Directory loop detected";
        return;
    }
    $visited_dirs->{$dir_key} = 1;
    $state->{directories_scanned}++;

    my $dh;
    unless (opendir($dh, $current_dir)) {
        my $err = $!;
        push @$errors_list, {
            path  => $current_dir,
            error => "Cannot open directory: $err",
        };
        $inaccessible_subtrees->{$current_dir} = "Cannot open directory: $err";
        return;
    }

    # Anti-TOCTOU Check: Verify opened directory handle against pre-checked lstat metadata
    my @dh_stat = stat($dh);
    if (!@dh_stat || $dh_stat[0] != $dir_lstat[0] || $dh_stat[1] != $dir_lstat[1]) {
        closedir($dh);
        push @$errors_list, {
            path  => $current_dir,
            error => "Directory replacement detected during traversal (descriptor mismatch)",
        };
        $inaccessible_subtrees->{$current_dir} = "Directory replacement detected";
        return;
    }

    my @entries = grep { $_ ne '.' && $_ ne '..' } readdir($dh);
    closedir($dh);

    # Deterministic alphabetical ordering
    @entries = sort @entries;

    for my $entry (@entries) {
        my $child_path = File::Spec->catfile($current_dir, $entry);
        my $rel_path   = File::Spec->abs2rel($child_path, $root_dir);
        $rel_path =~ s{\\}{/}g; # Normalize path separator

        my @child_stat = lstat($child_path);
        unless (@child_stat) {
            my $err = $!;
            push @$errors_list, {
                path  => $child_path,
                error => "Cannot lstat entry: $err",
            };
            next;
        }

        my $mode = $child_stat[2];

        if (S_ISLNK($mode)) {
            # FIX-02, FIX-04: Explicitly track symlinks without following.
            # External targets and broken symlinks are recorded by identity and target string.
            my $target = readlink($child_path);
            unless (defined $target) {
                my $err = $!;
                push @$errors_list, {
                    path  => $child_path,
                    error => "Cannot readlink symbolic link: $err",
                };
                next;
            }
            push @$symlinks_list, {
                path           => $rel_path,
                symlink_target => $target,
                mode           => sprintf("0%o", $mode & 07777),
                mtime_epoch    => int($child_stat[9]),
            };
            next;
        } elsif (S_ISDIR($mode)) {
            # Ensure subdirectory does not escape root boundary before descending
            my $canon_child = realpath($child_path);
            unless (defined $canon_child && (index($canon_child, $root_dir . '/') == 0 || $canon_child eq $root_dir)) {
                push @$errors_list, {
                    path  => $child_path,
                    error => "Directory traversal escaped root boundary: '$child_path'",
                };
                $inaccessible_subtrees->{$child_path} = "Directory escaped root boundary";
                next;
            }

            _scan_directory(
                root_dir              => $root_dir,
                current_dir           => $child_path,
                depth                 => $depth + 1,
                visited_dirs          => $visited_dirs,
                files_list            => $files_list,
                symlinks_list         => $symlinks_list,
                errors_list           => $errors_list,
                inaccessible_subtrees => $inaccessible_subtrees,
                state                 => $state,
            );
        } elsif (S_ISREG($mode)) {
            if (@$files_list >= MAX_TOTAL_FILES) {
                push @$errors_list, {
                    path  => $child_path,
                    error => "Maximum file inventory limit exceeded (" . MAX_TOTAL_FILES . ")",
                };
                last;
            }

            my ($hash_res, $hash_err) = LSA::SecEng::Hash::hash_file(path => $child_path);

            if ($hash_err && !$hash_err->{warning}) {
                push @$errors_list, {
                    path  => $child_path,
                    error => $hash_err->{error} || "Failed to hash file",
                };
                next;
            }

            if ($hash_err && $hash_err->{warning}) {
                $state->{concurrent_modifications}++;
            }

            push @$files_list, {
                path        => $rel_path,
                sha256      => $hash_res->{hash},
                size_bytes  => int($hash_res->{size_bytes}),
                mode        => $hash_res->{mode},
                mtime_epoch => int($hash_res->{modified_epoch}),
            };
        } else {
            # Non-regular file (FIFO, socket, device node) - unsupported
            push @$errors_list, {
                path  => $child_path,
                error => "Unsupported non-regular file encountered (FIFO/device/socket)",
            };
            next;
        }
    }
}

sub init_baseline {
    my (%args) = @_;
    my $target_dir  = $args{directory};
    my $output_file = $args{output};
    my $force       = $args{force} || 0;

    unless (defined $target_dir && length($target_dir)) {
        return (undef, { error => "Target directory cannot be empty", code => 2 });
    }

    unless (-e $target_dir) {
        return (undef, { error => "Target directory does not exist: '$target_dir'", code => 2 });
    }

    unless (-d $target_dir) {
        return (undef, { error => "Target path is not a directory: '$target_dir'", code => 2 });
    }

    my $canon_target = realpath($target_dir);
    unless (defined $canon_target) {
        return (undef, { error => "Failed to resolve canonical path for '$target_dir': $!", code => 3 });
    }

    unless (defined $output_file && length($output_file)) {
        return (undef, { error => "Output baseline path cannot be empty (use --output <file>)", code => 2 });
    }

    # Validate output destination directory
    my $out_dir = dirname($output_file);
    unless (-d $out_dir) {
        return (undef, { error => "Output directory does not exist: '$out_dir'", code => 2 });
    }

    my $canon_out_dir = realpath($out_dir);
    unless (defined $canon_out_dir) {
        return (undef, { error => "Failed to resolve canonical output directory '$out_dir': $!", code => 3 });
    }

    # Security Control: Reject output file located inside audited tree
    if (is_path_inside_directory($output_file, $canon_target)) {
        return (undef, {
            error => "Output baseline file cannot be located inside the audited directory tree",
            code  => 2,
        });
    }

    # Security Control: Reject symbolic link output destinations (FIX-04)
    if (-l $output_file) {
        return (undef, {
            error => "Output baseline destination cannot be a symbolic link: '$output_file'",
            code  => 2,
        });
    }

    # Security Control: Do not silently overwrite existing baselines without --force
    if (-e $output_file && !$force) {
        return (undef, {
            error => "Output baseline file already exists: '$output_file'. Overwriting is not permitted without explicit --force.",
            code  => 2,
        });
    }

    my @files;
    my @symlinks;
    my @errors;
    my %visited;
    my %inaccessible_subtrees;
    my %state = (
        directories_scanned      => 0,
        concurrent_modifications => 0,
    );

    # Allow test injection of scan errors
    if ($args{_inject_scan_error}) {
        push @errors, { path => $canon_target, error => $args{_inject_scan_error} };
    }

    _scan_directory(
        root_dir              => $canon_target,
        current_dir           => $canon_target,
        depth                 => 0,
        visited_dirs          => \%visited,
        files_list            => \@files,
        symlinks_list         => \@symlinks,
        errors_list           => \@errors,
        inaccessible_subtrees => \%inaccessible_subtrees,
        state                 => \%state,
    );

    # FIX-01 (CRITICAL): Never publish an incomplete baseline!
    # Validate entire inventory completeness BEFORE creating, writing, or publishing.
    if (@errors) {
        my @err_msgs = map { "$_->{path}: $_->{error}" } @errors;
        return (
            {
                target_directory    => $canon_target,
                output_file         => $output_file,
                files_indexed       => scalar(@files),
                directories_scanned => $state{directories_scanned},
                inaccessible_count  => scalar(@errors),
            },
            {
                error  => "Cannot publish incomplete baseline: encountered " . scalar(@errors) . " inspection error(s)",
                code   => 3,
                status => 'error',
                errors => \@err_msgs,
            }
        );
    }

    if ($state{concurrent_modifications} > 0) {
        return (
            {
                target_directory    => $canon_target,
                output_file         => $output_file,
                files_indexed       => scalar(@files),
                directories_scanned => $state{directories_scanned},
                inaccessible_count  => 0,
            },
            {
                error  => "Cannot publish baseline: " . $state{concurrent_modifications} . " file(s) modified concurrently during inventory",
                code   => 1,
                status => 'warning',
                errors => ["Concurrent file modification detected during inventory"],
            }
        );
    }

    # Stable alphabetical ordering by relative path
    @files    = sort { $a->{path} cmp $b->{path} } @files;
    @symlinks = sort { $a->{path} cmp $b->{path} } @symlinks;

    my $baseline_data = {
        '$schema'          => 'https://lsa.security/schemas/integrity-baseline.v1.json',
        schema_version    => '1.0.0',
        generator         => 'sec-cli',
        generated_at      => LSA::SecEng::Logger::get_iso_timestamp(),
        target_directory  => $canon_target,
        file_count        => scalar(@files),
        files             => \@files,
        symlinks          => \@symlinks,
    };

    my $coder = JSON::PP->new->utf8->canonical->pretty(1);
    my $json_bytes = eval { $coder->encode($baseline_data) };
    if ($@ || !defined $json_bytes) {
        return (undef, { error => "Failed to serialize baseline JSON: $@", code => 3 });
    }

    # FIX-04: Atomic write to temporary file in destination directory with permissions 0600
    my $tmp_filename = File::Spec->catfile(
        $canon_out_dir,
        sprintf(".tmp.baseline.%d.%d.%d.json", $$, int(time()), int(rand(1000000)))
    );

    my $opened = sysopen(my $tmp_fh, $tmp_filename, O_WRONLY | O_CREAT | O_EXCL, 0600);
    unless ($opened) {
        return (undef, { error => "Cannot create temporary baseline file '$tmp_filename': $!", code => 3 });
    }

    my $written = print $tmp_fh $json_bytes;
    unless ($written) {
        my $err = $!;
        close($tmp_fh);
        unlink($tmp_filename);
        return (undef, { error => "Failed to write baseline content: $err", code => 3 });
    }

    # FIX-03: Crash durability synchronization using IO::Handle::sync()
    if ($args{_inject_fsync_fail}) {
        close($tmp_fh);
        unlink($tmp_filename);
        return (undef, {
            error => "File synchronization (fsync) failed for temporary baseline: Injected I/O error",
            code  => 3,
        });
    }

    my $sync_res = eval { $tmp_fh->sync() };
    my $sync_err = $@ || $!;
    if ($@ || !$sync_res) {
        close($tmp_fh);
        unlink($tmp_filename);
        return (undef, {
            error => "File synchronization (fsync) failed for temporary baseline: $sync_err",
            code  => 3,
        });
    }

    unless (close($tmp_fh)) {
        my $err = $!;
        unlink($tmp_filename);
        return (undef, { error => "Failed to close temporary baseline file: $err", code => 3 });
    }

    # Calculate digest of the written baseline file
    my $baseline_digest = sha256_hex($json_bytes);

    # FIX-04: Atomic publication without silent overwrite race
    if ($force) {
        unless (rename($tmp_filename, $output_file)) {
            my $err = $!;
            unlink($tmp_filename);
            return (undef, { error => "Atomic rename to '$output_file' failed: $err", code => 3 });
        }
    } else {
        # POSIX link() guarantees kernel-atomic publication that fails with EEXIST if destination exists
        my $linked = link($tmp_filename, $output_file);
        my $link_err = $!;
        unlink($tmp_filename); # Unlink temp regardless of outcome

        unless ($linked) {
            if ($link_err == EEXIST) {
                return (undef, {
                    error => "Atomic publication collision: target file '$output_file' already exists. Publication aborted to protect existing baseline.",
                    code  => 2,
                });
            } else {
                return (undef, {
                    error => "Atomic publication via link() to '$output_file' failed: $link_err",
                    code  => 3,
                });
            }
        }
    }

    # FIX-03: Attempt directory synchronization for durable namespace entry
    my $dir_synced = 0;
    my $dir_sync_warning = undef;
    if ($args{_inject_dir_fsync_fail}) {
        $dir_sync_warning = "Directory synchronization failed: Injected directory sync failure";
    } else {
        if (sysopen(my $dir_fh, $canon_out_dir, O_RDONLY)) {
            my $d_res = eval { $dir_fh->sync() };
            if ($d_res) {
                $dir_synced = 1;
            } else {
                my $d_err = $@ || $!;
                $dir_sync_warning = "Directory synchronization not supported by filesystem or failed: $d_err";
            }
            close($dir_fh);
        } else {
            $dir_sync_warning = "Cannot open directory for synchronization: $!";
        }
    }

    my $result_payload = {
        target_directory    => $canon_target,
        output_file         => $output_file,
        baseline_sha256     => $baseline_digest,
        files_indexed       => scalar(@files),
        symlinks_indexed    => scalar(@symlinks),
        directories_scanned => $state{directories_scanned},
        inaccessible_count  => 0,
        durability          => {
            file_synced      => JSON::PP::true,
            directory_synced => $dir_synced ? JSON::PP::true : JSON::PP::false,
            atomic_published => JSON::PP::true,
        },
    };
    if (defined $dir_sync_warning) {
        $result_payload->{durability}->{directory_warning} = $dir_sync_warning;
    }

    return ($result_payload, undef);
}

sub verify_baseline {
    my (%args) = @_;
    my $target_dir    = $args{directory};
    my $baseline_file = $args{baseline};
    my $max_size      = $args{_max_baseline_size} || DEFAULT_MAX_BASELINE_SIZE;

    unless (defined $target_dir && length($target_dir)) {
        return (undef, { error => "Target directory cannot be empty", code => 2 });
    }

    unless (-e $target_dir) {
        return (undef, { error => "Target directory does not exist: '$target_dir'", code => 2 });
    }

    unless (-d $target_dir) {
        return (undef, { error => "Target path is not a directory: '$target_dir'", code => 2 });
    }

    my $canon_target = realpath($target_dir);
    unless (defined $canon_target) {
        return (undef, { error => "Failed to resolve canonical path for '$target_dir': $!", code => 3 });
    }

    unless (defined $baseline_file && length($baseline_file)) {
        return (undef, { error => "Baseline file path cannot be empty (use --baseline <file>)", code => 2 });
    }

    # FIX-05: Use no-follow opening for baseline file
    my $opened = sysopen(my $bfh, $baseline_file, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    unless ($opened) {
        my $err_no = $!;
        if ($err_no == ELOOP) {
            return (undef, { error => "Baseline file cannot be a symbolic link: '$baseline_file'", code => 2 });
        }
        if ($err_no == ENOENT) {
            return (undef, { error => "Baseline file does not exist: '$baseline_file'", code => 2 });
        }
        return (undef, { error => "Cannot open baseline file '$baseline_file': $err_no", code => 3 });
    }

    # FIX-05: Verify metadata on opened file descriptor
    my @bst = stat($bfh);
    unless (@bst) {
        my $err = $!;
        close($bfh);
        return (undef, { error => "Cannot fstat baseline descriptor: $err", code => 3 });
    }

    unless (S_ISREG($bst[2])) {
        close($bfh);
        return (undef, { error => "Baseline path is not a regular file: '$baseline_file'", code => 2 });
    }

    # FIX-05: Enforce documented maximum baseline size
    if ($bst[7] > $max_size) {
        close($bfh);
        return (undef, {
            error => "Baseline file size ($bst[7] bytes) exceeds maximum permitted limit ($max_size bytes)",
            code  => 2,
        });
    }

    # Read bounded content from descriptor
    my $baseline_raw = "";
    my $buf;
    while (1) {
        my $bytes = sysread($bfh, $buf, 65536);
        unless (defined $bytes) {
            my $err = $!;
            close($bfh);
            return (undef, { error => "Error reading baseline file '$baseline_file': $err", code => 3 });
        }
        last if $bytes == 0;
        $baseline_raw .= $buf;
        if (length($baseline_raw) > $max_size) {
            close($bfh);
            return (undef, { error => "Baseline content exceeds maximum permitted size", code => 2 });
        }
    }
    close($bfh);

    my $baseline_digest = sha256_hex($baseline_raw);
    my $parsed_baseline = eval { JSON::PP->new->utf8->decode($baseline_raw) };
    if ($@ || ref($parsed_baseline) ne 'HASH') {
        return (undef, { error => "Malformed baseline JSON in '$baseline_file': $@", code => 2 });
    }

    # FIX-05: Mandatory baseline fields
    for my $req_field (qw(schema_version target_directory file_count files)) {
        unless (exists $parsed_baseline->{$req_field} && defined $parsed_baseline->{$req_field}) {
            return (undef, {
                error => "Baseline document missing mandatory field: '$req_field'",
                code  => 2,
            });
        }
    }

    # FIX-05: Reject unsupported schema versions
    my $schema_version = $parsed_baseline->{schema_version};
    unless ($schema_version eq '1.0.0') {
        return (undef, {
            error => "Unsupported baseline schema version: $schema_version",
            code  => 2,
        });
    }

    my $baseline_files = $parsed_baseline->{files};
    unless (ref($baseline_files) eq 'ARRAY') {
        return (undef, { error => "Baseline document 'files' must be an array", code => 2 });
    }

    my $baseline_symlinks = $parsed_baseline->{symlinks} || [];
    unless (ref($baseline_symlinks) eq 'ARRAY') {
        return (undef, { error => "Baseline document 'symlinks' must be an array", code => 2 });
    }

    # FIX-05: Verify file_count is a nonnegative integer matching files array length exactly
    my $declared_count = $parsed_baseline->{file_count};
    unless (defined $declared_count && "$declared_count" =~ /^\d+$/ && $declared_count >= 0) {
        return (undef, {
            error => "Malformed file_count in baseline header: must be a nonnegative integer",
            code  => 2,
        });
    }
    if (int($declared_count) != scalar(@$baseline_files)) {
        return (undef, {
            error => "Baseline header file_count mismatch: declared $declared_count but contains " . scalar(@$baseline_files) . " entries",
            code  => 2,
        });
    }

    # FIX-05: Reject excessive entry counts
    if (scalar(@$baseline_files) > MAX_BASELINE_ENTRIES) {
        return (undef, {
            error => "Baseline contains excessive files exceeding limit (" . MAX_BASELINE_ENTRIES . ")",
            code  => 2,
        });
    }
    if (scalar(@$baseline_symlinks) > MAX_BASELINE_ENTRIES) {
        return (undef, {
            error => "Baseline contains excessive symlinks exceeding limit (" . MAX_BASELINE_ENTRIES . ")",
            code  => 2,
        });
    }

    # Validate baseline entries, reject non-canonical / traversal paths, reject duplicates across types
    my %baseline_files_map;
    my %baseline_symlinks_map;
    my %all_baseline_identities;

    for my $b_entry (@$baseline_files) {
        unless (ref($b_entry) eq 'HASH') {
            return (undef, { error => "Invalid baseline file entry: must be an object", code => 2 });
        }

        my $p = $b_entry->{path};
        unless (validate_relative_path($p)) {
            return (undef, { error => "Invalid or unsafe path entry in baseline files: " . ($p // 'undef'), code => 2 });
        }

        if (exists $all_baseline_identities{$p}) {
            return (undef, { error => "Duplicate path entry in baseline: '$p'", code => 2 });
        }

        # Validate entry metadata types and ranges
        unless (defined $b_entry->{sha256} && $b_entry->{sha256} =~ /^[0-9a-f]{64}$/i) {
            return (undef, { error => "Malformed SHA-256 digest in baseline for '$p'", code => 2 });
        }

        unless (defined $b_entry->{size_bytes} && "$b_entry->{size_bytes}" =~ /^\d+$/ && int($b_entry->{size_bytes}) >= 0) {
            return (undef, { error => "Malformed or negative size_bytes in baseline for '$p'", code => 2 });
        }

        unless (defined $b_entry->{mode} && $b_entry->{mode} =~ /^0[0-7]{3,4}$/) {
            return (undef, { error => "Malformed octal permission mode in baseline for '$p': '$b_entry->{mode}'", code => 2 });
        }

        $all_baseline_identities{$p} = 'file';
        $baseline_files_map{$p}      = $b_entry;
    }

    for my $s_entry (@$baseline_symlinks) {
        unless (ref($s_entry) eq 'HASH') {
            return (undef, { error => "Invalid baseline symlink entry: must be an object", code => 2 });
        }

        my $p = $s_entry->{path};
        unless (validate_relative_path($p)) {
            return (undef, { error => "Invalid or unsafe path entry in baseline symlinks: " . ($p // 'undef'), code => 2 });
        }

        if (exists $all_baseline_identities{$p}) {
            return (undef, {
                error => "Duplicate path identity across baseline entry types: '$p' already defined as $all_baseline_identities{$p}",
                code  => 2,
            });
        }

        unless (defined $s_entry->{symlink_target}) {
            return (undef, { error => "Missing symlink_target in baseline symlinks for '$p'", code => 2 });
        }

        if (defined $s_entry->{mode} && $s_entry->{mode} !~ /^0[0-7]{3,4}$/) {
            return (undef, { error => "Malformed octal permission mode in baseline symlinks for '$p': '$s_entry->{mode}'", code => 2 });
        }

        $all_baseline_identities{$p}   = 'symlink';
        $baseline_symlinks_map{$p}     = $s_entry;
    }

    # Inventory current filesystem state
    my @current_files;
    my @current_symlinks;
    my @scan_errors;
    my %visited;
    my %inaccessible_subtrees;
    my %state = (
        directories_scanned      => 0,
        concurrent_modifications => 0,
    );

    # Allow test injection of scan errors
    if ($args{_inject_scan_error}) {
        push @scan_errors, { path => $canon_target, error => $args{_inject_scan_error} };
    }

    _scan_directory(
        root_dir              => $canon_target,
        current_dir           => $canon_target,
        depth                 => 0,
        visited_dirs          => \%visited,
        files_list            => \@current_files,
        symlinks_list         => \@current_symlinks,
        errors_list           => \@scan_errors,
        inaccessible_subtrees => \%inaccessible_subtrees,
        state                 => \%state,
    );

    # Map scan errors by normalized relative path (FIX-01)
    my %scan_errors_by_path;
    for my $err_item (@scan_errors) {
        my $raw_p = $err_item->{path};
        my $rel_p = File::Spec->abs2rel($raw_p, $canon_target);
        $rel_p =~ s{\\}{/}g;
        $rel_p = '.' if $rel_p eq '' || $rel_p eq File::Spec->curdir();
        if (exists $scan_errors_by_path{$rel_p}) {
            $scan_errors_by_path{$rel_p} .= "; " . $err_item->{error};
        } else {
            $scan_errors_by_path{$rel_p} = $err_item->{error};
        }
    }

    my %current_files_map    = map { $_->{path} => $_ } @current_files;
    my %current_symlinks_map = map { $_->{path} => $_ } @current_symlinks;

    # Collect all unique paths across baseline, live filesystem, and scan errors
    my %all_paths = map { $_ => 1 } (
        keys %baseline_files_map,
        keys %baseline_symlinks_map,
        keys %current_files_map,
        keys %current_symlinks_map,
        keys %scan_errors_by_path,
    );
    my @sorted_paths = sort keys %all_paths;
    my @findings;

    my %summary = (
        unchanged => 0,
        modified  => 0,
        added     => 0,
        removed   => 0,
        error     => 0,
    );

    # Helper: Check if path falls under an inaccessible subtree (FIX-06)
    my sub is_path_under_inaccessible_subtree {
        my ($rel_path) = @_;
        my $abs_path = File::Spec->catfile($canon_target, $rel_path);
        for my $inacc_dir (keys %inaccessible_subtrees) {
            my $prefix = $inacc_dir;
            $prefix .= '/' unless $prefix =~ m{/$};
            if ($abs_path eq $inacc_dir || index($abs_path, $prefix) == 0) {
                return $inaccessible_subtrees{$inacc_dir};
            }
        }
        return undef;
    };

    for my $path (@sorted_paths) {
        # FIX-01: Explicit scan error for this specific path
        if (exists $scan_errors_by_path{$path}) {
            $summary{error}++;
            push @findings, {
                path   => $path,
                status => 'ERROR',
                error  => $scan_errors_by_path{$path},
            };
            next;
        }

        my $in_base_file = exists $baseline_files_map{$path};
        my $in_base_sym  = exists $baseline_symlinks_map{$path};
        my $in_curr_reg  = exists $current_files_map{$path};
        my $in_curr_sym  = exists $current_symlinks_map{$path};

        # FIX-06: Check if path falls within an inaccessible directory subtree
        my $inacc_reason = is_path_under_inaccessible_subtree($path);
        if ($inacc_reason && !$in_curr_reg && !$in_curr_sym) {
            # Inaccessible subtree prevented inspection: report as ERROR, NEVER as false REMOVED!
            $summary{error}++;
            push @findings, {
                path   => $path,
                status => 'ERROR',
                error  => "Inspection prevented by inaccessible ancestor directory: $inacc_reason",
            };
            next;
        }

        if ($in_base_file && $in_curr_reg) {
            my $b = $baseline_files_map{$path};
            my $c = $current_files_map{$path};

            my $hash_diff = lc($b->{sha256}) ne lc($c->{sha256});
            my $size_diff = int($b->{size_bytes}) != int($c->{size_bytes});
            my $mode_diff = (defined $b->{mode} && defined $c->{mode}) && ($b->{mode} ne $c->{mode});

            if (!$hash_diff && !$size_diff && !$mode_diff) {
                $summary{unchanged}++;
                push @findings, {
                    path   => $path,
                    status => 'UNCHANGED',
                    sha256 => $c->{sha256},
                };
            } else {
                $summary{modified}++;
                my $details = {};
                if ($hash_diff) {
                    $details->{sha256_baseline} = $b->{sha256};
                    $details->{sha256_current}  = $c->{sha256};
                }
                if ($size_diff) {
                    $details->{size_baseline} = int($b->{size_bytes});
                    $details->{size_current}  = int($c->{size_bytes});
                }
                if ($mode_diff) {
                    $details->{mode_baseline} = $b->{mode};
                    $details->{mode_current}  = $c->{mode};
                }
                push @findings, {
                    path    => $path,
                    status  => 'MODIFIED',
                    details => $details,
                };
            }
        } elsif ($in_base_sym && $in_curr_sym) {
            # FIX-02: Compare symlinks deterministically
            my $b_sym = $baseline_symlinks_map{$path};
            my $c_sym = $current_symlinks_map{$path};

            if ($b_sym->{symlink_target} eq $c_sym->{symlink_target}) {
                $summary{unchanged}++;
                push @findings, {
                    path           => $path,
                    status         => 'UNCHANGED',
                    type           => 'symlink',
                    symlink_target => $c_sym->{symlink_target},
                };
            } else {
                $summary{modified}++;
                push @findings, {
                    path    => $path,
                    status  => 'MODIFIED',
                    details => {
                        type            => 'symlink',
                        target_baseline => $b_sym->{symlink_target},
                        target_current  => $c_sym->{symlink_target},
                    },
                };
            }
        } elsif ($in_base_file && $in_curr_sym) {
            # FIX-02: Regular file replaced by a symbolic link
            $summary{modified}++;
            push @findings, {
                path    => $path,
                status  => 'MODIFIED',
                details => {
                    type_change    => "Regular file replaced by symbolic link",
                    symlink_target => $current_symlinks_map{$path}->{symlink_target},
                },
            };
        } elsif ($in_base_sym && $in_curr_reg) {
            # FIX-02: Symbolic link replaced by a regular file
            $summary{modified}++;
            push @findings, {
                path    => $path,
                status  => 'MODIFIED',
                details => {
                    type_change => "Symbolic link replaced by regular file",
                    sha256      => $current_files_map{$path}->{sha256},
                },
            };
        } elsif (!$in_base_file && !$in_base_sym && $in_curr_reg) {
            $summary{added}++;
            my $c = $current_files_map{$path};
            push @findings, {
                path    => $path,
                status  => 'ADDED',
                details => {
                    sha256     => $c->{sha256},
                    size_bytes => int($c->{size_bytes}),
                    mode       => $c->{mode},
                },
            };
        } elsif (!$in_base_file && !$in_base_sym && $in_curr_sym) {
            # FIX-02: Newly added symbolic link detected
            $summary{added}++;
            push @findings, {
                path    => $path,
                status  => 'ADDED',
                details => {
                    type           => "symlink",
                    symlink_target => $current_symlinks_map{$path}->{symlink_target},
                },
            };
        } elsif (($in_base_file || $in_base_sym) && !$in_curr_reg && !$in_curr_sym) {
            # Path in baseline but absent from both live regular files and live symlinks.
            my $full_child = File::Spec->catfile($canon_target, $path);
            my @st = lstat($full_child);

            if (!@st) {
                my $err_no = $!;
                if ($err_no == ENOENT) {
                    $summary{removed}++;
                    push @findings, {
                        path   => $path,
                        status => 'REMOVED',
                        ($in_base_sym ? (type => 'symlink') : ()),
                    };
                } else {
                    # Permission error or I/O failure (EACCES/EPERM): report ERROR, not REMOVED
                    $summary{error}++;
                    push @findings, {
                        path   => $path,
                        status => 'ERROR',
                        error  => "Cannot access path ($err_no): $!",
                    };
                }
            } else {
                # Special non-regular file replaced regular file or symlink
                $summary{error}++;
                push @findings, {
                    path   => $path,
                    status => 'ERROR',
                    error  => "Baseline entry replaced on filesystem by unsupported non-regular file",
                };
            }
        }
    }

    # FIX-06: Incorporate concurrent modifications into errors / findings
    if ($state{concurrent_modifications} > 0) {
        $summary{error}++;
        push @findings, {
            path   => '.',
            status => 'ERROR',
            error  => "Concurrent file modification detected during verification inventory (" . $state{concurrent_modifications} . " warnings)",
        };
    }

    # Sort all findings deterministically by relative path
    @findings = sort { $a->{path} cmp $b->{path} } @findings;

    my $report_data = {
        target_directory        => $canon_target,
        baseline_file           => $baseline_file,
        baseline_sha256         => $baseline_digest,
        total_baseline_files    => scalar(keys %baseline_files_map),
        total_baseline_symlinks => scalar(keys %baseline_symlinks_map),
        total_current_files     => scalar(@current_files),
        total_current_symlinks  => scalar(@current_symlinks),
        summary                 => \%summary,
        findings                => \@findings,
    };

    # Exit code determination:
    # 3: Inspection or environmental failure (errors > 0). Never exit 0 when completeness compromised.
    # 1: Verification completed, differences detected (modified, added, removed).
    # 0: Verification completed, zero differences.
    if ($summary{error} > 0) {
        return ($report_data, {
            error  => "Verification encountered " . $summary{error} . " inspection error(s)",
            code   => 3,
            status => 'error',
        });
    }

    if ($summary{modified} > 0 || $summary{added} > 0 || $summary{removed} > 0) {
        return ($report_data, {
            warning => sprintf(
                "Integrity differences detected: %d modified, %d added, %d removed",
                $summary{modified},
                $summary{added},
                $summary{removed}
            ),
            code    => 1,
            status  => 'warning',
        });
    }

    return ($report_data, undef);
}

1;
