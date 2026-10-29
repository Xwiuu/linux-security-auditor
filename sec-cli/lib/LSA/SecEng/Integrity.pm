package LSA::SecEng::Integrity;

use strict;
use warnings;
use Cwd qw(realpath);
use Digest::SHA qw(sha256_hex);
use Fcntl qw(O_WRONLY O_CREAT O_EXCL :mode);
use File::Basename qw(dirname basename);
use File::Spec;
use JSON::PP;

use LSA::SecEng::Hash;
use LSA::SecEng::Logger;

our $VERSION = '1.0.0';

use constant MAX_RECURSION_DEPTH => 64;
use constant MAX_TOTAL_FILES     => 100_000;

=head1 NAME

LSA::SecEng::Integrity - File Integrity Auditing and Baseline Verification

=head1 ARCHITECTURAL & SECURITY CONTEXT

This module implements read-only file integrity inventory (C<init_baseline>) and
reference verification (C<verify_baseline>) for the Security Engineering CLI.

=head2 SECURITY CONTROLS & ASSUMPTIONS

1. B<Read-Only Inspection:> Audited directories and files are never modified.
2. B<Symlink Rejection Policy:> Directory symlinks are never followed to avoid
   directory traversal escapes and filesystem cycles. Symlinks encountered in
   the target tree are rejected from the regular-file baseline.
3. B<Containment Verification:> The baseline output file cannot be placed inside
   the audited tree, preventing self-referential baseline poisoning and feedback loops.
4. B<Atomic Baseline Output:> Baselines are written to an exclusive temporary file
   in the output directory with restrictive permissions (0600) and atomically renamed.
   Overwriting existing baselines is rejected by default to prevent silent truncation.
5. B<TOCTOU & Race Condition Protections:> File hashing utilizes descriptor-based
   C<O_NOFOLLOW | O_NONBLOCK> opens via LSA::SecEng::Hash with pre/post stat comparisons.
6. B<Recursion Limits:> Directory depth is bounded to 64 levels and total file inventory
   is bounded to 100,000 files, guarding against cyclic mounts and algorithmic DoS.
7. B<Path Traversal Guard:> Baseline file verification validates every relative path,
   rejecting absolute paths, directory traversal sequences (C<../>), and null bytes.
8. B<Deterministic Order:> File inventories and comparison findings are strictly sorted
   lexicographically by normalized relative path.

=head1 KNOWN LIMITATIONS

A baseline is a cryptographic integrity reference, not proof that the initial system
state was untampered or secure. Users must protect stored baseline files with external
integrity mechanisms (e.g. read-only mounts, digital signatures, or remote storage).
Filesystem operations without volume-level snapshots remain subject to concurrent modification.

=cut

sub is_path_inside_directory {
    my ($file_path, $dir_path) = @_;

    my $real_dir = realpath($dir_path);
    return 0 unless defined $real_dir;

    my $parent = dirname($file_path);
    my $real_parent = realpath($parent);
    return 0 unless defined $real_parent;

    my $real_file = realpath($file_path);
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
    return 0 if $path =~ m{^/};
    return 0 if $path =~ m{^[a-zA-Z]:}; # Windows drive letter guard
    return 0 if $path =~ m{(^|/)\.\.(/|$)}; # Directory traversal guard
    return 0 if $path =~ m{\\\\};
    return 1;
}

sub _scan_directory {
    my (%args) = @_;
    my $root_dir       = $args{root_dir};
    my $current_dir    = $args{current_dir};
    my $depth          = $args{depth} || 0;
    my $visited_dirs   = $args{visited_dirs};
    my $files_list     = $args{files_list};
    my $errors_list    = $args{errors_list};
    my $state          = $args{state};

    if ($depth > MAX_RECURSION_DEPTH) {
        push @$errors_list, {
            path  => $current_dir,
            error => "Maximum recursion depth exceeded (" . MAX_RECURSION_DEPTH . ")",
        };
        return;
    }

    my @dir_stat = lstat($current_dir);
    unless (@dir_stat) {
        push @$errors_list, {
            path  => $current_dir,
            error => "Cannot lstat directory: $!",
        };
        return;
    }

    my $dir_key = "$dir_stat[0]:$dir_stat[1]";
    if ($visited_dirs->{$dir_key}) {
        push @$errors_list, {
            path  => $current_dir,
            error => "Directory loop detected (already visited inode $dir_stat[1])",
        };
        return;
    }
    $visited_dirs->{$dir_key} = 1;
    $state->{directories_scanned}++;

    my $dh;
    unless (opendir($dh, $current_dir)) {
        push @$errors_list, {
            path  => $current_dir,
            error => "Cannot open directory: $!",
        };
        return;
    }

    my @entries = grep { $_ ne '.' && $_ ne '..' } readdir($dh);
    closedir($dh);

    # Deterministic alphabetical ordering
    @entries = sort @entries;

    for my $entry (@entries) {
        my $child_path = File::Spec->catfile($current_dir, $entry);
        my @child_stat = lstat($child_path);

        unless (@child_stat) {
            push @$errors_list, {
                path  => $child_path,
                error => "Cannot stat entry: $!",
            };
            next;
        }

        my $mode = $child_stat[2];

        if (S_ISLNK($mode)) {
            # Rejection policy: never follow symlinks
            next;
        } elsif (S_ISDIR($mode)) {
            _scan_directory(
                root_dir     => $root_dir,
                current_dir  => $child_path,
                depth        => $depth + 1,
                visited_dirs => $visited_dirs,
                files_list   => $files_list,
                errors_list  => $errors_list,
                state        => $state,
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

            my $rel_path = File::Spec->abs2rel($child_path, $root_dir);
            $rel_path =~ s{\\}{/}g; # Normalize path separator

            push @$files_list, {
                path        => $rel_path,
                sha256      => $hash_res->{hash},
                size_bytes  => int($hash_res->{size_bytes}),
                mode        => $hash_res->{mode},
                mtime_epoch => int($hash_res->{modified_epoch}),
            };
        } else {
            # Skip non-regular files (FIFOs, sockets, device nodes)
            next;
        }
    }
}

sub init_baseline {
    my (%args) = @_;
    my $target_dir = $args{directory};
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

    # Security Control: Do not silently overwrite existing baselines
    if (-e $output_file && !$force) {
        return (undef, {
            error => "Output baseline file already exists: '$output_file'. Overwriting is not permitted without explicit force.",
            code  => 2,
        });
    }

    my @files;
    my @errors;
    my %visited;
    my %state = (
        directories_scanned      => 0,
        concurrent_modifications => 0,
    );

    _scan_directory(
        root_dir     => $canon_target,
        current_dir  => $canon_target,
        depth        => 0,
        visited_dirs => \%visited,
        files_list   => \@files,
        errors_list  => \@errors,
        state        => \%state,
    );

    # Stable alphabetical ordering by relative path
    @files = sort { $a->{path} cmp $b->{path} } @files;

    my $baseline_data = {
        '$schema'          => 'https://lsa.security/schemas/integrity-baseline.v1.json',
        schema_version    => '1.0.0',
        generator         => 'sec-cli',
        generated_at      => LSA::SecEng::Logger::get_iso_timestamp(),
        target_directory  => $canon_target,
        file_count        => scalar(@files),
        files             => \@files,
    };

    my $coder = JSON::PP->new->utf8->canonical->pretty(1);
    my $json_bytes = eval { $coder->encode($baseline_data) };
    if ($@ || !defined $json_bytes) {
        return (undef, { error => "Failed to serialize baseline JSON: $@", code => 3 });
    }

    # Atomic write to temporary file in the destination directory with permissions 0600
    my $tmp_filename = File::Spec->catfile(
        $canon_out_dir,
        sprintf(".tmp.baseline.%d.%d.json", $$, int(rand(1000000)))
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

    unless (close($tmp_fh)) {
        my $err = $!;
        unlink($tmp_filename);
        return (undef, { error => "Failed to close temporary baseline file: $err", code => 3 });
    }

    # Calculate digest of the written baseline file
    my $baseline_digest = sha256_hex($json_bytes);

    # Atomic rename into final output path
    unless (rename($tmp_filename, $output_file)) {
        my $err = $!;
        unlink($tmp_filename);
        return (undef, { error => "Atomic rename to '$output_file' failed: $err", code => 3 });
    }

    my $result_payload = {
        target_directory    => $canon_target,
        output_file         => $output_file,
        baseline_sha256     => $baseline_digest,
        files_indexed       => scalar(@files),
        directories_scanned => $state{directories_scanned},
        inaccessible_count  => scalar(@errors),
    };

    if (@errors) {
        my @err_msgs = map { "$_->{path}: $_->{error}" } @errors;
        return ($result_payload, {
            error  => "Baseline created with partial scan errors (" . scalar(@errors) . " inaccessible)",
            code   => 3,
            status => 'error',
            errors => \@err_msgs,
        });
    }

    if ($state{concurrent_modifications} > 0) {
        return ($result_payload, {
            warning => "Files were modified concurrently during inventory (" . $state{concurrent_modifications} . " warnings)",
            code    => 1,
            status  => 'warning',
        });
    }

    return ($result_payload, undef);
}

sub verify_baseline {
    my (%args) = @_;
    my $target_dir    = $args{directory};
    my $baseline_file = $args{baseline};

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

    unless (-e $baseline_file) {
        return (undef, { error => "Baseline file does not exist: '$baseline_file'", code => 2 });
    }

    if (-l $baseline_file) {
        return (undef, { error => "Baseline file cannot be a symbolic link: '$baseline_file'", code => 2 });
    }

    unless (-f $baseline_file) {
        return (undef, { error => "Baseline path is not a regular file: '$baseline_file'", code => 2 });
    }

    # Read and parse baseline JSON
    my $baseline_raw = do {
        open(my $bfh, '<:raw', $baseline_file)
            or return (undef, { error => "Cannot open baseline file '$baseline_file': $!", code => 3 });
        local $/;
        <$bfh>;
    };

    my $baseline_digest = sha256_hex($baseline_raw);
    my $parsed_baseline = eval { JSON::PP->new->utf8->decode($baseline_raw) };
    if ($@ || ref($parsed_baseline) ne 'HASH') {
        return (undef, { error => "Malformed baseline JSON in '$baseline_file': $@", code => 2 });
    }

    my $schema_version = $parsed_baseline->{schema_version};
    unless (defined $schema_version && $schema_version eq '1.0.0') {
        return (undef, {
            error => "Unsupported baseline schema version: " . ($schema_version // 'missing'),
            code  => 2,
        });
    }

    my $baseline_files = $parsed_baseline->{files};
    unless (defined $baseline_files && ref($baseline_files) eq 'ARRAY') {
        return (undef, { error => "Baseline document missing 'files' array", code => 2 });
    }

    # Validate baseline entries and check for path traversal / duplicates
    my %baseline_map;
    for my $b_entry (@$baseline_files) {
        unless (ref($b_entry) eq 'HASH') {
            return (undef, { error => "Invalid baseline file entry: must be an object", code => 2 });
        }

        my $p = $b_entry->{path};
        unless (validate_relative_path($p)) {
            return (undef, { error => "Invalid or unsafe path entry in baseline: '$p'", code => 2 });
        }

        if (exists $baseline_map{$p}) {
            return (undef, { error => "Duplicate path entry in baseline: '$p'", code => 2 });
        }

        unless (defined $b_entry->{sha256} && $b_entry->{sha256} =~ /^[0-9a-f]{64}$/i) {
            return (undef, { error => "Malformed SHA-256 digest in baseline for '$p'", code => 2 });
        }

        $baseline_map{$p} = $b_entry;
    }

    # Inventory current filesystem state
    my @current_files;
    my @scan_errors;
    my %visited;
    my %state = (
        directories_scanned      => 0,
        concurrent_modifications => 0,
    );

    _scan_directory(
        root_dir     => $canon_target,
        current_dir  => $canon_target,
        depth        => 0,
        visited_dirs => \%visited,
        files_list   => \@current_files,
        errors_list  => \@scan_errors,
        state        => \%state,
    );

    my %current_map;
    for my $c (@current_files) {
        $current_map{$c->{path}} = $c;
    }

    # Compare baseline against current tree
    my %all_paths = map { $_ => 1 } (keys %baseline_map, keys %current_map);
    my @sorted_paths = sort keys %all_paths;
    my @findings;

    my %summary = (
        unchanged => 0,
        modified  => 0,
        added     => 0,
        removed   => 0,
        error     => 0,
    );

    for my $path (@sorted_paths) {
        my $in_base = exists $baseline_map{$path};
        my $in_curr = exists $current_map{$path};

        if ($in_base && $in_curr) {
            my $b = $baseline_map{$path};
            my $c = $current_map{$path};

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
        } elsif (!$in_base && $in_curr) {
            $summary{added}++;
            my $c = $current_map{$path};
            push @findings, {
                path    => $path,
                status  => 'ADDED',
                details => {
                    sha256     => $c->{sha256},
                    size_bytes => int($c->{size_bytes}),
                    mode       => $c->{mode},
                },
            };
        } elsif ($in_base && !$in_curr) {
            # File existed in baseline but not in regular current map.
            # Inspect actual filesystem path to distinguish removal from permission error / symlink replacement.
            my $full_child = File::Spec->catfile($canon_target, $path);
            my @st = lstat($full_child);

            if (!@st) {
                my $err_no = $!;
                # Use Errno to detect genuine non-existence vs permission error
                if ($err_no == POSIX::ENOENT) {
                    $summary{removed}++;
                    push @findings, {
                        path   => $path,
                        status => 'REMOVED',
                    };
                } else {
                    $summary{error}++;
                    push @findings, {
                        path   => $path,
                        status => 'ERROR',
                        error  => "Inspection failed ($err_no): Cannot access path",
                    };
                }
            } else {
                # Path exists on filesystem, but was not in current regular file map!
                if (S_ISLNK($st[2])) {
                    $summary{modified}++;
                    push @findings, {
                        path    => $path,
                        status  => 'MODIFIED',
                        details => {
                            type_change => "Regular file replaced by symbolic link",
                        },
                    };
                } else {
                    $summary{error}++;
                    push @findings, {
                        path   => $path,
                        status => 'ERROR',
                        error  => "Regular file replaced by unsupported non-regular file",
                    };
                }
            }
        }
    }

    # Record any filesystem scan errors that prevented inspection
    for my $se (@scan_errors) {
        $summary{error}++;
        push @findings, {
            path   => $se->{path},
            status => 'ERROR',
            error  => $se->{error},
        };
    }

    # Sort all findings deterministically by relative path
    @findings = sort { $a->{path} cmp $b->{path} } @findings;

    my $report_data = {
        target_directory     => $canon_target,
        baseline_file        => $baseline_file,
        baseline_sha256      => $baseline_digest,
        total_baseline_files => scalar(keys %baseline_map),
        total_current_files  => scalar(@current_files),
        summary              => \%summary,
        findings             => \@findings,
    };

    # Determine exit code according to strict requirements:
    # 0: Verification completed, no differences and no errors.
    # 1: Verification completed, differences detected (added, removed, modified).
    # 3: Inspection or environmental failure (errors > 0). Never exit 0 on partial inspection.
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
