package LSA::SecEng::HostMetrics;

use strict;
use warnings;
use JSON::PP;

our $VERSION = '1.0.0';

sub unescape_octal_path {
    my ($str) = @_;
    return '' unless defined $str;
    $str =~ s/\\([0-7]{3})/chr(oct($1))/eg;
    return $str;
}

sub parse_meminfo {
    my ($path) = @_;
    $path //= '/proc/meminfo';

    unless (-e $path) {
        return (undef, ["Memory information file does not exist: '$path'"]);
    }
    unless (-r $path) {
        return (undef, ["Memory information file is not readable: '$path'"]);
    }

    my $fh;
    unless (open($fh, '<', $path)) {
        return (undef, ["Cannot open '$path' for reading: $!"]);
    }

    my %raw_fields;
    my @errors;
    my $line_num = 0;

    while (my $line = <$fh>) {
        $line_num++;
        chomp $line;
        next if $line =~ /^\s*$/;

        if ($line =~ /^([A-Za-z0-9_()]+):\s*(.*)$/) {
            my $key = $1;
            my $rest = $2;

            # Only process keys of interest or store all
            if ($rest =~ /^([0-9]+)(?:\s+kB)?$/) {
                $raw_fields{$key} = int($1);
            } else {
                # If this is one of our required keys and the value is not digits:
                if ($key =~ /^(?:MemTotal|MemAvailable|MemFree|SwapTotal|SwapFree)$/) {
                    push @errors, "Malformed numeric value for '$key' at $path line $line_num: '$rest'";
                }
            }
        }
    }
    close($fh);

    if (@errors) {
        return (undef, \@errors);
    }

    my @required = qw(MemTotal MemAvailable MemFree SwapTotal SwapFree);
    for my $req (@required) {
        unless (exists $raw_fields{$req}) {
            push @errors, "Missing required memory field '$req' in '$path'";
        }
    }

    if (@errors) {
        return (undef, \@errors);
    }

    my $metrics = {
        mem_total_kib     => $raw_fields{MemTotal},
        mem_available_kib => $raw_fields{MemAvailable},
        mem_free_kib      => $raw_fields{MemFree},
        swap_total_kib    => $raw_fields{SwapTotal},
        swap_free_kib     => $raw_fields{SwapFree},
    };

    return ($metrics, undef);
}

sub parse_loadavg {
    my ($path) = @_;
    $path //= '/proc/loadavg';

    unless (-e $path) {
        return (undef, ["Load average file does not exist: '$path'"]);
    }
    unless (-r $path) {
        return (undef, ["Load average file is not readable: '$path'"]);
    }

    my $fh;
    unless (open($fh, '<', $path)) {
        return (undef, ["Cannot open '$path' for reading: $!"]);
    }

    my $line = <$fh>;
    close($fh);

    unless (defined $line && length($line)) {
        return (undef, ["Empty load average file: '$path'"]);
    }

    chomp $line;
    my @tokens = split /\s+/, $line;
    if (@tokens < 3) {
        return (undef, ["Malformed load average content in '$path': expected at least 3 fields, found " . scalar(@tokens)]);
    }

    my @errors;
    my @load_keys = qw(load_1m load_5m load_15m);
    my %loads;

    for my $i (0 .. 2) {
        my $val = $tokens[$i];
        if ($val =~ /^[0-9]+(?:\.[0-9]+)?$/) {
            $loads{$load_keys[$i]} = 0.0 + $val;
        } else {
            push @errors, "Malformed numeric value for $load_keys[$i] in '$path': '$val'";
        }
    }

    if (@errors) {
        return (undef, \@errors);
    }

    return (\%loads, undef);
}

sub parse_mountinfo {
    my ($path) = @_;
    $path //= '/proc/self/mountinfo';

    unless (-e $path) {
        return (undef, ["Mount information file does not exist: '$path'"]);
    }
    unless (-r $path) {
        return (undef, ["Mount information file is not readable: '$path'"]);
    }

    my $fh;
    unless (open($fh, '<', $path)) {
        return (undef, ["Cannot open '$path' for reading: $!"]);
    }

    my @mounts;
    my @errors;
    my $line_num = 0;

    while (my $line = <$fh>) {
        $line_num++;
        chomp $line;
        next if $line =~ /^\s*$/;

        my @tokens = split /\s+/, $line;
        if (@tokens < 7) {
            push @errors, "Malformed mountinfo line $line_num in '$path': expected at least 7 fields";
            next;
        }

        my $mount_id    = $tokens[0];
        my $parent_id   = $tokens[1];
        my $major_minor = $tokens[2];
        my $mount_root  = unescape_octal_path($tokens[3]);
        my $mount_point = unescape_octal_path($tokens[4]);
        my $mount_opts_raw = $tokens[5];

        # Find separator '-'
        my $sep_idx = 6;
        while ($sep_idx < @tokens && $tokens[$sep_idx] ne '-') {
            $sep_idx++;
        }

        if ($sep_idx >= @tokens || $sep_idx + 2 >= @tokens) {
            push @errors, "Malformed mountinfo line $line_num in '$path': missing '-' separator or filesystem fields";
            next;
        }

        my $fs_type      = $tokens[$sep_idx + 1];
        my $mount_source = unescape_octal_path($tokens[$sep_idx + 2]);
        my $super_opts_raw = ($sep_idx + 3 < @tokens) ? $tokens[$sep_idx + 3] : '';

        my @mount_opts = split /,/, $mount_opts_raw;
        my @super_opts = length($super_opts_raw) ? split(/,/, $super_opts_raw) : ();

        my %opts_set;
        for my $opt (@mount_opts, @super_opts) {
            $opts_set{$opt} = 1;
        }

        my $has_nodev  = exists $opts_set{nodev}  ? JSON::PP::true : JSON::PP::false;
        my $has_nosuid = exists $opts_set{nosuid} ? JSON::PP::true : JSON::PP::false;
        my $has_noexec = exists $opts_set{noexec} ? JSON::PP::true : JSON::PP::false;

        push @mounts, {
            mount_id        => $mount_id,
            parent_id       => $parent_id,
            major_minor     => $major_minor,
            mount_point     => $mount_point,
            filesystem_type => $fs_type,
            mount_source    => $mount_source,
            mount_root      => $mount_root,
            mount_options   => \@mount_opts,
            super_options   => \@super_opts,
            nodev           => $has_nodev,
            nosuid          => $has_nosuid,
            noexec          => $has_noexec,
            flags           => {
                nodev  => $has_nodev,
                nosuid => $has_nosuid,
                noexec => $has_noexec,
            },
            raw_entry       => $line,
        };
    }
    close($fh);

    if (@errors) {
        return (undef, \@errors);
    }

    unless (@mounts) {
        return (undef, ["No valid mount entries found in '$path'"]);
    }

    return (\@mounts, undef);
}

sub collect_host_metrics {
    my (%args) = @_;
    my $meminfo_path   = $args{meminfo_path}   // '/proc/meminfo';
    my $loadavg_path   = $args{loadavg_path}   // '/proc/loadavg';
    my $mountinfo_path = $args{mountinfo_path} // '/proc/self/mountinfo';

    my @all_errors;

    my ($mem_data, $mem_errs) = parse_meminfo($meminfo_path);
    if ($mem_errs) {
        push @all_errors, @$mem_errs;
    }

    my ($load_data, $load_errs) = parse_loadavg($loadavg_path);
    if ($load_errs) {
        push @all_errors, @$load_errs;
    }

    my ($mounts_data, $mount_errs) = parse_mountinfo($mountinfo_path);
    if ($mount_errs) {
        push @all_errors, @$mount_errs;
    }

    if (@all_errors) {
        return (
            undef,
            {
                error   => $all_errors[0],
                errors  => \@all_errors,
                code    => 3,
                status  => 'error',
            }
        );
    }

    my $data = {
        memory => $mem_data,
        mem_total_kib     => $mem_data->{mem_total_kib},
        mem_available_kib => $mem_data->{mem_available_kib},
        mem_free_kib      => $mem_data->{mem_free_kib},
        swap_total_kib    => $mem_data->{swap_total_kib},
        swap_free_kib     => $mem_data->{swap_free_kib},

        load_average => $load_data,
        load_1m      => $load_data->{load_1m},
        load_5m      => $load_data->{load_5m},
        load_15m     => $load_data->{load_15m},

        mounts      => $mounts_data,
        mount_count => scalar(@$mounts_data),
    };

    return ($data, undef);
}

1;
