package LSA::SecEng::DNS;

use strict;
use warnings;
use Socket qw(getaddrinfo getnameinfo NI_NUMERICHOST SOCK_STREAM AF_UNSPEC);
use Time::HiRes qw(time);

our $VERSION = '1.0.0';

=head1 NAME

LSA::SecEng::DNS - Native DNS Resolution with Input Validation

=head1 RESOLVER TIMEOUT LIMITATIONS

Under POSIX systems and glibc, C<getaddrinfo> is a synchronous blocking system
resolver library call. While an application-level timer via C<alarm> and
C<$SIG{ALRM}> is configured, POSIX/C library resolver implementations may
defer signal delivery or block in kernel socket calls during network resolution.
Consequently, application timeout requests cannot guarantee a hard deadline
across all operating environments without asynchronous low-level resolver
subsystems. This limitation is explicitly acknowledged per strict YAGNI.

=cut

sub validate_hostname {
    my ($hostname) = @_;

    return 0 unless defined $hostname && length($hostname);
    return 0 if length($hostname) > 253;

    # Check for disallowed characters
    return 0 unless $hostname =~ /^[a-zA-Z0-9.-]+$/;

    # No consecutive dots or leading/trailing dots
    return 0 if $hostname =~ /\.\./;
    return 0 if $hostname =~ /^\./ || $hostname =~ /\.$/;

    # Validate individual labels (<= 63 chars, no leading/trailing hyphen)
    my @labels = split(/\./, $hostname);
    for my $label (@labels) {
        return 0 if length($label) == 0 || length($label) > 63;
        return 0 if $label =~ /^-/ || $label =~ /-$/;
    }

    return 1;
}

sub resolve_dns {
    my (%args) = @_;
    my $hostname = $args{hostname};
    my $timeout  = defined $args{timeout} ? $args{timeout} : 3.0;

    unless (defined $hostname && length($hostname)) {
        return (undef, { error => "Hostname cannot be empty", code => 2 });
    }

    unless (validate_hostname($hostname)) {
        return (undef, { error => "Invalid hostname format: '$hostname'", code => 2 });
    }

    unless (defined $timeout && $timeout =~ /^\d+(\.\d+)?$/ && $timeout > 0 && $timeout <= 10.0) {
        return (undef, { error => "Invalid timeout: '$timeout'. Must be > 0 and <= 10.0 seconds.", code => 2 });
    }

    my $start_time = time();
    my ($err, @res);
    my $timed_out = 0;

    eval {
        local $SIG{ALRM} = sub { $timed_out = 1; die "RESOLVER_TIMEOUT\n"; };
        # Schedule integer second alarm if positive
        my $alarm_secs = int($timeout + 0.999);
        alarm($alarm_secs > 0 ? $alarm_secs : 1);

        ($err, @res) = getaddrinfo(
            $hostname,
            undef,
            {
                family   => AF_UNSPEC,
                socktype => SOCK_STREAM,
            }
        );

        alarm(0);
    };
    alarm(0); # Ensure alarm reset

    my $elapsed_ms = sprintf("%.2f", (time() - $start_time) * 1000.0);

    if ($timed_out || ($@ && $@ =~ /RESOLVER_TIMEOUT/)) {
        return (
            {
                query             => $hostname,
                record_type       => 'A/AAAA',
                resolved_ips      => [],
                duration_ms       => $elapsed_ms + 0.0,
                timeout_requested => $timeout + 0.0,
            },
            {
                error  => "DNS resolution timed out after requested ${timeout}s limit",
                code   => 124,
                status => 'timeout',
            }
        );
    }

    if ($err) {
        return (
            {
                query             => $hostname,
                record_type       => 'A/AAAA',
                resolved_ips      => [],
                duration_ms       => $elapsed_ms + 0.0,
                timeout_requested => $timeout + 0.0,
            },
            {
                error  => "DNS resolution failed for '$hostname': $err",
                code   => 3,
                status => 'error',
            }
        );
    }

    my %unique_ips;
    for my $ai (@res) {
        my ($ni_err, $ip) = getnameinfo($ai->{addr}, NI_NUMERICHOST);
        if (!$ni_err && defined $ip && length($ip)) {
            $unique_ips{$ip} = 1;
        }
    }

    my @sorted_ips = sort keys %unique_ips;

    my $result = {
        query             => $hostname,
        record_type       => 'A/AAAA',
        resolved_ips      => \@sorted_ips,
        duration_ms       => $elapsed_ms + 0.0,
        timeout_requested => $timeout + 0.0,
        timeout_note      => "Resolver timeout is implementation-dependent; blocking getaddrinfo does not guarantee a hard deadline",
    };

    return ($result, undef);
}

1;
