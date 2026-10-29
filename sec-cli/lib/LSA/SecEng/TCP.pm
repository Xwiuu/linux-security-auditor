package LSA::SecEng::TCP;

use strict;
use warnings;
use IO::Socket::IP;
use POSIX qw(:errno_h strerror);
use Socket qw(SOL_SOCKET SO_ERROR);
use Time::HiRes qw(time clock_gettime CLOCK_MONOTONIC);
use JSON::PP;

our $VERSION = '1.0.0';

=head1 NAME

LSA::SecEng::TCP - TCP Connectivity and Latency Diagnostics

=head1 RESOLUTION AND TIMEOUT LIMITATIONS

When connecting to target endpoints specified by hostname rather than numeric IP address,
C<IO::Socket::IP> invokes the standard C library synchronous resolver (C<getaddrinfo>).
Under POSIX/glibc, synchronous resolver calls block until name resolution completes or
system-level resolver timeouts elapse. Consequently, application-level connection timeouts
apply to the TCP socket connection phase (the non-blocking C<connect> / C<select> window),
and do not strictly bound synchronous upstream DNS lookup latency prior to socket initialization.
Callers requiring bounded DNS resolution should resolve hostnames beforehand using C<resolve_dns>.

=cut

sub _get_monotonic_time {
    my $m = eval { clock_gettime(CLOCK_MONOTONIC) };
    return defined $m ? $m : time();
}

sub validate_target_host {
    my ($host) = @_;
    return 0 unless defined $host && length($host);
    return 0 if length($host) > 253;

    # Valid IPv4, IPv6, or domain name / localhost
    # Disallow shell metacharacters, spaces, control characters
    if ($host =~ /^[a-zA-Z0-9.-]+$/) {
        # Check label structure for hostnames
        return 0 if $host =~ /\.\./; # No consecutive dots
        return 1;
    }

    # IPv6 format with colons and brackets
    if ($host =~ /^\[?[0-9a-fA-F:]+\]?$/) {
        return 1;
    }

    return 0;
}

sub check_tcp {
    my (%args) = @_;
    my $host    = $args{host};
    my $port    = $args{port};
    my $timeout = defined $args{timeout} ? $args{timeout} : 3.0;

    unless (validate_target_host($host)) {
        return (undef, { error => "Invalid target host: '$host'", code => 2 });
    }

    unless (defined $port && $port =~ /^\d+$/ && $port >= 1 && $port <= 65535) {
        return (undef, { error => "Invalid port: '$port'. Must be between 1 and 65535.", code => 2 });
    }

    unless (defined $timeout && $timeout =~ /^\d+(\.\d+)?$/ && $timeout > 0 && $timeout <= 10.0) {
        return (undef, { error => "Invalid timeout: '$timeout'. Must be > 0 and <= 10.0 seconds.", code => 2 });
    }

    # Strip square brackets from IPv6 host if present for IO::Socket::IP
    my $clean_host = $host;
    $clean_host =~ s/^\[//;
    $clean_host =~ s/\]$//;

    my $clock_fn = $args{_clock_fn} || \&_get_monotonic_time;
    my $start_monotonic = $clock_fn->();
    my $start_wall = time(); # used for user-facing latency_ms
    my $deadline = $start_monotonic + $timeout;

    # Attempt non-blocking connection
    my $sock = IO::Socket::IP->new(
        PeerHost => $clean_host,
        PeerPort => $port,
        Blocking => 0,
    );

    unless ($sock) {
        my $err = $@ || $!;
        return (
            {
                target_host     => $host,
                port            => int($port),
                reachable       => JSON::PP::false,
                latency_ms      => 0.0,
                timeout_seconds => $timeout + 0.0,
            },
            {
                error  => "Socket initialization / resolution failed: $err",
                code   => 3,
                status => 'error',
            }
        );
    }

    my $fileno = fileno($sock);
    unless (defined $fileno) {
        close($sock);
        return (undef, { error => "Invalid socket file descriptor", code => 3 });
    }

    # Monotonic deadline enforcement in select loop (Sprint 01B FIX-02)
    # Remaining time is calculated directly from monotonic deadline on every iteration,
    # ensuring signal interruptions (EINTR) do not suffer from interval subtraction drift.
    my $nfound;
    my $select_err;

    while (1) {
        my $now_mono = $clock_fn->();
        my $remaining = $deadline - $now_mono;

        if ($remaining <= 0) {
            # Monotonic deadline exhausted
            $nfound = 0;
            last;
        }

        my $wvec = "";
        vec($wvec, $fileno, 1) = 1;
        my $rvec = $wvec;

        $nfound = $args{_select_fn}
            ? $args{_select_fn}->($rvec, $wvec, undef, $remaining)
            : select($rvec, $wvec, undef, $remaining);
        $select_err = $!;

        if (defined $nfound && $nfound > 0) {
            last; # Socket ready for read/write
        } elsif (defined $nfound && $nfound == 0) {
            last; # select call timed out
        } else {
            # select returned undef / error (< 0)
            if ($select_err == EINTR) {
                # Signal interruption: loop back and evaluate remaining monotonic deadline
                next;
            } else {
                # Genuine select system call failure (EBADF, EINVAL, etc.)
                close($sock);
                my $elapsed_ms = sprintf("%.2f", (time() - $start_wall) * 1000.0);
                return (
                    {
                        target_host     => $host,
                        port            => int($port),
                        reachable       => JSON::PP::false,
                        latency_ms      => $elapsed_ms + 0.0,
                        timeout_seconds => $timeout + 0.0,
                    },
                    {
                        error  => "Socket select failed: $select_err",
                        code   => 3,
                        status => 'error',
                    }
                );
            }
        }
    }

    my $elapsed_ms = sprintf("%.2f", (time() - $start_wall) * 1000.0);

    if ($nfound == 0) {
        close($sock);
        return (
            {
                target_host     => $host,
                port            => int($port),
                reachable       => JSON::PP::false,
                latency_ms      => $elapsed_ms + 0.0,
                timeout_seconds => $timeout + 0.0,
            },
            {
                error  => "Connection timed out after ${timeout}s",
                code   => 124,
                status => 'timeout',
            }
        );
    }

    # Socket is ready: inspect socket error status via getsockopt
    my $opt = $args{_getsockopt_fn}
        ? $args{_getsockopt_fn}->($sock)
        : getsockopt($sock, SOL_SOCKET, SO_ERROR);
    my $getopt_err = $!;
    close($sock);

    unless (defined $opt) {
        return (
            {
                target_host     => $host,
                port            => int($port),
                reachable       => JSON::PP::false,
                latency_ms      => $elapsed_ms + 0.0,
                timeout_seconds => $timeout + 0.0,
            },
            {
                error  => "getsockopt(SO_ERROR) failed: $getopt_err",
                code   => 3,
                status => 'error',
            }
        );
    }

    my $sock_err = unpack("i", $opt);

    if ($sock_err == 0) {
        # Successfully connected
        return (
            {
                target_host     => $host,
                port            => int($port),
                reachable       => JSON::PP::true,
                latency_ms      => $elapsed_ms + 0.0,
                timeout_seconds => $timeout + 0.0,
            },
            undef
        );
    } elsif ($sock_err == ECONNREFUSED) {
        # Connection refused by target
        return (
            {
                target_host     => $host,
                port            => int($port),
                reachable       => JSON::PP::false,
                latency_ms      => $elapsed_ms + 0.0,
                timeout_seconds => $timeout + 0.0,
            },
            {
                error  => "Connection refused: port $port is closed on $host",
                code   => 1,
                status => 'warning',
            }
        );
    } elsif ($sock_err == ETIMEDOUT) {
        # Kernel-level TCP timeout
        return (
            {
                target_host     => $host,
                port            => int($port),
                reachable       => JSON::PP::false,
                latency_ms      => $elapsed_ms + 0.0,
                timeout_seconds => $timeout + 0.0,
            },
            {
                error  => "Connection timed out (ETIMEDOUT)",
                code   => 124,
                status => 'timeout',
            }
        );
    } else {
        # Host unreachable or other network error
        my $err_str = strerror($sock_err);
        return (
            {
                target_host     => $host,
                port            => int($port),
                reachable       => JSON::PP::false,
                latency_ms      => $elapsed_ms + 0.0,
                timeout_seconds => $timeout + 0.0,
            },
            {
                error  => "Connection failed: $err_str (errno $sock_err)",
                code   => 3,
                status => 'error',
            }
        );
    }
}

1;
