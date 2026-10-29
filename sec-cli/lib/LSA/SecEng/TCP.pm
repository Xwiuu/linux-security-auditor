package LSA::SecEng::TCP;

use strict;
use warnings;
use IO::Socket::IP;
use POSIX qw(:errno_h strerror);
use Socket qw(SOL_SOCKET SO_ERROR);
use Time::HiRes qw(time);
use JSON::PP;

our $VERSION = '1.0.0';

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

    my $start_time = time();

    # Attempt non-blocking connection
    my $sock = IO::Socket::IP->new(
        PeerHost => $clean_host,
        PeerPort => $port,
        Blocking => 0,
    );

    unless ($sock) {
        my $err = $@ || $!;
        my $elapsed = sprintf("%.2f", (time() - $start_time) * 1000.0);
        return (
            {
                target_host     => $host,
                port            => int($port),
                reachable       => JSON::PP::false,
                latency_ms      => 0.0,
                timeout_seconds => $timeout + 0.0,
            },
            {
                error => "Socket initialization / resolution failed: $err",
                code  => 3,
                status => 'error',
            }
        );
    }

    my $fileno = fileno($sock);
    unless (defined $fileno) {
        close($sock);
        return (undef, { error => "Invalid socket file descriptor", code => 3 });
    }

    my $wvec = "";
    vec($wvec, $fileno, 1) = 1;
    my $rvec = $wvec;

    # Wait up to $timeout seconds for socket to become ready
    my $nfound = select($rvec, $wvec, undef, $timeout);
    my $elapsed_ms = sprintf("%.2f", (time() - $start_time) * 1000.0);

    if ($nfound == 0) {
        # Timed out
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

    # Socket is ready: retrieve error status via getsockopt
    my $opt = getsockopt($sock, SOL_SOCKET, SO_ERROR);
    my $sock_err = defined $opt ? unpack("i", $opt) : 0;
    close($sock);

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
        # Host unreachable or network error
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
