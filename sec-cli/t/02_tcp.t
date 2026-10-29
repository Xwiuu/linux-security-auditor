use strict;
use warnings;
use Test::More;
use File::Basename qw(dirname);
use File::Spec;
use IO::Socket::IP;
use POSIX qw(:errno_h);
use JSON::PP;

my $t_dir = dirname(File::Spec->rel2abs(__FILE__));
my $lib_dir = File::Spec->catdir($t_dir, '..', 'lib');
unshift @INC, $lib_dir;

require_ok('LSA::SecEng::TCP');

# 1. Genuine readiness: Live local TCP connection without mocks
my $server = IO::Socket::IP->new(
    LocalHost => '127.0.0.1',
    LocalPort => 0,
    Listen    => 5,
    ReuseAddr => 1,
);

SKIP: {
    skip "Could not bind local listener: $!", 4 unless $server;

    my $port = $server->sockport;
    my ($res, $err) = LSA::SecEng::TCP::check_tcp(
        host    => '127.0.0.1',
        port    => $port,
        timeout => 3.0,
    );

    ok(defined $res, "Genuine readiness: TCP check to live local listener returned result");
    is($err, undef, "No error on connected local listener");
    is($res->{reachable}, JSON::PP::true, "Reachable flag is true");
    ok($res->{latency_ms} >= 0, "Latency measured in ms: $res->{latency_ms}");
    close($server);
}

# 2. Genuine connection refusal: Closed local port without mocks
my $probe = IO::Socket::IP->new(LocalHost => '127.0.0.1', LocalPort => 0, Listen => 1);
my $closed_port = $probe ? $probe->sockport : 59999;
close($probe) if $probe;

my ($res_refused, $err_refused) = LSA::SecEng::TCP::check_tcp(
    host    => '127.0.0.1',
    port    => $closed_port,
    timeout => 2.0,
);

ok(defined $res_refused, "Genuine refusal: TCP check to closed port returned result");
is($res_refused->{reachable}, JSON::PP::false, "Reachable is false on closed port");
is($err_refused->{code}, 1, "Exit code 1 on connection refusal");
is($err_refused->{status}, 'warning', "Status is 'warning' on connection refusal");
like($err_refused->{error}, qr/refused/i, "Error message describes refusal");

# 3. Simulated select-result classification: Zero readiness (select returning 0)
# (Separated from elapsed-time enforcement per Sprint 01B FIX-02)
my ($res_zero, $err_zero) = LSA::SecEng::TCP::check_tcp(
    host       => '127.0.0.1',
    port       => $closed_port,
    timeout    => 2.0,
    _select_fn => sub {
        my ($rvec, $wvec, $evec, $rem) = @_;
        return 0; # Simulate select returning 0 (zero file descriptors ready)
    },
);

ok(defined $res_zero, "Zero readiness returned result payload");
is($res_zero->{reachable}, JSON::PP::false, "Reachable is false on zero readiness");
is($err_zero->{code}, 124, "Zero readiness maps to timeout code 124");
is($err_zero->{status}, 'timeout', "Status is 'timeout'");
like($err_zero->{error}, qr/timed out/i, "Error message notes timeout");

# 4. Simulated select-result classification: Select system call failure
my ($res_sel_err, $err_sel_err) = LSA::SecEng::TCP::check_tcp(
    host       => '127.0.0.1',
    port       => $closed_port,
    timeout    => 2.0,
    _select_fn => sub {
        $! = POSIX::EBADF;
        return -1; # Simulate select returning error (< 0) with non-EINTR errno
    },
);

is($res_sel_err->{reachable}, JSON::PP::false, "Reachable is false on select system call failure");
is($err_sel_err->{code}, 3, "Select system call failure exits with environmental error code 3");
is($err_sel_err->{status}, 'error', "Status is 'error'");
like($err_sel_err->{error}, qr/Socket select failed/, "Error message captures select failure");

# 5. Monotonic deadline enforcement: EINTR retry with remaining timeout
my $eintr_calls = 0;
my @remaining_seen;
my ($res_eintr, $err_eintr) = LSA::SecEng::TCP::check_tcp(
    host       => '127.0.0.1',
    port       => $closed_port,
    timeout    => 3.0,
    _select_fn => sub {
        my ($rvec, $wvec, $evec, $rem) = @_;
        $eintr_calls++;
        push @remaining_seen, $rem;
        if ($eintr_calls == 1) {
            $! = POSIX::EINTR;
            return -1;
        }
        return 0; # Terminate on second pass with timeout
    },
);

is($eintr_calls, 2, "Select retried after EINTR without exiting prematurely");
ok($remaining_seen[1] <= $remaining_seen[0], "Remaining timeout passed to second select is monotonic and bounded");
is($err_eintr->{code}, 124, "Timeout code 124 returned after EINTR retry completes");

# 6. Monotonic deadline enforcement: Exhausted deadline
# Simulates monotonic clock passing deadline during loop; must terminate without calling select
my $simulated_clock = 1000.0;
my $select_invoked = 0;
my ($res_exhaust, $err_exhaust) = LSA::SecEng::TCP::check_tcp(
    host       => '127.0.0.1',
    port       => $closed_port,
    timeout    => 2.0, # Deadline will be 1002.0
    _clock_fn  => sub {
        # Advance clock to 1003.0 (past deadline of 1002.0)
        $simulated_clock += 3.0;
        return $simulated_clock;
    },
    _select_fn => sub {
        $select_invoked = 1;
        return 1;
    },
);

is($select_invoked, 0, "Select was not invoked because monotonic deadline was already exhausted");
is($err_exhaust->{code}, 124, "Exhausted deadline exits with timeout code 124");
is($err_exhaust->{status}, 'timeout', "Status is 'timeout' on exhausted deadline");

# 7. Deterministic getsockopt failure (Sprint 01A FIX-03)
my ($res_opt_fail, $err_opt_fail) = LSA::SecEng::TCP::check_tcp(
    host            => '127.0.0.1',
    port            => $closed_port,
    _select_fn      => sub { return 1; },
    _getsockopt_fn  => sub { return undef; },
);

is($res_opt_fail->{reachable}, JSON::PP::false, "Reachable is false when getsockopt fails");
is($err_opt_fail->{code}, 3, "getsockopt undef failure returns environmental error code 3");
is($err_opt_fail->{status}, 'error', "Status is error");
like($err_opt_fail->{error}, qr/getsockopt.*failed/, "Descriptive getsockopt failure error");

# 8. Kernel ETIMEDOUT unpack verification
my ($res_etimedout, $err_etimedout) = LSA::SecEng::TCP::check_tcp(
    host           => '127.0.0.1',
    port           => $closed_port,
    _select_fn     => sub { return 1; },
    _getsockopt_fn => sub { return pack("i", POSIX::ETIMEDOUT); },
);

is($err_etimedout->{code}, 124, "Kernel ETIMEDOUT mapped to exit code 124");
is($err_etimedout->{status}, 'timeout', "Status is timeout on ETIMEDOUT");

# 9. Input Validation tests
my ($res_inv1, $err_inv1) = LSA::SecEng::TCP::check_tcp(host => 'invalid;host', port => 80);
is($err_inv1->{code}, 2, "Invalid host with shell metacharacters rejected with code 2");

my ($res_inv2, $err_inv2) = LSA::SecEng::TCP::check_tcp(host => '127.0.0.1', port => 70000);
is($err_inv2->{code}, 2, "Out of range port rejected with code 2");

my ($res_inv3, $err_inv3) = LSA::SecEng::TCP::check_tcp(host => '127.0.0.1', port => 80, timeout => 15.0);
is($err_inv3->{code}, 2, "Timeout > 10.0s rejected with code 2");

done_testing();
