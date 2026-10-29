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

# 1. Local TCP connection success fixture
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

    ok(defined $res, "TCP check to local listener returned result");
    is($err, undef, "No error on connected local listener");
    is($res->{reachable}, JSON::PP::true, "Reachable flag is true");
    ok($res->{latency_ms} >= 0, "Latency measured in ms: $res->{latency_ms}");
    close($server);
}

# 2. Local TCP refusal fixture (guaranteed closed local port)
my $probe = IO::Socket::IP->new(LocalHost => '127.0.0.1', LocalPort => 0, Listen => 1);
my $closed_port = $probe ? $probe->sockport : 59999;
close($probe) if $probe;

my ($res_refused, $err_refused) = LSA::SecEng::TCP::check_tcp(
    host    => '127.0.0.1',
    port    => $closed_port,
    timeout => 2.0,
);

ok(defined $res_refused, "TCP check to closed port returned result");
is($res_refused->{reachable}, JSON::PP::false, "Reachable is false on closed port");
is($err_refused->{code}, 1, "Exit code 1 on connection refusal");
is($err_refused->{status}, 'warning', "Status is 'warning' on connection refusal");
like($err_refused->{error}, qr/refused/i, "Error message describes refusal");

# 3. Deterministic TCP Timeout test (Sprint 01A FIX-04: no 192.0.2.1, fully deterministic)
my ($res_to, $err_to) = LSA::SecEng::TCP::check_tcp(
    host       => '127.0.0.1',
    port       => $closed_port,
    timeout    => 1.0,
    _select_fn => sub {
        # Simulate select timeout (0 file descriptors ready)
        return 0;
    },
);

ok(defined $res_to, "Timeout check returned result payload");
is($res_to->{reachable}, JSON::PP::false, "Reachable is false on timeout");
is($err_to->{code}, 124, "Timeout exits with code 124");
is($err_to->{status}, 'timeout', "Status is 'timeout'");
like($err_to->{error}, qr/timed out/i, "Error message notes timeout");

# 4. Deterministic EINTR handling followed by timeout in select loop
my $eintr_count = 0;
my ($res_eintr, $err_eintr) = LSA::SecEng::TCP::check_tcp(
    host       => '127.0.0.1',
    port       => $closed_port,
    timeout    => 2.0,
    _select_fn => sub {
        $eintr_count++;
        if ($eintr_count == 1) {
            $! = POSIX::EINTR;
            return -1;
        }
        return 0; # Then simulate timeout on retry
    },
);

is($eintr_count, 2, "Select retried after EINTR without crashing");
is($err_eintr->{code}, 124, "Resulted in timeout after EINTR retry");

# 5. Deterministic getsockopt failure (Sprint 01A FIX-03)
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

# 6. Kernel ETIMEDOUT unpack verification (Sprint 01A FIX-03)
my ($res_etimedout, $err_etimedout) = LSA::SecEng::TCP::check_tcp(
    host           => '127.0.0.1',
    port           => $closed_port,
    _select_fn     => sub { return 1; },
    _getsockopt_fn => sub { return pack("i", POSIX::ETIMEDOUT); },
);

is($err_etimedout->{code}, 124, "Kernel ETIMEDOUT mapped to exit code 124");
is($err_etimedout->{status}, 'timeout', "Status is timeout on ETIMEDOUT");

# 7. Input Validation tests
my ($res_inv1, $err_inv1) = LSA::SecEng::TCP::check_tcp(host => 'invalid;host', port => 80);
is($err_inv1->{code}, 2, "Invalid host with shell metacharacters rejected with code 2");

my ($res_inv2, $err_inv2) = LSA::SecEng::TCP::check_tcp(host => '127.0.0.1', port => 70000);
is($err_inv2->{code}, 2, "Out of range port rejected with code 2");

my ($res_inv3, $err_inv3) = LSA::SecEng::TCP::check_tcp(host => '127.0.0.1', port => 80, timeout => 15.0);
is($err_inv3->{code}, 2, "Timeout > 10.0s rejected with code 2");

done_testing();
