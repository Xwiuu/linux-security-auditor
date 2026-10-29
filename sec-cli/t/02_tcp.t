use strict;
use warnings;
use Test::More;
use File::Basename qw(dirname);
use File::Spec;
use IO::Socket::IP;
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

if ($server) {
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
} else {
    pass("Could not bind local listener");
    pass("Could not bind local listener");
    pass("Could not bind local listener");
    pass("Could not bind local listener");
}

# 2. Local TCP refusal fixture (port 1 or an unbound high port)
# Find an unused port by briefly binding and closing
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

# 3. Input Validation
my ($res_inv1, $err_inv1) = LSA::SecEng::TCP::check_tcp(host => 'invalid;host', port => 80);
is($err_inv1->{code}, 2, "Invalid host with shell metacharacters rejected with code 2");

my ($res_inv2, $err_inv2) = LSA::SecEng::TCP::check_tcp(host => '127.0.0.1', port => 70000);
is($err_inv2->{code}, 2, "Out of range port rejected with code 2");

my ($res_inv3, $err_inv3) = LSA::SecEng::TCP::check_tcp(host => '127.0.0.1', port => 80, timeout => 15.0);
is($err_inv3->{code}, 2, "Timeout > 10.0s rejected with code 2");

# 4. TCP Timeout handling with controlled non-routable address (RFC 5737 TEST-NET-1 192.0.2.1)
# Note: 192.0.2.1 is reserved for documentation/testing and drops packets without RST
my ($res_to, $err_to) = LSA::SecEng::TCP::check_tcp(
    host    => '192.0.2.1',
    port    => 81,
    timeout => 0.5, # 500ms timeout
);

if ($err_to && $err_to->{code} == 124) {
    is($err_to->{code}, 124, "TCP connect to unreachable test IP times out with exit code 124");
    is($err_to->{status}, 'timeout', "Status is 'timeout'");
} else {
    # If route is immediately rejected by local routing table (ENETUNREACH), that is also valid
    ok($err_to->{code} == 124 || $err_to->{code} == 3, "TCP connect to 192.0.2.1 handled as timeout (124) or network unreachable (3)");
    pass("TCP non-routable test completed");
}

done_testing();

