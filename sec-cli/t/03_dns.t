use strict;
use warnings;
use Test::More;
use File::Basename qw(dirname);
use File::Spec;

my $t_dir = dirname(File::Spec->rel2abs(__FILE__));
my $lib_dir = File::Spec->catdir($t_dir, '..', 'lib');
unshift @INC, $lib_dir;

require_ok('LSA::SecEng::DNS');

# 1. Local resolution (localhost) without internet dependency
my ($res_local, $err_local) = LSA::SecEng::DNS::resolve_dns(
    hostname => 'localhost',
    timeout  => 3.0,
);

ok(defined $res_local, "DNS resolution for localhost succeeds");
is($err_local, undef, "No error on localhost resolution");
ok(scalar(@{$res_local->{resolved_ips}}) >= 1, "At least one IP resolved for localhost");

# Verify presence of IPv4 or IPv6 loopback
my %ips = map { $_ => 1 } @{$res_local->{resolved_ips}};
ok(exists $ips{'127.0.0.1'} || exists $ips{'::1'}, "Localhost resolves to 127.0.0.1 or ::1");

# 2. Timeout limitation documentation presence
ok(defined $res_local->{timeout_note}, "Timeout limitation note present in DNS response");
like($res_local->{timeout_note}, qr/blocking getaddrinfo does not guarantee a hard deadline/, "Timeout note documents blocking resolver limitation");

# 3. Input Validation without network queries
my ($res_inv1, $err_inv1) = LSA::SecEng::DNS::resolve_dns(hostname => '');
is($err_inv1->{code}, 2, "Empty hostname rejected with code 2");

my ($res_inv2, $err_inv2) = LSA::SecEng::DNS::resolve_dns(hostname => 'bad;domain.com');
is($err_inv2->{code}, 2, "Hostname with semicolon rejected with code 2");

my ($res_inv3, $err_inv3) = LSA::SecEng::DNS::resolve_dns(hostname => 'bad..domain.com');
is($err_inv3->{code}, 2, "Hostname with consecutive dots rejected with code 2");

my ($res_inv4, $err_inv4) = LSA::SecEng::DNS::resolve_dns(hostname => '-leading.hyphen.com');
is($err_inv4->{code}, 2, "Hostname with leading hyphen label rejected with code 2");

my ($res_inv5, $err_inv5) = LSA::SecEng::DNS::resolve_dns(hostname => 'localhost', timeout => 15.0);
is($err_inv5->{code}, 2, "Timeout > 10.0s rejected with code 2");

# 4. Resolver Error Handling (RFC 6761 .invalid domain - no public internet dependency)
my ($res_err, $err_err) = LSA::SecEng::DNS::resolve_dns(
    hostname => 'unresolvable-test-host.invalid',
    timeout  => 1.0,
);

is($err_err->{code}, 3, "Non-existent RFC 6761 .invalid domain returns exit code 3");
is($err_err->{status}, 'error', "Status is error for unresolvable host");
like($err_err->{error}, qr/DNS resolution failed/, "Error message correctly formatted");

# 5. Unexpected Exception Handling (Sprint 01A FIX-06: distinguish eval exception from resolver error)
my ($res_exc, $err_exc) = LSA::SecEng::DNS::resolve_dns(
    hostname           => 'localhost',
    _getaddrinfo_fn    => sub {
        die "Simulated internal resolver crash or library abort\n";
    },
);

ok(defined $err_exc, "Unexpected exception returns error info");
is($err_exc->{code}, 3, "Unexpected exception exits with code 3 (not success, not timeout)");
is($err_exc->{status}, 'error', "Status is 'error' on unexpected exception");
like($err_exc->{error}, qr/Unexpected resolver exception: Simulated internal resolver crash/, "Exception message captured without reporting success");

# 6. Established Timeout Simulation (Sprint 01A FIX-06: exit code 124 strictly for established timeout)
my ($res_to, $err_to) = LSA::SecEng::DNS::resolve_dns(
    hostname           => 'localhost',
    _getaddrinfo_fn    => sub {
        die "RESOLVER_TIMEOUT\n";
    },
);

ok(defined $err_to, "Established timeout returns error info");
is($err_to->{code}, 124, "Timeout exits strictly with code 124");
is($err_to->{status}, 'timeout', "Status is 'timeout'");
like($err_to->{error}, qr/timed out/, "Error describes timeout event");

done_testing();
