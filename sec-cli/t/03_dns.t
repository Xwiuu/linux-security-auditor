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

# 4. Resolver Error Handling (RFC 6761 .invalid domain)
# RFC 6761 guarantees that queries for *.invalid MUST NOT be routed or resolved
my ($res_err, $err_err) = LSA::SecEng::DNS::resolve_dns(
    hostname => 'unresolvable-test-host.invalid',
    timeout  => 1.0,
);

is($err_err->{code}, 3, "Non-existent RFC 6761 .invalid domain returns exit code 3");
like($err_err->{error}, qr/DNS resolution failed/, "Error message correctly formatted");

done_testing();
