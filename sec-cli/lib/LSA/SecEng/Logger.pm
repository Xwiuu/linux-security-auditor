package LSA::SecEng::Logger;

use strict;
use warnings;
use POSIX qw(strftime);
use Time::HiRes qw(gettimeofday);
use JSON::PP;

our $VERSION = '1.0.0';

sub get_iso_timestamp {
    my ($seconds, $microseconds) = gettimeofday();
    my $base = strftime("%Y-%m-%dT%H:%M:%S", gmtime($seconds));
    return sprintf("%s.%03dZ", $base, int($microseconds / 1000));
}

sub get_hostname {
    my $host = eval {
        require Sys::Hostname;
        Sys::Hostname::hostname();
    };
    return $host || 'localhost';
}

sub create_log_entry {
    my (%args) = @_;

    my $level   = uc($args{level} || 'INFO');
    my $message = $args{message};
    my $context = $args{context};

    unless (defined $message && length($message)) {
        return (undef, "Log message cannot be empty");
    }

    unless ($level =~ /^(DEBUG|INFO|WARN|WARNING|ERROR|FATAL)$/) {
        return (undef, "Invalid log level: $level");
    }

    $level = 'WARN' if $level eq 'WARNING';

    my $entry = {
        timestamp => get_iso_timestamp(),
        level     => $level,
        message   => "$message",
        pid       => $$,
        hostname  => get_hostname(),
    };

    if (defined $context) {
        if (ref($context) eq 'HASH') {
            $entry->{context} = $context;
        } else {
            return (undef, "Context must be a HASH reference");
        }
    }

    return ($entry, undef);
}

sub format_json {
    my ($entry) = @_;
    my $coder = JSON::PP->new->utf8->canonical;
    return $coder->encode($entry);
}

1;
