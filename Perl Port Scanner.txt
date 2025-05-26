
#!/usr/bin/perl

use strict;
use warnings;
use IO::Socket::INET;
use threads;
use Thread::Queue;
use Getopt::Long qw(:config no_ignore_case);
use Pod::Usage;

# Command line options
my $host;
my $port_str = "1-1024";
my $threads = 100;
my $help;

GetOptions(
    "host|h=s"    => \$host,
    "ports|p=s"   => \$port_str,
    "threads|t=i" => \$threads,
    "help"        => \$help,
) or pod2usage(2);

pod2usage(1) if $help || !$host;

# Validate thread count
if ($threads < 1 || $threads > 1000) {
    die "Error: Thread count must be between 1 and 1000\n";
}

# Parse port specification into array of port numbers
sub parse_ports {
    my $str = shift;
    my %ports;
    
    foreach my $part (split /,/, $str) {
        $part =~ s/\s+//g;  # Remove whitespace
        
        if ($part =~ /^(\d+)-(\d+)$/) {
            my ($start, $end) = ($1, $2);
            if ($start > $end) {
                die "Error: Invalid port range '$part' - start port must be <= end port\n";
            }
            if ($start < 1 || $end > 65535) {
                die "Error: Port numbers must be between 1 and 65535\n";
            }
            $ports{$_} = 1 for $start .. $end;
        } elsif ($part =~ /^(\d+)$/) {
            my $port = $1;
            if ($port < 1 || $port > 65535) {
                die "Error: Port number must be between 1 and 65535\n";
            }
            $ports{$port} = 1;
        } else {
            die "Error: Invalid port specification '$part'\n";
        }
    }
    
    return sort { $a <=> $b } keys %ports;
}

my @ports = parse_ports($port_str);

if (@ports == 0) {
    die "Error: No valid ports specified\n";
}

# Scan a single port
sub scan_port {
    my ($host, $port, $timeout) = @_;
    
    my $sock = IO::Socket::INET->new(
        PeerAddr => $host,
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => $timeout,
    );
    
    if ($sock) {
        close($sock);
        return ($port, 1);
    }
    
    return ($port, 0);
}

# Scan all ports using thread pool
sub scan_ports {
    my ($host, $ports_ref, $max_threads) = @_;
    my $queue = Thread::Queue->new(@$ports_ref);
    my @open_ports : shared;
    my @workers;
    
    # Create worker threads
    for (1 .. $max_threads) {
        push @workers, threads->create(sub {
            while (defined(my $port = $queue->dequeue_nb)) {
                my ($p, $is_open) = scan_port($host, $port, 1);
                if ($is_open) {
                    {
                        lock(@open_ports);
                        push @open_ports, $p;
                    }
                }
            }
        });
    }
    
    # Wait for all threads to complete
    $_->join for @workers;
    
    return sort { $a <=> $b } @open_ports;
}

# Main execution
print "Scanning $host on ports: $port_str\n";
print "Total ports to scan: " . scalar(@ports) . "\n";
print "Using $threads threads...\n\n";

eval {
    my @open_ports = scan_ports($host, \@ports, $threads);
    
    print "Scan complete. Open ports on $host:\n";
    if (@open_ports) {
        printf "  Port %d is OPEN\n", $_ for @open_ports;
        print "\nTotal open ports found: " . scalar(@open_ports) . "\n";
    } else {
        print "  No open ports found.\n";
    }
    1;
} or do {
    chomp(my $error = $@);
    print "Error during scan: $error\n";
    exit 1;
};

__END__
