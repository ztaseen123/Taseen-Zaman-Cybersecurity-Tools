#!/usr/bin/perl

use strict;
use warnings;
use feature 'say';

# Configuration
my $log_file = "apache_access.log";
my @target_ips = ('127.0.0.1', '127.0.0.11', '217.0.22.3', '139.12.0.2');

# Create a hash for faster IP lookup
my %target_lookup = map { $_ => 1 } @target_ips;

# Initialize counters for all target IPs
my %count = map { $_ => 0 } @target_ips;

# Open the log file
open(my $fh, '<', $log_file) or die "Error: Cannot open file '$log_file': $!\n";

say "Analyzing Apache log file: $log_file";
say "Target IP addresses: " . join(', ', @target_ips);
say "-" x 50;

my $total_lines = 0;
my $processed_lines = 0;

# Process each line of the log file
while (my $line = <$fh>) {
    chomp $line;
    $total_lines++;
    
    # Skip empty lines
    next if $line =~ /^\s*$/;
    
    # Extract IP address (first field in Apache Common/Combined Log Format)
    # Handle both space and tab separators more robustly
    my ($ip_address) = split /\s+/, $line, 2;
    
    # Skip if no IP address found
    next unless defined $ip_address && $ip_address ne '';
    
    $processed_lines++;
    
    # Check if this IP is one of our targets (more efficient lookup)
    if (exists $target_lookup{$ip_address}) {
        $count{$ip_address}++;
    }
    
    # Progress indicator for large files
    if ($total_lines % 10000 == 0) {
        print "Processed $total_lines lines...\r";
    }
}

close($fh);

# Clear progress indicator
print " " x 30 . "\r";

# Display results
say "Analysis Results:";
say "=" x 50;
say sprintf("Total lines read: %d", $total_lines);
say sprintf("Lines processed: %d", $processed_lines);
say "";

my $total_matches = 0;
my $found_any = 0;

# Sort results by IP address for consistent output
foreach my $ip (sort @target_ips) {
    my $count_val = $count{$ip};
    $total_matches += $count_val;
    
    if ($count_val > 0) {
        say sprintf("%-15s appeared %d times", $ip, $count_val);
        $found_any = 1;
    } else {
        say sprintf("%-15s not found in log", $ip);
    }
}

say "";
say "Summary:";
say sprintf("Total matches found: %d", $total_matches);

if (!$found_any) {
    say "No target IP addresses were found in the log file.";
} else {
    say "Target IPs found: " . join(', ', grep { $count{$_} > 0 } @target_ips);
}

__END__
