#!/usr/bin/perl
# build-probes/bench.pl -- perl workload for the L1 block-lookup measurement.
#
# Goal: exercise as many distinct guest opcode types as possible in one long-
# running process, so a perf-record profile has enough JIT dispatch pressure
# to answer PA's block-transition-density question. The perl VM is one indirect
# branch per opcode and (per an earlier profile) sat at ~82.6 % JIT fraction --
# the densest source of block transitions we have.
#
# What is deliberately here:
#   - arithmetic + math (Collatz-ish integer loop, sqrt/log noise)
#   - string ops (concat, join, split, index, uc/lc, reverse)
#   - regex (character class, capture, backreference, non-greedy)
#   - hash + array manipulation (build, sort, grep, delete)
#   - subroutine calls (deep recursion + shallow tail chains)
#
# What is deliberately NOT here:
#   - fork / system / exec / backtick -- process spawn would dwarf everything
#     we are trying to measure (30-test_evp.t was 0.634 % JIT for exactly this
#     reason; documented in docs/build-agent.md's superseded gate)
#   - file I/O in the hot loop
#   - a single tight loop -- one loop compiles to a couple of JIT blocks and
#     does not exercise dispatch
#
# Runs to a wall-clock budget so the process length is predictable irrespective
# of host speed. Env override: BENCH_SECONDS.

use strict;
use warnings;

my $budget = $ENV{BENCH_SECONDS} // 45;
my $t0     = time();
my $iters  = 0;
my $checksum = 0;

my @words = qw(
    lorem ipsum dolor sit amet consectetur adipiscing elit sed do
    eiusmod tempor incididunt ut labore et dolore magna aliqua enim
    ad minim veniam quis nostrud exercitation ullamco laboris nisi
    aliquip ex ea commodo consequat duis aute irure dolor reprehenderit
    voluptate velit esse cillum eu fugiat nulla pariatur excepteur sint
    occaecat cupidatat non proident sunt culpa qui officia deserunt
);

sub collatz_len {
    my ($n) = @_;
    my $s = 0;
    while ($n > 1) {
        $n = ($n & 1) ? 3 * $n + 1 : $n >> 1;
        ++$s;
        return $s if $s > 10000; # guard, though 27-bit orbits are bounded
    }
    return $s;
}

sub ackermann_bounded {
    my ($m, $n, $depth) = @_;
    return 1 if $depth > 800;              # keep the stack sane on any host
    return $n + 1 if $m == 0;
    return ackermann_bounded($m - 1, 1, $depth + 1) if $n == 0;
    return ackermann_bounded($m - 1,
                             ackermann_bounded($m, $n - 1, $depth + 1),
                             $depth + 1);
}

sub string_batch {
    my $out = 0;
    for (my $i = 0; $i < 300; ++$i) {
        my @picks = map { $words[($i * 31 + $_) % @words] } 0..9;
        my $s = join(' ', @picks);
        $s .= reverse($s);
        $s = uc($s);
        $s = lc($s);
        $out += length($s);
        $out += index($s, 'dolor');
        my @parts = split(/\s+/, $s);
        $out += scalar @parts;
    }
    return $out;
}

sub regex_batch {
    my $out = 0;
    for (my $i = 0; $i < 200; ++$i) {
        my $s = join(' ', map { $words[($i * 17 + $_) % @words] } 0..15);
        while ($s =~ /(\w+)\s+(\w+)/g) {
            $out++ if length($1) > length($2);
        }
        # backreference + capture: match words that repeat pairs
        while ($s =~ /(\w{3,5}).*?\1/g) { $out++; }
        # substitute
        (my $t = $s) =~ s/([aeiou])([bcdfg])/$2$1/g;
        $out += length($t);
    }
    return $out;
}

sub hash_batch {
    my %h;
    for (my $i = 0; $i < 400; ++$i) {
        $h{$words[$i % @words] . $i} = $i * 7 + 3;
    }
    my $out = 0;
    my @keys = sort keys %h;
    for my $k (grep { length > 6 } @keys) {
        $out += $h{$k};
    }
    delete $h{$_} for @keys[0..99];
    $out += scalar keys %h;
    for my $k (@keys[100..$#keys]) {
        $h{$k}++ if exists $h{$k};
    }
    return $out;
}

sub array_batch {
    my @a = map { ($_ * 1103515245 + 12345) & 0x7fffffff } 1..500;
    @a = sort { $a <=> $b } @a;
    my @b = grep { $_ & 1 } @a;
    my @c = map { $_ * 2 - 1 } @b;
    my $out = 0;
    $out += $_ for @c;
    push @c, $out;
    pop @c;
    unshift @c, $out;
    shift @c;
    return $out;
}

# Main loop -- rotate through the batches until wall-clock budget is spent.
while ((time() - $t0) < $budget) {
    my $bit = $iters % 5;
    if    ($bit == 0) { $checksum += collatz_len(($iters * 7919) & 0x7fffff); }
    elsif ($bit == 1) { $checksum += string_batch(); }
    elsif ($bit == 2) { $checksum += regex_batch(); }
    elsif ($bit == 3) { $checksum += hash_batch(); }
    else              {
        $checksum += array_batch();
        $checksum += ackermann_bounded(2, 5 + ($iters % 3), 0);
    }
    ++$iters;
}

my $elapsed = time() - $t0;
printf "bench.pl: iters=%d elapsed=%ds checksum=%d\n",
    $iters, $elapsed, $checksum & 0xffffffff;
