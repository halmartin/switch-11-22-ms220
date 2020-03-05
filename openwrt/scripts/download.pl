#!/usr/bin/perl
use strict;
use warnings;

my $target = shift @ARGV;
my $filename = shift @ARGV;
my $md5sum = shift @ARGV;
my @mirrors;

my $ok;

@ARGV > 0 or die "Syntax: $0 <target dir> <filename> <md5sum> <mirror> [<mirror> ...]\n";

sub download
{
	my $mirror = shift;

        $mirror =~ s|/$||;
	open WGET, "wget -t5 --timeout=20 -O- \"$mirror/$filename\" |" or die "Cannot launch wget.\n";
	open MD5SUM, "| md5sum > \"$target/$filename.md5sum\"" or die "Cannot launch md5sum.\n";
	open OUTPUT, "> $target/$filename.dl" or die "Cannot create file $target/$filename.dl: $!\n";
	my $buffer;
	while (read WGET, $buffer, 1048576) {
		print MD5SUM $buffer;
		print OUTPUT $buffer;
	}
	close MD5SUM;
	close WGET;
	close OUTPUT;
	
	if (($? >> 8) != 0 ) {
		print STDERR "Download failed.\n";
		cleanup();
		return;
	}
	
	my $sum = `cat "$target/$filename.md5sum"`;
	$sum =~ /^(\w+)\s+/ or die "Could not generate md5sum\n";
	$sum = $1;
	
	if (($sum ne $md5sum)) {
		print STDERR "MD5 sum of the downloaded file does not match - deleting download.\n";
		print STDERR "got $sum expected $md5sum\n";
		cleanup();
		return;
	}
	
	unlink "$target/$filename";
	system("mv \"$target/$filename.dl\" \"$target/$filename\"");
	cleanup();
}

sub cleanup
{
	unlink "$target/$filename.dl";
	unlink "$target/$filename.md5sum";
}

foreach my $mirror (@ARGV) {
	if ($mirror =~ /^\@SF\/(.+)$/) {
		my $sfpath = $1;
		open SF, "wget -t1 -q -O- 'http://prdownloads.sourceforge.net/$sfpath/$filename' |";
		while (<SF>) {
			/RADIO NAME=use_default VALUE=(\w+) OnClick="form\.submit\(\)">/ or
			/type="radio" name="use_default" value="(\w+)" onclick="form\.submit\(\)"\/>/ and do {
				push @mirrors, "http://$1.dl.sourceforge.net/sourceforge/$sfpath";
			};
			/<a href="\/.+\?use_mirror=(\w+)"><b>Download/ and do {
				push @mirrors, "http://$1.dl.sourceforge.net/sourceforge/$sfpath";
			};
		}
		push @mirrors, "http://dl.sourceforge.net/sourceforge/$sfpath";
		close SF;
	} elsif ($mirror =~ /^\@GNU\/(.+)$/) {
		my $gnupath = $1;
		push @mirrors, "ftp://ftp.gnu.org/gnu/$gnupath";
		push @mirrors, "ftp://ftp.belnet.be/mirror/ftp.gnu.org/gnu/$gnupath";
		push @mirrors, "ftp://ftp.mirror.nl/pub/mirror/gnu/$gnupath";
		push @mirrors, "http://mirror.switch.ch/ftp/mirror/gnu/$gnupath";
		push @mirrors, "ftp://ftp.uu.net/archive/systems/gnu/$gnupath";
		push @mirrors, "ftp://ftp.eu.uu.net/pub/gnu/$gnupath";
		push @mirrors, "ftp://ftp.leo.org/pub/comp/os/unix/gnu/$gnupath";
		push @mirrors, "ftp://ftp.digex.net/pub/gnu/$gnupath";
	} else {
		push @mirrors, $mirror;
	}
}

# We don't want to use the openwrt mirrors for meraki builds.
# push @mirrors, 'http://mirror1.openwrt.org/';
# push @mirrors, 'http://downloads.openwrt.org/sources/';

while (!$ok) {
	my $mirror = shift @mirrors;
	$mirror or die "No more mirrors to try - giving up.\n";
	
	download($mirror);
	-f "$target/$filename" and $ok = 1;
}

$SIG{INT} = \&cleanup;

