use strict;
use warnings FATAL => qw(all);

use File::Find;

my $Target = "regression.diffs";

find(\&dump, "src");

sub dump {
  if ($_ eq $Target) {
    my $path = $File::Find::name;
    print "=== $path ===\n";
    open(my $fh, "<", $_) || die "wtf";
    while (my $line = <$fh>) {
      print $line;
      if ($. > 1000) { last; }
    }
  }
}
