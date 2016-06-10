#!/usr/local/bin/perl

# mkdir-p.pl

# On some systems, the -p option to mkdir (= also create any missing parent
# directories) is not available.

my $arg;

foreach $arg (@ARGV) {
  $arg =~ tr|\\|/|;
  &do_mkdir_p($arg);
}


sub do_mkdir_p {
  local($dir) = @_;

  $dir =~ s|/*\Z(?!\n)||s;

  if (-d $dir) {
    return;
  }

  if ($dir =~ m|[^/]/|s) {
    local($parent) = $dir;
    $parent =~ s|[^/]*\Z(?!\n)||s;

    do_mkdir_p($parent);
  }

  unless (mkdir($dir, 0777)) {
    if (-d $dir) {
      # We raced against another instance doing the same thing.
      return;
    }
    die "Cannot create directory $dir: $!\n";
  }
  print "created directory `$dir'\n";
}
