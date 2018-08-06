# first part of postgres build.pl, just doesn't run msbuild

use strict;

BEGIN
{

    chdir("../../..") if (-d "../msvc" && -d "../../../src");

}

use lib "src/tools/msvc";

use Cwd;

use Mkvcbuild;

# buildenv.pl is for specifying the build environment settings
# it should contain lines like:
# $ENV{PATH} = "c:/path/to/bison/bin;$ENV{PATH}";

if (-e "src/tools/msvc/buildenv.pl")
{
    do "src/tools/msvc/buildenv.pl";
}
elsif (-e "./buildenv.pl")
{
    do "./buildenv.pl";
}

# set up the project
our $config;
do "config_default.pl";
do "config.pl" if (-f "src/tools/msvc/config.pl");

# print "PATH: $_\n" foreach (split(';',$ENV{PATH}));

Mkvcbuild::mkvcbuild($config);
