# Configuration arguments for vcbuild.
use strict;
use warnings;

our $config = {
	asserts => 0,    # --enable-cassert
	     # float4byval=>1,         # --disable-float4-byval, on by default

	# float8byval=> $platformbits == 64, # --disable-float8-byval,
	# off by default on 32 bit platforms, on by default on 64 bit platforms

	# blocksize => 8,         # --with-blocksize, 8kB by default
	# wal_blocksize => 8,     # --with-wal-blocksize, 8kB by default
	# trans_slots_per_page => 4, # --with-trans_slots_per_page, 4 by default
	ldap      => 1,        # --with-ldap
	extraver  => undef,    # --with-extra-version=<string>
	gss       => undef,    # --with-gssapi=<path>
	icu       => undef,    # --with-icu=<path>
	nls       => undef,    # --enable-nls=<path>
	tap_tests => undef,    # --enable-tap-tests
	tcl       => undef,    # --with-tcl=<path>
	perl      => undef,    # --with-perl=<path>
	python    => undef,    # --with-python=<path>
	openssl   => undef,    # --with-openssl=<path>
	uuid      => undef,    # --with-uuid=<path>
	xml       => undef,    # --with-libxml=<path>
	xslt      => undef,    # --with-libxslt=<path>
	iconv     => undef,    # (not in configure, path to iconv)
	zlib      => undef     # --with-zlib=<path>
};

1;
