# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "Running tests 1..8\n"; }
END {print "Load failed ... not ok 1\n" unless $loaded;}
use CGI::SecureState;
use Digest::SHA1 qw (sha1 sha1_hex);
use Crypt::Blowfish;
$loaded = 1;
print "Everything seems to load ... ok 1\n";

@ISA=qw (CGI);
######################### End of black magic.

unless ( eval { require 5.6.0 } )
{
    warn "Wow, you really insist on using an old version of PERL, don't you?\n";
    warn "If this is not a warning that you expected to see, read the README file\n";
    warn "Press return to continue.\n";
    <STDIN>;
}

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

$ENV{'REMOTE_ADDR'}='127.0.0.1';
my $test=2;
print "Testing Crypt::Blowfish ... ";
my $cipher = new Crypt::Blowfish (rand().rand().rand());
my $words="Blah blah blah blah blah";
my $binstring=$words;


$binstring=~ s/(.{8})/$cipher->encrypt($1)/egs;
$binstring=~ s/(.{8})/$cipher->decrypt($1)/egs;
if ($binstring ne $words) { &fail("not ok 2\n") }
else { print "ok 2\n" } 


$test=3;
print "Testing Digest::SHA1 ... ";
if (&sha1($binstring) ne pack("H*",&sha1_hex($binstring))) { &fail("not ok 3\n") }
else { print "ok 3\n" }

$test=4;
print "Testing long filenames ... ";
unless ( open FILETEST, "looOoo_oooooo-123ngfiletESt" ) { &fail("not ok 4\n") }
else { close FILETEST; print "ok 4\n"; }

$test=5;
print "\nAt the cgi text prompt, type in \"cgi=test%20%0A%07\" press return,\n";
print "and type your system's end of file indicator (Ctrl-D on UNIX).  Note \n";
print "that for this to work, the test program must be in a directory that it\n";
print "can write in.\n";

use CGI qw( -debug );
my $cgi=new CGI::SecureState(".");

print "\nTesting CGI::SecureState ... ";
if ($cgi->param('cgi') ne pack ("C*",116,101,115,116,32,10,7)) { &fail("not ok 5\n")}
else { print "ok 5\n" }


$test=6;
print "Testing CGI::SecureState->add ... ";
$cgi->add('random_stuff' => 'Some\[]/cv;l,".'.chr(244).chr(2).'bxpo wierdness');
if ($cgi->param('random_stuff') ne 'Some\[]/cv;l,".'.chr(244).chr(2).'bxpo wierdness') { &fail("not ok 6\n") }
else { print "ok 6\n" }

$cgi->SUPER::delete('cgi');
$cgi->SUPER::delete('random_stuff');
$cgi->decipher;
print "Testing reading from the saved data ... ";
if ($cgi->param('cgi') ne pack ("C*",116,101,115,116,32,10,7)) { &fail("not ok 7\n")}
elsif ($cgi->param('random_stuff') ne 'Some\[]/cv;l,".'.chr(244).chr(2).'bxpo wierdness') { &fail("not ok 7\n")}
else { print "ok 7\n" }

$test=8;
print "Testing cgi->delete_session ... ";
$cgi->delete_session;
print "unless you see errors, ok 8\n";

print "All done.\n";
print "If you see ANY wierd error messages, that is an indication of \n";
print "failure, and CGI::SecureState should be installed.\n";




sub fail
{
    my $error=shift;
    my $input;
    warn $error;
    print "\nA possibly fatal error occurred.  Are you sure that this is ok? ";
    chomp ($input=<STDIN>);
    return if ($input =~ /^y(?:es)?$/i);
    die "User cancelled install!!\n";
}
