#!/usr/bin/perl -wT
use strict;
no strict 'refs';
package CGI::SecureState;

use CGI;
use Crypt::Blowfish;
use Digest::SHA1 qw(sha1 sha1_hex sha1_base64);
use vars qw(@ISA $VERSION);
@ISA=qw(CGI); 
$VERSION = '0.21';


sub new 
{
    #declare needed objects
    my ($self) = shift;

    #this is relatively legal....
    my $cgi=new CGI;
    $cgi->delete('.statedir');
    $cgi->delete('.objectfile');
    $cgi->delete('.cipher');
    $cgi->{'.statedir'}=shift || ".";

    my $id=$cgi->param('.id')|| &sha1_hex(shift or (time()^rand()).($CGI::SecureState::Devel::counter+=rand()));
    my $remote_addr=$ENV{'REMOTE_ADDR'};
    my $remoteip=pack("CCCC", split (".", $remote_addr));
    my $key=pack("H*",$id).&sha1($remoteip);
    $cgi->{'.cipher'}=Crypt::Blowfish->new($key);
    $_=&sha1_base64($id.$remote_addr);
    tr|+/|_-|;
    /([\w-]{27})/;
    $cgi->{'.objectfile'}=$1;
    bless $cgi, $self;
    $cgi->param('.id') ? $cgi->decipher : $cgi->param(-name => '.id', -value => $id);
    $cgi->encipher;
    return $cgi;
}

sub encipher
{
    my ($self)=shift;
    my ($binstring,$tmp)=("");
    my ($statedir,$filename,$cipher,@savedpairs)=($self->{'.statedir'},$self->{'.objectfile'},$self->{'.cipher'},$self->param());
    return if ($self->param('.sailthru'));
    foreach (@savedpairs)  {
	if ($tmp=$self->param($_)){
	    $tmp=~ s/(\W)/\\$1/go;
	    $binstring.=join(" ",($_=~ m/(\w*)/),$tmp)." \n";
	}
    }
    $binstring=sprintf("%lx", length($binstring)) . " \n" . $binstring;
    $tmp=(length($binstring) % 8)+1;
    $binstring.= chr(int(rand(256))) while(--$tmp);
    $binstring=reverse($binstring);
    $binstring=~ s/(.{8})/$cipher->encrypt($1)/egs;
    open (OBJFILE , "> $statedir/$filename") || $self->errormsg('Filesystem Error');
    print OBJFILE $binstring;
    close OBJFILE or $self->errormsg('Filesystem Error');
}

sub decipher
{
    my ($self)=shift;
    my ($binstring,$spkey,$spvalue)=("");
    my ($statedir,$filename,$cipher)=($self->{'.statedir'},$self->{'.objectfile'},$self->{'.cipher'});
    return if ($self->param('.sailthru'));
    open (OBJFILE , "$statedir/$filename") || $self->errormsg ('Invalid ID');
    $binstring.=$_ while (<OBJFILE>);
    close OBJFILE or $self->errormsg('Filesystem Error');
    $binstring=~ s/(.{8})/$cipher->decrypt($1)/egs;
    $binstring=reverse($binstring);
    ($_)=split(" \n",$binstring);
    $binstring=substr($binstring,length()+2,hex()) || $self->errormsg('Invalid ID');
    foreach (split (" \n",$binstring))
    {
	($spkey,$spvalue)=split (" ",$_,2);
	if ($spvalue && ! defined ($self->param($spkey)))  {
	    $spvalue=~ s/\\(\W)/$1/go;
	    $self->param(-name => $spkey, -value => $spvalue);
	}
    }
}

sub add
{
    my ($self)=shift;
    $self->param(@_);
    $self->encipher;
}

sub delete
{
    my ($self)=shift;
    $self->SUPER::delete(shift);
    $self->encipher;
}

sub delete_all
{
    my ($self)=shift;
    open (OBJFILE, join("","> ",$self->{'.statedir'},"/",$self->{'.objectfile'})) || $self->errormsg('Invalid ID');
    close OBJFILE or $self->errormsg('Filesystem Error');
    $self->SUPER::delete_all();
}

sub delete_session
{
    my ($self)=shift;
    (unlink $self->{'.statedir'}."/".$self->{'.objectfile'}) or $self->errormsg('Filesystem Error');
    $self->SUPER::delete_all;
}

sub state_url
{
    my ($self)=shift;
    return $self->script_name()."?.id=".$self->param('.id');
}

sub state_url_thru
{
    my ($self)=shift;
    return $self->script_name()."?.id=".$self->param('.id')."&.sailthru=1";
}

sub state_field 
{ 
    my ($self) = shift;
    return $self->hidden('.id'=> $self->param('.id')); 
}

sub state_field_thru
{ 
    my ($self) = shift;
    return $self->hidden('.id' => $self->param('.id'))."\n".$self->hidden('.sailthru' => '1'); 
}

sub errormsg
{
    print "Content-type: text/html\n\n";
    print "<HTML><HEAD><TITLE>Server Error</TITLE></HEAD><BODY bgcolor=\"white\">\n";
    print "<br><h1>The following error was encountered: </h1>\n";
    if ($_[1] eq 'Invalid ID')
    {
	print "<p>Your unique identification string is not valid.  There could be several\n";
	print " reasons for this: your identifier has become corrupt, your identifier has expired, \n";
	print "you are not yet authorized to the server, or there is a bug in the referring script.";
    }
    elsif ($_[1] eq 'Filesystem Error')
    {
	print "<p>A server file error occurred.  This is most likely due to a bug in the referring\n";
	print " script or a permissions problem on the server";
    }
    print "\n</BODY></HTML>";
    exit;
}


"True Value";

=head1 NAME

CGI::SecureState -- Transparent, secure statefulness for CGI programs

=head1 SYNOPSIS

    use CGI::SecureState;

    my ($optional_state_dir,$optional_rand)=("states","gf8w7reh7");
    my $cgi = new CGI::SecureState($optional_state_dir,$optional_rand);
    print $cgi->header(); 
    my $url = $cgi->state_url(); 
    print "<a href=$url>I am a stateful CGI session.</a>"; 

=head1 DESCRIPTION

A Better Solution to the stateless problem

HTTP is a stateless protocol; a HTTP server closes the connection after serving
an object. It retains no memory of the request details and doesn't relate
subsequent requests with what it has already served.

CGI::Persistent solves this problem by introducing persistent CGI sessions
that store their state data on the server side. 
However, CGI::Persistent has a few nasty problems of its own:

  a) It doesn't work with PERL's taint mode!
  b) It stores data as plain text.
  c) Because it uses Persistence::Object::Simple for key
     generation, it is possible for a user to steal the
     identification string of an administrator and
     use it at a different computer before the session ends.

Enter CGI::SecureState.  CGI::SecureState was a complete rewrite of 
CGI::Persistent with a completely different implementaion.  Not only does
CGI::SecureState work with taint mode, but it also taints the saved data,
allowing for true transparency.  CGI::Persistent has been emulated as
well as possible, even to the point of including undocumented features
in the source of CGI::Persistent, such as the state_url_thru subroutine.
As an extra bonus, CGI::SecureState has been tested with mod_perl and
Apache::Registry and has worked flawlessly (for me at least).
Finally, the last neat feature of CGI::SecureState is that if someone
does find out the remote identification string of an important user
and rushes over to a different computer to use it, they will be stymied
because CGI::SecureState uses the IP address as part of its encryption
scheme.

CGI::SecureState is very close to CGI::Persistent which is derived from 
CGI.pm. CGI.pm methods have been overridden as appropriate.

=head1 METHODS 

=over 4

=item B<new()>

Creates a new CGI object and creates an associated state file and key 
if none already exist.  new() takes two optional arguments. The first 
argument is the directory where the state files are stored.  This should
definitely be a separate directory to ease maintenance of expired state 
files not cleaned up with the delete_session method.  The default
directory is the current working directory.  The second argument should be
completely random data, as generated by a module such as Math::TrulyRandom,
and is only necessary if you are concerned about the random data used 
in key and filename generation.  If you don't provide a second argument,
then CGI::SecureState will use a method based on the rand() call to
generate random data to be hashed with Digest::SHA1.  
Contrary to CGI::Persistent, you cannot specify the identifying key
when you call new().

Examples: 

 $q = new CGI::SecureState; 
 $q = new CGI::SecureState "states";
 $rand= rand (); #or something from Math::TrulyRandom
 $q = new CGI::SecureState  undef, $rand;

=item B<state_url()>

Returns a URL with the state identification string. This URL should be used
for referring to the stateful session associated with the query.

=item B<state_field()> 

Returns a hidden INPUT type for inclusion in HTML forms. Like state_url(),
this element is used in forms to refer to the stateful session associated
with the query.

=item B<state_url_thru()>

A (currently) undocumented feature in CGI::Persistent.  This returns 
state_field, but with an additional ".sailthru" parameter that makes
CGI::SecureState skip reading the state file on disk.  Currently, if
the remote client adds a .sailthru parameter to the query string, the
disk image will be ignored, even if you did not specifically call
state_url_thru or state_field_thru.  This just might be fixed in the
future.

=item B<state_field_thru()>

Like state_field in that it returns a hidden input field and like 
state_url_thru in that the input field contains instructions to
skip over the disk image of the stateful session.

=item B<add()>

This is a new one.  CGI->param will just temporarily set the parameters
that you pass.  If you want stuff saved on disk (that can be overwritten
by the user!) then use add() in the same way as param().

=item B<delete()>

delete() is an overridden method that deletes a named attribute from the 
query.  The state file on disk is updated to reflect the removal of 
the parameter.

Important note: Attributes that are NOT explicitly delete()ed will lurk
about and come back to haunt you!

=item B<delete_all()>

This command toasts all the current cgi parameters, but unlike 
CGI::Persistent, it merely clears the state file instead of deleting it.
For that, use delete_session() instead.

=item B<delete_session()>

This command not only deletes all the cgi parameters, but kills the 
disk image of the session as well. This method should be used when you 
want to irrevocably destroy a session.

=back

=head1 EXAMPLE

This example will show a form that will tell you what what previously
entered.  It should have a directory called "states" that it can write to.


  #!/usr/bin/perl -wT
  use CGI::SecureState;

  my $cgi= new CGI::SecureState('states');

  print $cgi->header(); 
  $cgi->start_html(-title => "CGI::SecureState test", 
		 -bgcolor => "white");
  print $cgi->start_form($cgi->url());
  print $cgi->state_field();
  print "\n<b>Enter some text: </b>";
  print $cgi->textfield("input","");
  print "<br>",$cgi->submit,$cgi->reset;
  print $cgi->end_form;
  print "\n<br><br><br>";

  unless (defined $cgi->param('num_inputs'))
  {
      $cgi->add('num_inputs' => '1');
  }
  else
  {
      $cgi->add('num_inputs' => ($cgi->param('num_inputs')+1));
  }
  $cgi->add('input'.$cgi->param('num_inputs') => 
  	  $cgi->param('input')); 
  $cgi->delete('input');

  foreach ($cgi->param())
  {
      # .id is the name of the identifying key
      print "\n<br>$_ -> ",$cgi->param($_) if ($_ ne '.id');
  }
  print $cgi->end_html;

=head1 BUGS

There are B<no known bugs> with the current version.  Take note of the
following limitations, however.

=head1 LIMITATIONS

CGI parameters can not have spaces or binary data in their names.
However, the values may be anything.  This is a data file format
limitation and will be changed if enough people complain.

See the statement about .sailthru in state_url_thru.  Again, if
enough people complain, I will fix it.

On UNIX systems, srand() depends on time() which has a granularity
of one second.  Two people connecting from two different computers
within the same second will get the same random seed unless you provide
your own random data.  However, they will not use the same encryption
or the same data file on disk.  This statement does not apply to
users of Apache::Registry because they have the nice little feature that 
global variables are preserved across sessions.

Crypt::Blowfish is the only cipher that CGI::SecureState is using
at the moment.  Change at your own risk.

CGI.pm has its own funky way of doing state persistence that 
CGI::SecureState does NOT override.  This include setting default
values for form input fields.  If this becomes problematic,
use the -override setting when calling things like hidden().


CGI::SecureState requires:
Long file names (at least 27 chars): needed to ensure remote ticket 
authenticity.

Crypt::Blowfish: it couldn't be called "Secure" without.  At some point in
the future (as better algorithms become available), this
requirement may be changed.  Tested with version 2.06.

Digest::SHA1: for super-strong (160 bit) hashing of data.  It is used in
key generation and filename generation.  Tested with version 1.03.

CGI.pm: it couldn't be called "CGI" without.  Should not be a problem as it
comes standard with Perl 5.004 and above.  Tested with version
2.56.

Perl: Hmmm.  Tested with v5.6.0.  This module has NOT been tested with
5.005 or below.  Use at your own risk.  There may be several bugs
induced by lower versions of Perl, several of which may
include: failure to compile, failure to run, or the mysterious
absence of your favorite pair of lemming slippers.  The author is
exempt from wrongdoing and liability in case you decide to use
CGI::SecureState with a Perl less than 5.6.0.


It would be really nice if someone would audit the key generation,
enciphering, and deciphering subroutines to make sure that as little
as possible information is given to an attacker about the nature of
the contents.  As of right now, I am the only person who has looked at it.  
I think that the 24-byte (192 bit) encryption is more than enough to counter 
cryptanalysis, but one can never be too sure.  If nothing else, it
would at least make sure that I am using Crypt::Blowfish properly
and not dumping the encryption level down to 8 bytes (64 bits).


If you do find a bug, you should send it immediately to
behroozi@penguinpowered.com with the subject "CGI::SecureState Bug!".
I am not responsible for problems in other people's code and will
bluntly tell you so if you insist on sending me faulty code.  It is
ok if you send me a bug report, it is better if you send a small
chunk of code that points it out, and it is best if you send a patch--if
the patch is good, you might see a release the next day on CPAN.
Otherwise, it could take weeks . . .

=head1 SEE ALSO 

  CGI(3), CGI::Persistent(3)

=head1 AUTHORS

Peter Behroozi, behroozi@penguinpowered.com


I ripped a good deal of documentation from CGI::Persistent, so

Vipul Ved Prakash, mail@vipul.net

deserves credit as well.
Don't mail him with bugs or he might search me out and steal my
set of perfumed mousepads.

=cut
