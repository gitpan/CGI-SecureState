#!/usr/bin/perl -wT
package CGI::SecureState;

use strict;
use CGI;
use Crypt::Blowfish;
use Digest::SHA1 qw(sha1 sha1_hex sha1_base64);
use Fcntl qw(:flock :DEFAULT :seek);
use File::Spec;
use vars qw(@ISA $VERSION $counter $NASTY_WARNINGS $AVOID_SYMLINKS
	    $USE_FLOCK $FLOCK_RFLAGS $FLOCK_WFLAGS $FLOCK_UFLAGS);

BEGIN {
@ISA=qw(CGI); 
$VERSION = '0.30';

#Set this to 0 if you want warnings about deprecated behavior to be suppressed.
#This is especially true if you want to be left in peace while updating scripts based 
#on older versions of CGI::SecureState.  However, the warnings issued should be heeded
#because they generally result in better coding style and program security.
$NASTY_WARNINGS = 1;

#Set this to 0 if you don't want CGI::SecureState to test for the presence of a link
#before writing to a state file.  If this is set to 1 and CGI::SecureState sees a 
#symlink in place of a real file, it will spit out a fatal error.
$AVOID_SYMLINKS = 1;

#Set this to 0 if you do not want CGI::SecureState to use "flock" to assure that
#only one instance of CGI::SecureState is accessing the state file at a time.
#Leave this at 1 unless you really have a good reason not to.

$USE_FLOCK = 1;

#The operating systems below do not support flock, except for
#Windows NT systems, but it is impossible to distinguish WinNT
#systems from Win9x systems only based on $^O
local $_=$^O;
$USE_FLOCK = 0 if (/MacOS/i || /VMS/i || /VOS/i || /MSWin32/i);

if ($USE_FLOCK) {
    $FLOCK_RFLAGS = LOCK_SH;  #Flock flags used when reading from a file
    $FLOCK_WFLAGS = LOCK_EX;  #Flock flags used when writing to a file
    $FLOCK_UFLAGS = LOCK_UN;  #Flock flags used when unlocking a file
}

sub import {
foreach (@_) {
    $NASTY_WARNINGS=0, next if (/[:-]?no_nasty_warnings/);
    $AVOID_SYMLINKS=0, next if (/[:-]?dont_avoid_symlinks/);
    $USE_FLOCK=0,      next if (/[:-]?no_flock/);
    $USE_FLOCK=1,      next if (/[:-]?use_flock/);
    if (/[:-]?extra_secure/ || /[:-]?paranoid_secure/) {
	$CGI::PRIVATE_TEMPFILES=1;
	$CGI::POST_MAX=1024*10;
	$CGI::DISABLE_UPLOADS = /[:-]?paranoid_secure/;
	next;
    } elsif (/[:-]?no_secure/) {
	$CGI::PRIVATE_TEMPFILES=0;
	$CGI::POST_MAX=-1;
	$CGI::DISABLE_UPLOADS=0;
	next;
    }
}
}

}

sub new 
{
    #Obtain the class (should be CGI::SecureState in most cases)
    my ($self) = shift;

    #populate the argument array
    my %args=($_[0]=~ /^\s*-/) ? @_ : (-stateDir => shift(), -mindSet => shift(), -memory => shift(), -key => shift());

    #Set up the CGI object to our liking
    my $cgi=new CGI;

    #We don't want any nassssty tricksssy people playing with things that we
    #should be setting ourselves
    $cgi->delete('.statefile');
    $cgi->delete('.cipher');
    $cgi->delete('.isforgetful');
    $cgi->delete('.memory');
    $cgi->delete('.age');
    $cgi->delete('.errormsg');

    #if the user has an error message subroutine, we should use it:
    $cgi->{'.errormsg'}=$args{'-errorSub'} || $args{'-errorsub'} || undef;

    #set the directory where we will store saved information
    my $statedir=$args{'-stateDir'} || $args{'-statedir'} || ".";

    #set the forgetfulness;  By default, this is "forgetful" because it encourages
    #cleaner programming, but if the user is upgrading from 0.2x series, this will likely be
    #blank; if so set to unforgetful and give them a few nasty warning messages.

    $args{'-mindSet'}||=$args{'-mindset'};
    if (!defined $args{'-mindSet'}) {
	$cgi->{'.isforgetful'}=undef;
    } else {
	$cgi->{'.isforgetful'}=($args{'-mindSet'}=~/unforgetful/i) ? 0 : 1;
	$cgi->{'.isforgetful'}=$1 if ($args{'-mindSet'}=~/(\d)/);
    }

    #Set up memory
    my $newmemory=0;

    if (ref($args{'-memory'}) eq 'ARRAY') {
	$cgi->{'.memory'}={map {$_ => 1} @{$args{'-memory'}}};
	$newmemory=1;
    } else {
	$cgi->{'.memory'}={};
    }
    
    #Set up the encryption part
    my $id=$cgi->param('.id')|| &sha1_hex($args{'key'} or rand().rand().(time()^rand()).
					  ($CGI::SecureState::counter+=rand()));
    my $remote_addr=$ENV{'REMOTE_ADDR'};
    my $remoteip=pack("CCCC", split (".", $remote_addr));
    my $key=pack("H*",$id).&sha1($remoteip);
    $cgi->{'.cipher'}=Crypt::Blowfish->new($key);
    
    #Set up (and untaint) the name of the location to store data
    my $statefile=&sha1_base64($id.$remote_addr);
    $statefile =~ tr|+/|_-|;
    $statefile =~ /([\w-]{27})/;
    $statefile=File::Spec->catfile($statedir,$1);
    $cgi->{'.statefile'}=$statefile;
    
    #convert $cgi into a CGI::SecureState object
    bless $cgi, $self;

    #if this is not a new session, attempt to read from the state file
    $cgi->param('.id') ? $cgi->recover_memory : $cgi->param(-name => '.id', -value => $id);

    #save any changes to the state file; if there are none, then update the timestamp
    ($newmemory || !$cgi->{'.isforgetful'}) ? $cgi->save_memory : $cgi->encipher;

    #finish
    return $cgi;
}

sub add
{
    my ($self)=shift;
    my ($isforgetful,$memory)=@$self{'.isforgetful','.memory'};
    if (ref($_[1]) eq 'ARRAY') {
	my %params=@_;
	foreach my $param (keys %params) {
	    $self->param($param, @{$params{$param}});
	    $isforgetful ? $memory->{$param}=1 : delete($memory->{$param});
	}
    } else {
	$self->param(@_);
	$isforgetful ? $memory->{$_[0]}=1 : delete($memory->{$_[0]});
    }
    $self->save_memory;
}

sub remember
{
    my ($self)=shift;
    my ($isforgetful,$memory)=@$self{'.isforgetful','.memory'};
    $isforgetful ? $memory->{shift()}=1 : delete($memory->{shift()}) while (@_);
    $self->save_memory;
}

sub delete
{
    my ($self)=shift;
    my ($isforgetful,$memory)=@$self{'.isforgetful','.memory'};
    while (@_) {
	delete $memory->{$_[0]} if ($isforgetful);
	$self->SUPER::delete(shift);
    }
    $self->save_memory;
}

sub delete_all
{
    my ($self)=shift;
    my ($statefile, $cipher, $isforgetful, $memory, $age, $errormsg) = 
	@$self{'.statefile','.cipher','.isforgetful','.memory','.age','.errormsg'};
    my $id=$self->param('.id');
    $self->SUPER::delete_all();
    $self->param('.id' => $id);
    @$self{'.statefile','.cipher','.isforgetful','.memory','.age','.errormsg'} = 
	($statefile, $cipher, $isforgetful, $memory, $age, $errormsg);
    $memory={} if ($isforgetful);
    $self->save_memory;
}

sub delete_session
{
    my ($self)=shift;
    (unlink $self->{'.statefile'}) or $self->errormsg('failed to delete the state file');
    $self->SUPER::delete_all;
}

sub params
{
    my $self=shift;
    return $self->param unless (@_);
    my @values;
    foreach my $param (@_) {
	push @values, scalar $self->param($param);
    }
    return @values;
}

sub age
{
    my ($self)=shift;
    if (defined $self->{'.age'}) {
	my $current_time=unpack("N",pack("N",time()));
	return (($current_time-$self->{'.age'})/24/3600);
    }
    return 0;
}

sub state_url
{
    my ($self)=shift;
    return $self->script_name()."?.id=".$self->param('.id');
}

sub state_param
{
    my ($self)=shift;
    return ".id=".$self->param('.id');
}

sub state_field 
{ 
    my ($self) = shift;
    return $self->hidden('.id' => $self->param('.id')); 
}


sub start_html { 
    my $self=shift;
    my $isforgetful=$self->{'.isforgetful'};
    if ($NASTY_WARNINGS && ! defined $isforgetful) {
	my $complaint='The author of this script failed to set the \'-mindSet\' attribute when creating '.
	    'the CGI::SecureState object associated with this dynamic web-enabled application.  Please contact '.
	    'him/her and tell him/her to read the updated CGI::SecureState documentation.';
	warn("The author of the script at ".$self->url." failed to set the '-mindSet' attribute when creating".
	     "the CGI::SecureState object.  Please tell him/her to read the updated CGI::SecureState documentation!");
	return $self->SUPER::start_html(@_).$complaint;
    }
    return $self->SUPER::start_html(@_);
}

sub errormsg {
    my $self=shift;
    if (ref($self->{'.errormsg'}) eq 'CODE') {
	$self->{'.errormsg'}->(@_) && exit;
    }
    my $error = shift;
    print $self->header;
    print $self->start_html(-title => "Server Error: \u$error.", -bgcolor => "white");
    print "<br>", $self->h1("The following error was encountered:");
    if ($error =~ /^failed/) {
	print("<p>The server $error, which is a file manipulation error.  This is most likely due to a bug in ",
	      "the referring script or a permissions problem on the server.</p>");
    } elsif ($error eq "symlink encountered") {
	print("<p>The server encountered a symlink in the state file directory.  This is usually the sign of an ",
	      "attemped security breach and has been logged in the server log files.  It is unlikely that you are ",
	      "responsible for this error, but it is nonetheless fatal.</p>");
	warn("CGI::SecureState FATAL error: Symlink encountered while trying to access $self->{'.statefile'}");
    } elsif ($error eq "invalid state file") {
	print("The file that stores information about your session has been corrupted on the server. ",
	      "This is usually the sign of an attemped security breach and has been logged in the server ",
	      " log files.  It is unlikely that you are responsible for this error, but it is nonetheless fatal.</p>");
	warn("CGI::SecureState FATAL error: The state file $self->{'.statefile'} became corrupted.");
    } elsif ($error eq "statefile inconsistent with mindset") {
	print("The mindset of the statefile is different from that specified in the referring script.  This is",
	      " most likely a bug in the referring script, but could also be due to a file permissions problem.</p>");
    } else {
	print "<p>$error.</p>";
	warn("CGI::SecureState FATAL error: $error.");
    }
    print $self->end_html;
    exit;
}

sub save_memory {
    my $self=shift;
    my (@values,@params,$param);
    my ($isforgetful,$memory)=@$self{'.isforgetful','.memory'};

    #If we are forgetful, then we need to save the contents of our memory
    #If we remember stuff, then we need to save everything but the contents of our memory
    foreach ($self->param)  {
	next if ($isforgetful xor (exists $memory->{$_}));
	next if ($_ eq '.id');
	if (@params=$self->param($_)) {
	    foreach $param (@params) { $param =~ s/([ \\])/\\$1/go }  #escape meta-characters
	    push @values, join("  ",@params), $_;
	}
    }
    
    push @values, $isforgetful ? "Forgetful" :  "Remembering";
    push @values, "Saved-Values";

    $self->encipher(@values);
}


sub recover_memory {
    my $self=shift;
    my (@data,$param,@values, $value);
    my ($isforgetful,$memory)=@$self{'.isforgetful','.memory'};

    @data=$self->decipher;

    if (@data) {
	#skip over fields until we get to the Saved-Values section
	#to retain compatibility with later versions of CGI::SecureState
	do { $param=pop(@data) } while ($param ne "Saved-Values" && @data);

	#check to make sure that our mindset is the same as the statefile's
	$param=pop @data;
	$self->errormsg('statefile inconsistent with mindset') if ($isforgetful and $param ne "Forgetful");
	$self->errormsg('statefile inconsistent with mindset') if (!$isforgetful and $param ne "Remembering");

	while (@data) {
	    $param=pop @data;
	    @values=split(/\ \ /, pop @data);
	    next if (!$isforgetful && (exists($memory->{$param}) || defined $self->param($param)));
	    foreach $value (@values) { $value =~ s/\\(.)/$1/go } #unescape meta-characters
	    $self->param($param,@values);
	    $self->{'.memory'}->{$param}=1 if ($isforgetful);
	}
    }
}



#The encipher subroutine accepts a list of values to encrypt and writes them to
#the state file.  If the list of values is empty, it merely updates the timestamp
#of the state file.
sub encipher {
    my ($self,@values)=@_;
    my ($cipher,$statefile)=@$self{'.cipher','.statefile'};
    my ($length,$time,$buffer,$block);
    $time=pack("N",time());

    if ($AVOID_SYMLINKS) { -l $statefile and $self->errormsg('symlink encountered')}

    #only update the timestamp if we've got nothing to write
    unless (@values) {
	sysopen(STATEFILE,$statefile, O_RDWR | O_CREAT, 0600 ) || $self->errormsg('failed to open the state file');
	if ($USE_FLOCK) { flock(STATEFILE, $FLOCK_WFLAGS) || $self->errormsg('failed to lock the state file') }
	binmode STATEFILE;
	if (sysread(STATEFILE,$buffer,16)==16) {
	    #the length of the encrypted data is stored in the first four bytes of the state file
	    $length=substr($cipher->decrypt(substr($buffer,0,8)),0,4);
	    $buffer=$length.($time^substr($buffer,12,4));
	} else {
	    $length=pack("N",0);
	    $buffer=$length.$time;
	}
	sysseek(STATEFILE,0,SEEK_SET);
	syswrite(STATEFILE,$cipher->encrypt($buffer),8);
    }
    else {
	sysopen(STATEFILE,$statefile, O_WRONLY | O_TRUNC | O_CREAT, 0600 ) 
	    || $self->errormsg('failed to open the state file');
	if ($USE_FLOCK) { flock(STATEFILE, $FLOCK_WFLAGS) || $self->errormsg('failed to lock the state file') }
	binmode STATEFILE;

	#escape line-feeds ("\n")  and backslashes ('\') in the values because they have special meanings
	foreach (@values) { s/\\/\\\\/go; s/\n/\\\n/go; }
	
	#join the list together
	$buffer=join("\n\n",@values);

	#add metadata to the beginning
	$length=length($buffer);
	$buffer=pack("N",$length).$time.$buffer;

	#pad the buffer to have a length that is divisible by 8
	if ($length%=8) {
	    $length=8-$length;
	    $buffer.=chr(int(rand(256))) while ($length--);
	}

	#encrypt in reverse-CBC mode
	$block=$cipher->encrypt(substr($buffer,-8,8));
	substr($buffer,-8,8,$block);

	$length=length($buffer) - 8;
	while(($length-=8)>-8) {
	    $block^=substr($buffer,$length,8);
	    $block=$cipher->encrypt($block);
	    substr($buffer,$length,8,$block);
	}

	#blast it to the file
	syswrite(STATEFILE,$buffer,length($buffer));
    }
    if ($USE_FLOCK) { flock(STATEFILE, $FLOCK_UFLAGS) || $self->errormsg('failed to unlock the state file') }
    close(STATEFILE) || $self->errormsg('failed to close the state file');
}


sub decipher {
    my ($self)=shift;
    my ($cipher,$statefile)=@$self{'.cipher','.statefile'};
    my ($length,$extra,$decoded,$buffer,$block,@values);

    if ($AVOID_SYMLINKS) { -l $statefile and $self->errormsg('symlink encountered')}
    sysopen(STATEFILE,$statefile, O_RDONLY) || $self->errormsg('failed to open the state file');
    if ($USE_FLOCK) { flock(STATEFILE, $FLOCK_RFLAGS) || $self->errormsg('failed to lock the state file') }
    binmode STATEFILE;

    #read metadata
    sysread(STATEFILE,$block,8);
    $block=$cipher->decrypt($block);

    #if there is nothing in the file, only set the age; otherwise read the contents
    unless (sysread(STATEFILE,$buffer,8)==8) {
	$self->{'.age'}=unpack("N",substr($block,4,4));
	@values=();
    } else {
	#parse metadata
	$block^=$buffer;
	$self->{'.age'}=unpack("N",substr($block,4,4));
	$length=unpack("N",substr($block,0,4));
	$extra = ($length % 8) ? (8-($length % 8)) : 0;
	$decoded=-8;

	#sanity check
	if ((stat(STATEFILE))[7] != ($length+$extra+8)) 
	{ $self->errormsg('invalid state file') }

	#read the rest of the file
	sysseek(STATEFILE, 8, SEEK_SET);
	unless (sysread(STATEFILE,$buffer,$length+$extra) == ($length+$extra)) 
	{ $self->errormsg('invalid state file') }

	my $next_block;
	$block=$cipher->decrypt(substr($buffer,0,8));
	#decrypt it
	while (($decoded+=8)<$length-8) {
	    $next_block = substr($buffer,$decoded+8,8);
	    $block^=$next_block;
	    substr($buffer, $decoded, 8, $block);
	    $block=$cipher->decrypt($next_block);
	}
	substr($buffer, $decoded, 8, $block);
	substr($buffer,-$extra,$extra) = "";

	#separate it
	@values=split(/\n\n/,$buffer);

	#unescape "\n" and '\'
	foreach (@values) { s/\\(.)/$1/go; }
    }
    if ($USE_FLOCK) { flock(STATEFILE, $FLOCK_UFLAGS) || $self->errormsg('failed to unlock the state file') }
    close(STATEFILE) || $self->errormsg('failed to close the state file');

    return(@values);
}

"True Value";

=head1 NAME

CGI::SecureState -- Transparent, secure statefulness for CGI programs

=head1 SYNOPSIS

    use CGI::SecureState;

    my ($optional_state_dir,$optional_rand)=("states","gf8w7reh7");
    my @memory = qw(param1 param2 other_params_to_remember);
    my $cgi = new CGI::SecureState(-stateDir => $optional_state_dir,
                                   -mindSet => 'forgetful',
                                   -memory => \@memory,
                                   -key => $optional_rand);
    print $cgi->header(); 
    my $url = $cgi->state_url(); 
    my $param = $cgi->state_param();
    print "<a href=\"$url\">I am a stateful CGI session.</a>";
    print "<a href=\"other_url.pl?$param\">I am a different ",
          "script that also has access to this session.</a>";


=head2 Very Important Note for Current Users

For current users who would otherwise skip reading the rest of the file, CGI::SecureState
has changed enormously between the 0.2x series and version 0.30.  The most visible change
will appear if you try to run your old scripts unchanged under CGI::SecureState.  If you
do so, you will receive nasty warnings (for most people this means both in the output web 
page and your log files) that will alert you to the fact that you need to specify a mindset
for your scripts.  If you installed this module from the CPAN, you should also have received
a notice to read this documentation.  Please do so, as this mysterious mindset business
(as well as all the scrumptious new features will shortly be explained).

Of course, any and all comments on the changes above are welcome.  If you are interested, 
send mail to behroozi@cpan.org with the subject "CGI::SecureState Comment".


=head1 DESCRIPTION

A Better Solution to the stateless problem

HTTP is a stateless protocol; a HTTP server closes the connection after serving
an object. It retains no memory of the request details and doesn't relate
subsequent requests with what it has already served.

There are a few methods available to deal with this problem, such as cookies and
fields in forms, but they have many limitations and may not work on older browsers.

CGI::SecureState solves this problem by introducing persistent CGI sessions
that store their data on the server side in an encrypted state file.  CGI::SecureState 
is similar in purpose to CGI::Persistent (and retains much of the same user
interface) but has a completely different implementation.  For those of you
who have worked with CGI::Persistent before, you will be pleased to learn that
CGI::SecureState was designed to work with Perl's taint mode and has worked
flawlessly with mod_perl and Apache::Registry for more than a year.  
CGI::SecureState was designed from the ground up for security, a fact which may
rear its ugly head if anybody tries to do something tricksy.

=head1 MINDSETS

If you were curious about the mindset business mentioned earlier, this section
is for you.  In the past, CGI::SecureState had only one mind-set, which was to
remember everything and anything that the client web page sent to it.  Besides
causing severe bloat of the session file, this behavior led to all sorts of 
insidious bugs where parameters saved by one web page would continue to lurk in the
state file and cause problems in web pages down the line.

As a result, it was necessary to include the idea of different mindsets in 
CGI::SecureState 0.30.  The old mindset remains, slightly modified, in the
form of the "unforgetful" mindset.  In this mindset, CGI::SecureState will
save (and recall) all the parameters passed to the script excepting those
that are in its "memory".  The new mindset available is the "forgetful"
mindset which will save (and recall) everything in "memory" and nothing else.

You may wonder why "memory" is in quotes.  The answer is simple: you pass
the "memory" to the CGI::SecureState object when it is initialized.  So, to
have a script that remembers everything except the parameters "foo" and "bar", 
do

    my $cgi = new CGI::SecureState(-mindSet => 'unforgetful',
                                   -memory => [qw(foo bar)]);

but to have a script that forgets everything except the parameters "user" and
"pass", you would do instead

    my $cgi = new CGI::SecureState(-mindSet => 'forgetful',
                                   -memory => [qw(user pass)]);

Simple, really.  In accord with the mindset of Perl, which is that methods should
Do the Right Thing, the "forgetful" mindset will remember parameters when you
tell it to, and not forget them until you decide that it should be so.  This means
that if you have a script to handle logins, like

    my $cgi = new CGI::SecureState(-mindSet => 'forgetful',
                                   -memory => [qw(user pass)]);

then other scripts do not have to re-memorize the "user" and "pass" parameters;
a mere

    my $cgi = new CGI::SecureState(-mindSet => 'forgetful');
    my ($user,$pass) = ($cgi->param('user'),$cgi->param('pass'));

would suffice.  However, if you read the rest of the documentation, that last line 
could even have been

    my ($user,$pass) = $cgi->params('user','pass');

Once you all see how more intuitive this new mindset is, I am sure that you 
will make the switch, but, in the meantime, the 'unforgetful' mindset remains.

One more note about mindsets.  In order to retain compatibility with older
scripts, the "unforgetful" mindset will allow CGI parameters received from
a client to overwrite previously saved parameters on disk.  The new
"forgetful" mindset discards parameters from clients if they already exist
on disk.  A future version of CGI::SecureState may make this behavior
separate from the mindset.


=head1 METHODS 

CGI::SecureState inherits its methods from CGI.pm, overriding them as necessary.

=over 4

=item B<new()>

Creates a new CGI object and creates an associated state file and key 
if none already exist.  new() has exactly one required argument (the mindset,
of course!), and takes three optional arguments.  If the mindset is not
specified, then CGI::SecureState will spit out nasty warnings until you
change your scripts or set $CGI::SecureState::NASTY_WARNINGS to 0.

The mindset may be specified in a few different ways, the most common being
to spell out 'forgetful' or 'unforgetful'.  If it pleases you, you may also 
use '1' to specify forgetfulness, and '0' to specify unforgetfulness.

The optional arguments include the "memory" of the object (as an array
reference), the directory in which state files should be stored 
(otherwise they will get dumped in whatever the current directory is!), 
random data for key generation (only necessary if you are concerned
about the randomness generated by the module itself), and a subroutine
reference to override the built-in error printing subroutine. 

A quick note about that last one.  Many people have complained about the
menacing nature of the warnings and errors produced by CGI::SecureState
and have wanted a quick and easy way to print out their own.  Now they
have it.  The subroutine should print out a complete web page and include
the "Content-Type" header.  The possible errors that can be caught by the
subroutine are:

    failed to close the state file
    failed to delete the state file
    failed to lock the state file
    failed to open the state file
    failed to unlock the state file
    invalid state file
    statefile inconsistent with mindset
    symlink encountered

If the subroutine can handle the error, it should return a true value,
otherwise it should return false.

Examples: 

    #forget everything but the "user" and "pass" params.
    $cgi = new CGI::SecureState(-mindSet => 'forgetful',
                                -memory => [qw(user pass)]);


    #invoke the old behavior of CGI::SecureState
    $cgi = new CGI::SecureState(-mindSet => 'unforgetful');
    $cgi = new CGI::SecureState(-mindSet => 0); #same thing

    #full listing
    $cgi = new CGI::SecureState(-stateDir => $statedir, 
				-mindSet => $mindset, 
				-memory => \@memory,
				-errorSub => \&errorSub,
				-key => $key);

    #if you don't like my capitalizations, then try
    $cgi = new CGI::SecureState(-statedir => $statedir, 
				-mindset => $mindset, 
				-memory => \@memory,
				-errorsub => \&errorSub,
				-key => $key);

    #if you prefer the straight argument style (note absence of
    #errorSub -- it is only supported with the new argument style)
    $cgi = new CGI::SecureState($statedir, $mindset, \@memory, $key);

    #cause nasty warnings
    $cgi = new CGI::SecureState;


=item B<state_url()>

Returns the URL of the current script with the state identification string
attached. This URL should be used for referring to the stateful session 
associated with the query.


=item B<state_param()>

Returns a key-value pair that you can use to retain the session when linking 
to other scripts.  If, for example, you want the script "other.pl" to be able
to see your current script's session, you would use

    print "<a href=\"other.pl?",$cgi->state_param,
           "\">Click Here!</a>";

to do so.


=item B<state_field()>

Returns a hidden INPUT type for inclusion in HTML forms. Like state_url(),
this element is used in forms to refer to the stateful session associated
with the query.



=item B<params()>

Allows you to get the scalar values of multiple parameters at once.

    my ($user,$pass) = $cgi->params(qw(user pass));

is equivalent to

    my ($user,$pass) = (scalar $cgi->params('user'),
                        scalar $cgi->params('pass'));



=item B<add()>

This command adds a new parameter to the CGI object and stores it to disk.
Use this command if you want something to be saved, since the param() method
will only temporarily set a parameter.  add() uses the same syntax as param(), 
but you may also add more than one parameter at once if the values are in a 
reference to an array:

    $cgi->add(param_a => ['value'], param_b => ['value1', 'value2']);



=item B<remember()>

This command is similar to add(), but saves current parameters to disk instead
of new ones.  For example, if "foo" and "bar" were passed in by the user and
were not previously stored on disk,

    $cgi->remember('foo','bar');

will save their values to the state file.



=item B<delete()>

delete() is an overridden method that deletes named attributes from the 
query.  The state file on disk is updated to reflect the removal of 
the parameter.  Note that this has changed to accept a list of params to
delete because otherwise the state file would be seperately rewritten for
each delete().

Important note: Attributes that are NOT explicitly delete()ed will lurk
about and come back to haunt you unless you use the 'forgetful' mindset!



=item B<delete_all()>

This command toasts all the current cgi parameters, but it merely clears 
the state file instead of deleting it.  For that, use delete_session() instead.



=item B<delete_session()>

This command not only deletes all the cgi parameters, but kills the 
disk image of the session as well. This method should be used when you 
want to irrevocably destroy a session.



=item B<age()>

This returns the time in days since the session was last accessed.

=back



=head1 GLOBALS

You may set these options to globally affect the behavior of CGI::SecureState.

=over 4

=item B<NASTY_WARNINGS>

Set this to 0 if you want warnings about deprecated behavior to be suppressed.
This is especially true if you want to be left in peace while updating scripts based 
on older versions of CGI::SecureState.  However, the warnings issued should be heeded
because they generally result in better coding style and program security.

You may either do
    use CGI::SecureState qw(:no_nasty_warnings); #or
    $CGI::SecureState::NASTY_WARNINGS = 0;


=item B<AVOID_SYMLINKS>

Set this to 0 if you don't want CGI::SecureState to test for the presence of a symlink
before writing to a state file.  If this is set to 1 and CGI::SecureState sees a 
symlink in place of a real file, it will spit out a fatal error.  It is generally
a good idea to keep this in place, but if you have a good reason to, then do
    use CGI::SecureState qw(:dont_avoid_symlinks); #or
    $CGI::SecureState::AVOID_SYMLINKS = 1;


=item B<USE_FLOCK>

Set this to 0 if you do not want CGI::SecureState to use "flock" to assure that
only one instance of CGI::SecureState is accessing the state file at a time.
Leave this at 1 unless you really have a good reason not to.

For users running a version of Windows NT (including 2000 and XP), you should set
this variable to 1 because $^O will always report "MSWin32", regardless of whether
your system is Win9x (which does not support flock) or WinNT (which does).

To set to 0, do
    use CGI::SecureState qw(:no_flock); #or
    $CGI::SecureState::USE_FLOCK = 0;

To set to 1, do
    use CGI::SecureState qw(:use_flock); #or
    $CGI::SecureState::USE_FLOCK = 1;


=item B<Extra and Paranoid Security>

If the standard security is not enough, CGI::SecureState provides extra security
by setting the appropriate options in CGI.pm.  The ":extra_security" option
enables private file uploads and sets the maximum size for a CGI POST to be
10 kilobytes.  The ":paranoid_security" option disables file uploads entirely.
To use them, do
    use CGI::SecureState qw(:extra_security);  #or
    use CGI::SecureState qw(:paranoid_security);

To disable them, do
    use CGI::SecureState qw(:no_security);
=back


=head1 EXAMPLES

This example is a simple log-in script.  It should have a directory called "states" 
that it can write to.

  #!/usr/bin/perl -wT
  use CGI::SecureState qw(:paranoid_security);

  my $cgi = new CGI::SecureState(-stateDir => 'states', 
                                 -mindSet => 'forgetful');

  my ($user,$pass,$lo)=$cgi->params(qw(user pass logout));
  my $failtime = $cgi->param('failtime') || 0;

  print $cgi->header();
  $cgi->start_html(-title => "CGI::SecureState Example");

  if ($user ne 'Cottleston' || $pass ne 'Pie') {
    if (defined $user) {
      $failtime+=$cgi->age()*86400;
      print "Incorrect Username/Password. It took you only ",
	     $cgi->age*86400, " seconds to fail this time.";
      print " It has been $failtime seconds since you started.";
      $cgi->add(failtime => $failtime);
    }
    print $cgi->start_form(-action => $cgi->url());
    print $cgi->state_field();
    print "\n<b>Username: </b>", $cgi->textfield("user");
    print "\n<br><b>Password: </b>", $cgi->password_field("pass");
    print "<br>",$cgi->submit("Login"),$cgi->reset;
    print $cgi->end_form;
  } elsif (! defined $lo) {
    print "You logged in!\n<br>";
    print "Click <a href=\"",$cgi->url,"?",$cgi->state_param;
    print ";logout=true\">here</a> to logout.";
    $cgi->remember('user','pass');
  } else {
    print "You have logged out.";
    $cgi->delete_session;
  }
  print $cgi->end_html;

This example will show a form that will tell you what what previously
entered.  It should have a directory called "states" that it can write to.


  #!/usr/bin/perl -wT
  use CGI::SecureState qw(:paranoid_security);

  my $cgi = new CGI::SecureState(-stateDir => 'states', 
                                -mindSet => 'unforgetful');
  print $cgi->header(); 
  $cgi->start_html(-title => "CGI::SecureState test", 
		 -bgcolor => "white");
  print $cgi->start_form(-action => $cgi->url());
  print $cgi->state_field();
  print "\n<b>Enter some text: </b>";
  print $cgi->textfield("input","");
  print "<br>",$cgi->submit,$cgi->reset;
  print $cgi->end_form;
  print "\n<br><br><br>";

  unless (defined $cgi->param('num_inputs')) {
      $cgi->add('num_inputs' => '1');
  }
  else {
      $cgi->add('num_inputs' => ($cgi->param('num_inputs')+1));
  }
  $cgi->add('input'.$cgi->param('num_inputs') => 
  	  $cgi->param('input')); 
  $cgi->delete('input');

  foreach ($cgi->param()) {
      print "\n<br>$_ -> ",$cgi->param($_) if (/input/);
  }
  print $cgi->end_html;

=head1 BUGS

There are B<no known bugs> with the current version.  However, take note
of the limitations section.

If you do find a bug, you should send it immediately to
behroozi@www.pls.uni.edu with the subject "CGI::SecureState Bug".
I am I<not responsible> for problems in your code, so make sure
that an example actually works before sending it.  It is merely acceptable
if you send me a bug report, it is better if you send a small
chunk of code that points it out, and it is best if you send a patch--if
the patch is good, you might see a release the next day on CPAN.
Otherwise, it could take weeks . . .



=head1 LIMITATIONS

Crypt::Blowfish is the only cipher that CGI::SecureState is using
at the moment.  Change at your own risk.

CGI.pm has its own funky way of doing state persistence that 
CGI::SecureState does NOT override.  This includes setting default
values for form input fields.  If this becomes problematic,
use the -override setting when calling things like hidden().

Many of the previous limitations of CGI::SecureState have been 
removed in the 0.30 version.  


CGI::SecureState requires:


Long file names (at least 27 chars): needed to ensure remote ticket 
authenticity.


Crypt::Blowfish: it couldn't be called "Secure" without.  At some point in
the future (as better algorithms become available), this
requirement may be changed.  Tested with versions 2.06, 2.09.


Digest::SHA1: for super-strong (160 bit) hashing of data.  It is used in
key generation and filename generation.  Tested with versions 1.03, 2.01.


CGI.pm: it couldn't be called "CGI" without.  Should not be a problem as it
comes standard with Perl 5.004 and above.  Tested with versions
2.56, 2.74, 2.79.

Fcntl: for file flags that are portable (like LOCK_SH and SEEK_SET).  Comes
with Perl.  Tested with version 1.03.

File::Spec: for concatenating directories and filenames in a portable way.
Comes with Perl.  Tested with version 0.82.

Perl: Hmmm.  Tested with v5.6.[01].  This module has NOT been tested with
5.005 or below.  Use at your own risk.  There may be several bugs
induced by lower versions of Perl, which are not limited to the failure 
to compile, the failure to behave properly, or the mysterious absence
of your favorite pair of lemming slippers.  The author is
exempt from wrongdoing and liability in case you decide to use
CGI::SecureState with a Perl less than 5.6.0.


=head1 SEE ALSO 

  CGI(3), CGI::Persistent(3)

=head1 AUTHORS

Peter Behroozi, behroozi@www.pls.uni.edu

=cut
