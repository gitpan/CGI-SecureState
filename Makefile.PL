use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'CGI::SecureState',
    'VERSION_FROM'	=> 'SecureState.pm',
    'PREREQ_PM'		=> {CGI => '2.0', Digest::SHA1 => '1.0', Crypt::Blowfish => '2.0'}
);
