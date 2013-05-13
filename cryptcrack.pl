#!/usr/bin/perl -w
#
# Copyright Dan Faerch 2010... http://the-blackhats.blogspot.com.br/
#
use Getopt::Std;
use Time::HiRes qw( usleep gettimeofday tv_interval);
use threads;
use threads::shared;
use Thread::Queue;
use Data::Dumper;

my $version       = "1.0";

my $maxQueue      = 5000; # Numero maximo de palavras no buffer
my $display_timer = 5;    # Number of seconds to sleep between output
my $threads_count = 4;
my $debug         = 0;    # 0,1 or 2
my $quiet         = 0;    # 0 or 1
my $passfile;

my $passwords = {};
my %opts;

my $wordlist          = Thread::Queue->new; 
my $found_passwords   = &share({});
my ($shutdown):shared = 0;
my $start_time        = [gettimeofday];
my $count:shared      = 0;
my $outfile:shared;


sub displayTimer {
    my $shown_passwords = {};
    while (!$shutdown) {
         sleep $display_timer;

         if (!$quiet) {
             print printf('%02.2f',($count / tv_interval ( $start_time, [gettimeofday])));
             print " keys por segundo.\n";
         }


         foreach (keys %$passwords) {
                 if ((defined $found_passwords->{$_}) && (!defined $shown_passwords->{$_})) {
                       print "FOUND: ".$found_passwords->{$_}." ($_)\n" if (!$quiet);
                       writeOutfile($found_passwords->{$_}." ($_)") if ($outfile);
                       $shown_passwords->{$_}=1;
                 }
         }

         print "queue size: ".$wordlist->pending()."\n" if ($debug);
         if (scalar(keys(%$passwords)) == scalar(keys(%$found_passwords))) {
                   print "No hashes left to crack\n" if (!$quiet);
                   $shutdown = 1;
                   return;
         }
         if (!$wordlist->pending()) { # Flag for shutdown if done with the wordlist
                   $shutdown = 1;
                   return;
         }

         $start_time = [gettimeofday];
         $count = 0;
    }
}

# This function just calles "crypt". 
sub doCrypt {
    my $type = shift;
    my $salt = shift;
    my $pass = shift;
    
    # This is redundant. Its just to show where to stick in any optimized versions of the algorithms
    if ($type eq '$6$') { # SHA-512
         return crypt($pass, $type . $salt);
    } else {
         return crypt($pass, $type . $salt);    
    }
}


# Takes a password, encrypts and compares to all hashes
sub crackingThread {
    my $id = shift;
    my $newhash;

    print "Thread $id is ready\n" if ($debug);

    while (!$shutdown) {
        unless (defined($pass = $wordlist->dequeue_nb())) {
            return if ($shutdown);

            print "Thread $id sleeping\n" if ($debug > 1);
            usleep 50000;
            next;
        }

        $count++;

        foreach my $ohash (keys %$passwords) {
             next if (defined $found_passwords->{$ohash}); # Dont spend time on passwords already cracked
             $newhash = doCrypt($passwords->{$ohash}->{'prefix'},$passwords->{$ohash}->{'salt'},$pass);
             
             #Search the $passwords hash for a match
             foreach (keys %$passwords) {
                   if ($newhash eq $_) {
                       lock($found_passwords);
                       $found_passwords->{$_} = $pass;
                   }
             }
        }
    }
}

sub selfTest {
    my $newhash = doCrypt('$6$', "/2CahJnQ", 'jamesdick');
    
    if (length $newhash != 98) {
               print "SHA512 Selftest failed. Hash output length is incorrect. Expected 98 chars, got ".length($newhash).". (maybe your system doesnt support SHA512(\$6\$) passwords)\n";
               exit 998;
    }
    if ($newhash ne '$6$/2CahJnQ$4cl6vYMRg/ytkZsfBDrBEORmneK45hqDC77KAdkW/NgPumKHwL04SXUequNzktFSEwHcdpLOF.gOSHfLyJvlo.') {
               print "SHA512 Selftest failed. Hash output does not match expected.\n";
               exit 999;
    }                 
}

sub addToPasswords {
    my $hash = shift;
    
    my $p;
    my $s;
    
    if ($hash =~ m/^(\$[a-z0-9]{1,3}\$)((?:[^\$]+\$)?[^\$]+)\$.+$/) {
                 $p = $1;
                 $s = $2;
    } elsif ($hash =~ m/^(..).+/) { # Old DES style passwords
                 $p = '';
                 $s = $1;
    } else {
                 return;
    }

    $passwords->{$hash}->{'prefix'} = $p;
    $passwords->{$hash}->{'salt'}   = $s;
    
}

sub readPasswordsFromFile {
    my $file = shift;
    open(F,$file);

    my $c = 0;
    while (<F>) {
          chomp;
          # Shadow format
          if (m/^([^:]+):([^:]+)/i) {
               addToPasswords($2);
               $c++;
               
          } elsif (m/.../) { # if not blank
               addToPasswords($_);
               $c++;
          }
    }

    close(F);

    print "Read $c hashes from file\n" if (!$quiet);
    print Dumper($passwords) if ($debug > 1);
}

sub usage() {
print <<EOD
Multithreaded cryptcracker by Dan Faerch, 2010. Version $version.

Usage: cat wordlist | $0 [options]

options:
  -f filename       Input file containing hashes (required)
  -o filename	     Output file where cracked passwords are appended (no default, optional)
  -t count           number of threads. should match number of CPU cores (default: 4)
  -d level           debug level 0 to 2 (default: 0)
  -i seconds         How often to print out status and found passwords
  -q                 quiet
EOD
;
exit 1;
}

sub writeOutfile {
    my $data = shift;

    open(OF,">>".$outfile);
    print OF $data."\n";
    close(OF);
}

sub getOpts {
    getopts('qd:t:f:o:i:',\%opts);

    $debug = $opts{d}           if (defined $opts{'d'});
    $quiet = 1                  if (defined $opts{'q'});
    $threads_count = $opts{'t'} if (defined $opts{'t'});
    $display_timer = $opts{'i'} if (defined $opts{'i'});
    
    if ($threads_count<1) {
          print "Cannot run with 0 threads\n";
          exit 1;
    }

    if (defined $opts{'o'}) {
          $outfile = $opts{'o'};
          # Test that outfile can be written.
          if (!open(OF,">>".$outfile)) {
                print "Unable to open outfile\n";
                exit 1;
          };
          close(OF);
    } elsif (defined $opts{'q'}) {
         print "Running in quiet mode, without saving to file, makes no sense.\n";
         exit 1;
    }

    if (!defined $opts{'f'}) {
        print "Error: Filename needed!\n\n";
        usage();
    } else {
        if (-f $opts{'f'}) {
                readPasswordsFromFile($opts{'f'});
                if (scalar(keys %$passwords) == 0) {
                      print "No passwords found in inputfile\n";
                      exit 1;
                }
        } else {
                print "Could not find file ".$opts{'f'}."\n";
                exit 1;
        }
    }
}

#---------------------------------------------------------
selfTest();
getOpts();


my $threads = {
      'display' => threads->new(\&displayTimer) # Start the display thread
};

print "Spawning $threads_count threads\n" unless ($quiet);
for (my $i=0;$i<$threads_count;$i++) {
         $threads->{$i} = threads->new(\&crackingThread,$i);
}

# Loop passwords from STDIN
while (<>) {
      chomp;
      $wordlist->enqueue($_);
      
      # Sleep a bit if queue is full
      if ($wordlist->pending > $maxQueue)  {
          usleep 200000;
      }
}

# Wait for shutdown
while (!$shutdown) {
      usleep 10000;
}

# Close threads nicely
foreach (keys %$threads) {
       print "Freeing thread $_\n" if ($debug > 1);
       $threads->{$_}->join();
}

if (!$quiet) {
   # Dump found passwords:
   print "\n\nCracked passwords:\n---------------\n";
   foreach (keys %$found_passwords) {
       print $found_passwords->{$_}." ($_)\n" if ($_);
   }
   print "\n";
}

1;
