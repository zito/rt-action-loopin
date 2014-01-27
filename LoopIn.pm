package RT::Action::LoopIn;

# SEE: http://wiki.bestpractical.com/view/AddWatchersOnCorrespond

# This scrip will add new watchers based on message headers, but
# only if the actor is authorized (is a requestor, cc, or admincc).

use strict;

use base qw(RT::Action);

my $scrip = 'Scrip:LoopIn';

# {{{ sub Describe
 sub Describe  {
    my $self = shift;
    return (ref $self . " add new watchers from to/cc list if actor is authorized.");
 }
 # }}}

# {{{ sub Prepare
 sub Prepare  {
    # nothing to prepare
    return 1;
 }
 # }}}

sub Commit {
   my $self = shift;
   my $Transaction = $self->TransactionObj;
   my $ActorAddr = $Transaction->CreatorObj->EmailAddress;
   my $Queue = $self->TicketObj->QueueObj;
   my $Ticket = $self->TicketObj;
   my $Id = $self->TicketObj->id;
   my @Authorized;
   my @Unauthorized;

   # assume it is NOT valid to loop in additional addresses
   my $loopin_authorized = 0;

   $RT::Logger->debug("$scrip: about to check if creator is authorized");

   # load email alias file, if present
   my %loopauth;
   my $loopauthfile = RT->Config->Get('WM_LoopAuth');
   if ($loopauthfile and my $fh = IO::File->new($loopauthfile)) {
      while (<$fh>) {
         chomp;
         s/^\s*//;        # strip leading whitespace
         s/\s*$//;        # strip trailing whitespace
         next if /^$/;    # skip blank lines
         next if /^#/;    # skip comment lines
         if (/^equiv\s+(\S+)\s+(\S+)$/i) {
            $loopauth{equiv}{lc($1)} = $2;
         }
         elsif (/^domain\s+(\S+)\s+(\S+)$/i) {
            $loopauth{domain}{lc($1)}->{lc($2)} = 1;
         }
         else {
            $RT::Logger->error("$scrip: unknown loopauth directive: $_");
         }
      }
   }

   # if actor is a requestor, cc or admincc, loopin is authorized
   if (my $Creator = $Transaction->CreatorObj) {
      my $Principal = $Creator->PrincipalId if $Creator->Id;
      $RT::Logger->debug("$scrip: creator principal ID: #$Principal");
      if (($Queue->IsCc($Principal) or
           $Queue->IsAdminCc($Principal) or
           $Ticket->IsCc($Principal) or
           $Ticket->IsAdminCc($Principal) or
           $Ticket->IsRequestor($Principal)
          )) {
         $loopin_authorized = 1;
         $RT::Logger->debug("$scrip: $ActorAddr is authorized to loop in additional watchers");
      }
   }

   $RT::Logger->debug("$scrip: about to extract candidate address list");

   # extract a list of to and cc addresses associated with this transaction
   for my $h (qw(To Cc)) {
      my $header = $Transaction->Attachments->First->GetHeader($h);
      for my $addrObj (Mail::Address->parse($header)) {
         # extract and normalize email address
         my $addr = lc $RT::Nobody->UserObj->CanonicalizeEmailAddress($addrObj->address);

         # ignore the specific addresses for this queue:
         next if lc $Queue->CorrespondAddress eq $addr or lc $Queue->CommentAddress eq $addr;

         # ignore any email address that looks like one for ANY of our queues:
         next if RT::EmailParser::IsRTAddress(, $addr);

         # normalize address if equivalence is defined
         if (defined($loopauth{equiv}{$addr})) {
            $RT::Logger->debug("$scrip: normalizing $addr to $loopauth{equiv}{$addr}");
            $addr = $loopauth{equiv}{$addr};
         }

         # ignore any email address that is already a watcher
         my $User = RT::User->new($RT::SystemUser);
         $User->LoadByEmail($addr);     # NOT LoadOrCreateByEmail
         my $Principal = $User->PrincipalId if $User->Id;
         next if ($Queue->IsCc($Principal) or
                  $Queue->IsAdminCc($Principal) or
                  $Ticket->IsCc($Principal) or
                  $Ticket->IsAdminCc($Principal) or
                  $Ticket->IsRequestor($Principal)
                 );

         # extend additional watchers list if authorized
         if ($loopin_authorized or domainauth($loopauth{domain}, $ActorAddr, $addr)) {
            $RT::Logger->debug("$scrip: Ticket #$Id correspondence contains header - $h: $addr");
            push @Authorized, $addr;
         }
         else {
            push @Unauthorized, $addr;
         }
      }
   }

   my $comment = "";

   if (@Unauthorized) {
      $comment .= "$ActorAddr made an unauthorized attempt to loop in the following:\n " . join("\n ", @Unauthorized) . "\n";
   }

   $RT::Logger->debug("$scrip: about to add candidate addresses as watchers");

   # add authorized candidates not already listed as watchers
   if (@Authorized) {
      my @looped;       # list of looped addresses
      my @failed;       # list of failed addresses
      for my $addr (@Authorized) {
         my $User = RT::User->new($RT::SystemUser);
         $User->LoadOrCreateByEmail($addr);
         my $Principal = $User->PrincipalId if $User->Id;
         # add the new watcher and check for errors
         my ($ret, $msg) = $Ticket->AddWatcher(
            Type  => 'Cc',
            Email => $addr,
            PrincipalId => $Principal,
         );
         if ($ret) {
            $RT::Logger->info("$scrip: New watcher added to ticket #$Id: $addr (#$Principal)");
            push(@looped, $addr);
         } else {
            $RT::Logger->error("$scrip: Failed to add new watcher to ticket #$Id: $addr (#$Principal) - $msg");
            push(@failed, $addr);
         }
      }
      if (@looped) {
         $comment .= "$ActorAddr successfully looped in the following:\n  " . join("\n  ", @looped) . "\n";
      }
      if (@failed) {
         $comment .= "$ActorAddr failed to loop in the following:\n  " . join("\n  ", @failed) . "\n";
      }
   }

   $Ticket->Comment(Content => $comment) if $comment;
}

sub domainauth {
   my $domainauth = shift;
   my $actor = shift;
   my $loopin = shift;
   my $loopin_domain;
   my $actor_domain;

   $RT::Logger->debug("$scrip: checking domainauth for $actor looping in $loopin");
   ($loopin_domain = $loopin) =~ s/^[^@]+@//;
   ($actor_domain = $actor) =~ s/^[^@]+@//;
   $RT::Logger->debug("$scrip: actor domain: $actor_domain, loopin domain: $loopin_domain");
   return 0 unless defined $domainauth;
   return 0 unless defined $domainauth->{$loopin_domain};
   return 1 if $domainauth->{lc($loopin_domain)}->{lc($actor)};
   return 1 if $domainauth->{lc($loopin_domain)}->{'*@'.lc($actor_domain)};
   return 0;
}

return 1;
