package Mail::SpamAssassin::Plugin::Fromnamespoof;
my $VERSION = 0.3;

use strict;
use Mail::SpamAssassin::Plugin;
use List::Util ();

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

sub dbg { Mail::SpamAssassin::Plugin::dbg ("Fromnamespoof: @_"); }

# constructor: register the eval rule
sub new
{
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->set_config($mailsaobject->{conf});

  # the important bit!
  $self->register_eval_rule("check_fromname_spoof");
  $self->register_eval_rule("check_fromname_different");
  $self->register_eval_rule("check_fromname_contains_email");
  $self->register_eval_rule("check_fromname_equals_to");
  $self->register_eval_rule("check_fromname_owners_differ");
  $self->register_eval_rule("check_fromname_spoof_high_profile");
  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds = ();

  push (@cmds, {
    setting => 'fns_add_addrlist',
    type => 5,
    code => sub {
      my($conf, $key, $value, $line) = @_;
      local($1,$2);
      if ($value !~ /^ \( (.*?) \) \s+ (.*) \z/sx) {
        return '-99999999999999';
      }
      my $listname = "FNS_$1";
      $value = $2;
      $conf->{parser}->add_to_addrlist ($listname, split(/\s+/, $value));
    }
  });

  push (@cmds, {
    setting => 'fns_remove_addrlist',
    type => 5,
    code => sub {
      my($conf, $key, $value, $line) = @_;
      local($1,$2);
      if ($value !~ /^ \( (.*?) \) \s+ (.*) \z/sx) {
        return '-99999999999999';
      }
      my $listname = "FNS_$1";
      $value = $2;
      $conf->{parser}->remove_from_addrlist ($listname, split (/\s+/, $value));
    }
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub check_fromname_different
{
  my ($self, $pms) = @_;

  if (!defined $pms->{fromname_contains_email}) {
    _check_fromnamespoof($self, $pms);
  }

  return $pms->{fromname_address_different};

}

sub check_fromname_spoof
{
  my ($self, $pms) = @_;

  if (!defined $pms->{fromname_contains_email}) {
    _check_fromnamespoof($self, $pms);
  }

  return ($pms->{fromname_address_different} && $pms->{fromname_owner_different});

}

sub check_fromname_contains_email
{
  my ($self, $pms) = @_;

  if (!defined $pms->{fromname_contains_email}) {
    _check_fromnamespoof($self, $pms);
  }

  return $pms->{fromname_contains_email};

}

sub check_fromname_equals_to
{
  my ($self, $pms) = @_;

  if (!defined $pms->{fromname_contains_email}) {
    _check_fromnamespoof($self, $pms);
  }

  return $pms->{fromname_equals_to_addr};
}

sub check_fromname_owners_differ
{
  my ($self, $pms) = @_;

  if (!defined $pms->{fromname_contains_email}) {
    _check_fromnamespoof($self, $pms);
  }

  return $pms->{fromname_owner_different};
}

sub check_fromname_spoof_high_profile
{
  my ($self, $pms) = @_;

  if (!defined $pms->{fromname_contains_email}) {
    _check_fromnamespoof($self, $pms);
  }

  return $pms->{fromname_different_high_profile};

}

sub _check_fromnamespoof
{
  my ($self, $pms) = @_;

  $pms->{fromname_contains_email} = 0;
  $pms->{fromname_address_different} = 0;
  $pms->{fromname_equals_to_addr} = 0;
  $pms->{fromname_domain_different} = 0;
  $pms->{fromname_owner_different} = 0;
  $pms->{fromname_different_high_profile} = 0;

  my $list_refs = {};

  foreach my $conf (keys %{$self->{main}{conf}}) {
    if ($conf =~ /^FNS_/) {
      $list_refs->{$conf} = $self->{main}{conf}{$conf};
    }
  }

  my %fnd = ();
  my %fad = ();
  my %tod = ();

  $fnd{'addr'} = $pms->get("From:name");

  if ($fnd{'addr'} =~ /\b([\w\.\!\#\$\%\&\'\*\+\/\=\?\^\_\`\{\|\}\~\-]+@[\w\-\.]+\.[\w\-\.]++)\b/i) {
    $pms->{fromname_contains_email} = 1;
    my $nochar = ($fnd{'addr'} =~ y/A-Za-z0-9//c);
    $nochar -= ($1 =~ y/A-Za-z0-9//c);

    return 0 unless ((length($fnd{'addr'})+$nochar) - length($1) <= 5);

    $fnd{'addr'} = lc $1;
  } else {
    return 0;
  }

  $fad{'addr'} = lc $pms->get("From:addr");
  my @toaddrs = $pms->all_to_addrs();
  $tod{'addr'} = lc $toaddrs[0];

  $fnd{'domain'} = Mail::SpamAssassin::Util::uri_to_domain($fnd{'addr'});
  $fnd{'owner'} = _find_address_owner($fnd{'addr'}, $list_refs);

  $fad{'domain'} = Mail::SpamAssassin::Util::uri_to_domain($fad{'addr'});
  $fad{'owner'} = _find_address_owner($fad{'addr'}, $list_refs);

  $tod{'domain'} = Mail::SpamAssassin::Util::uri_to_domain($tod{'addr'});
  $tod{'owner'} = _find_address_owner($tod{'addr'}, $list_refs);

  $pms->{fromname_address_different} = 1 if ($fnd{'addr'} ne $fad{'addr'});

  $pms->{fromname_domain_different} = 1 if ($fnd{'domain'} ne $fad{'domain'});

  $pms->{fromname_equals_to_addr} = 1 if ($fnd{'addr'} eq $tod{addr});

  if ($fnd{'owner'} ne $fad{'owner'}) {
    $pms->{fromname_owner_different} = 1;
    $pms->{fromname_different_high_profile} = 1 if ($fnd{'owner'} =~ /^hp_/);
  }

  if ($pms->{fromname_address_different}) {
    $pms->set_tag("FNS_FNAME_ADDR", $fnd{'addr'});
    $pms->set_tag("FNS_FADDR_ADDR", $fad{'addr'});
    $pms->set_tag("FNS_FNAME_OWNER", $fnd{'owner'});
    $pms->set_tag("FNS_FADDR_OWNER", $fad{'owner'});
    $pms->set_tag("FNS_FNAME_DOMAIN", $fnd{'domain'});
    $pms->set_tag("FNS_FADDR_DOMAIN", $fad{'domain'});

    dbg("From name spoof: $fnd{'addr'} $fnd{'domain'} $fnd{'owner'}");
    dbg("Actual From: $fad{'addr'} $fad{'domain'} $fad{'owner'}");
    dbg("To Address: $tod{'addr'} $tod{'domain'} $tod{'owner'}");
  }
}

sub _find_address_owner
{
  my ($check, $list_refs) = @_;
  foreach my $owner (keys %{$list_refs}) {
    foreach my $white_addr (keys %{$list_refs->{$owner}}) {
      my $regexp = qr/$list_refs->{$owner}{$white_addr}/i;
      if ($check =~ /$regexp/)  {
        $owner =~ s/FNS_//;
        return lc $owner;
      }
    }
  }

  my $owner = Mail::SpamAssassin::Util::uri_to_domain($check);
  $owner =~ /^([^\.]+)\./;
  return lc $1;
}

1;
