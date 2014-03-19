package Apache::Authn::GoogleApps;
=head1 NAME

Apache::Authn::GoogleApps - Apache Auth module by Google Apps Account

=head1 SYNOPIS

このファイルをコピー
 /usr/lib/perl5/Apache/Authn/GoogleApps.pm

httpd.conf に

  PerlLoadModule Apache::Authn::GoogleApps
  <Location /svn>
     AuthType Basic
     AuthName GoogleAccount
     Require valid-user

     # ユーザ名に自動で補完するドメイン。
     GoogleAppsDomain example.com
     # 自動で補完するドメインをくっつけるタイミング。Always 常に None 付けない
     # Auto ユーザ名に @ が入っていなければくっつける（hoge と入れたら hoge@example.com にして認証）
     GoogleAppsDomainAppend Always
     # 認証に成功したらその結果をサーバにキャッシュしている時間（秒数）
     # キャッシュするけどスレッドごとに別っぽい（ARP::Pool）
     GoogleAppsCacheCredsMax 3600

     # ハンドラを使う宣言
     PerlAuthenHandler Apache::Authn::GoogleApps::handler
  </Location>

  and reload your apache

=head1 Git URL
  https://github.com/nazoking/perl-apache-authn-googleapps

=head1 AUTHOR

  nazoking "< nazoking@gmail.com >"

=cut

use strict;
use warnings FATAL => 'all', NONFATAL => 'redefine';

use LWP::UserAgent;
use Apache2::Module;
use Apache2::Access;
use Apache2::ServerRec qw();
use Apache2::RequestRec qw();
use Apache2::RequestUtil qw();
use Apache2::Const qw(:common :override :cmd_how);
use APR::Pool ();
use APR::Table ();
use Data::Dumper;

use 5.010;

my @directives = (
  {
    name => 'GoogleAppsDomain',
    req_override => OR_AUTHCFG, # allow overrides true
    args_how => TAKE1,  # One argument only (full description)
    errmsg => 'set your google apps domain ex "example.com"',
  },
  {
    name => 'SpecialAuthUserFile',
    req_override => OR_AUTHCFG, # allow overrides true
    args_how => TAKE1,  # One argument only (full description)
    errmsg => 'set your special auth user file path.',
  },
  {
    name => 'GoogleAppsDomainAppend',
    req_override => OR_AUTHCFG, # allow overrides true
    args_how => TAKE1,  # One argument only (full description)
    errmsg => 'value select None|Always|Auto',
  },
  {
    name => 'GoogleAppsCacheCredsMax',
    req_override => OR_AUTHCFG, # allow overrides true
    args_how => TAKE1,  # One argument only (full description)
    errmsg => 'cache time seconds. ex 3600',
  }
);
Apache2::Module::add(__PACKAGE__, \@directives);

sub GoogleAppsDomain{ set_val("GoogleAppsDomain", @_); }
sub GoogleAppsDomainAppend{ set_val("GoogleAppsDomainAppend", @_); }
sub SpecialAuthUserFile{ set_val("SpecialAuthUserFile", @_); }
sub GoogleAppsCacheCredsMax {
  my ($self, $parms, $arg) = @_;
  if ($arg) {
    $self->{GoogleAppsCachePool} = APR::Pool->new;
    $self->{GoogleAppsCacheCreds} = APR::Table::make($self->{GoogleAppsCachePool}, $arg);
    $self->{GoogleAppsCacheCredsMax} = $arg;
  }
}

sub set_val {
  my ($key, $self, $parms, $arg) = @_;
  $self->{$key} = $arg;
}

sub gapp_login{
  my $usr = shift;
  my $pass = shift;
  my $r = shift;
  my $lwp_object = LWP::UserAgent->new;
  my $url = 'https://www.google.com/accounts/ClientLogin';

  my $response = $lwp_object->post( $url, [
    'accountType' => 'HOSTED',
    'Email' => $usr, 'Passwd' => $pass,
    'service' => 'apps'
  ] );
  return $response->is_success;
}

sub cache_login_check{
  my ( $usr , $pass, $cfg, $r ) = @_;
  return 0 unless $cfg->{GoogleAppsCacheCreds};
  my $c = $cfg->{GoogleAppsCacheCreds}->get($usr);
  return 0 unless $c;
  my ($ctime,$cpass) = split(':',$c,2);
  cache_reflesh( $cfg, $r ) if $ctime < time();
  return $cpass eq $pass;
}

sub cache_reflesh{
  my $cfg = shift;
  my $r = shift;
  foreach my $key ( keys %{$cfg->{GoogleAppsCacheCreds}} ){
    my ( $ct, $cp ) = split(':',$cfg->{GoogleAppsCacheCreds}->get($key),2);
    if( $ct < time() ){
      $cfg->{GoogleAppsCacheCreds}->unset( $key );
    }
  }
}

sub cache_login_push{
  my ( $usr , $pass, $cfg, $r ) = @_;
  return 0 unless $cfg->{GoogleAppsCacheCreds};
  cache_reflesh( $cfg, $r );
  $cfg->{GoogleAppsCacheCreds}->set( $usr, ''.(time()+$cfg->{GoogleAppsCacheCredsMax}).':'.$pass );
  return 1;
}

# start add by bocelli
sub mkpasswd {
    my $passwd = shift;
    my $salt   = shift;
    my @chars  = ( '.', '/', 0 .. 9, 'A' .. 'Z', 'a' .. 'z' );
    my $Magic = '$apr1$';    # Apache specific Magic chars
    my $cryptType = (  $^O =~ /^MSWin/i ) ? "MD5" : "crypt";

    if ( $salt && $cryptType =~ /MD5/i && $salt =~ /^\Q$Magic/ ) {

        # Borrowed from Crypt::PasswdMD5
        $salt =~ s/^\Q$Magic//;       # Take care of the magic string if present
        $salt =~ s/^(.*)\$.*$/$1/;    # Salt can have up to 8 chars...
        $salt = substr( $salt, 0, 8 );    # That means no more than 8 chars too.
                                          # For old crypt only
    }
    elsif ( $salt && $cryptType =~ /crypt/i ) {
        if ($salt =~ /\$2a\$\d+\$(.{23})/) {
            $salt = $1;
        } else {
            # Make sure only use 2 chars
            $salt = substr( $salt, 0, 2 );
        }
    }
    else {

# If we use MD5, create apache MD5 with 8 char salt: 3 randoms, 5 dots
        if ( $cryptType =~ /MD5/i ) {
            $salt =
              join ( '', map { $chars[ int rand @chars ] } ( 0 .. 2 ) )
              . "." x 5;

            # Otherwise fallback to standard archaic crypt
        }
        else {
            $salt = join ( '', map { $chars[ int rand @chars ] } ( 0 .. 1 ) );
        }
    }

    if ( $cryptType =~ /MD5/i ) {
                require Crypt::PasswdMD5;
        return Crypt::PasswdMD5::apache_md5_crypt( $passwd, $salt );
    }
    else {
        return crypt( $passwd, $salt );
    }
}

sub loadPassFile {
    my $filename = shift;
    state %map;
    return %map if %map;
    open(my $fh, '<', $filename) or die "cannot open file $filename";
    while(my $line = <$fh>) {
        my @list = split(/:/, $line, 2);
        my $pass = $list[1];
        $pass =~ s/\n//;
        $map{$list[0]} = $pass;
    }
    close($fh);
    return %map;
}

sub checkuser {
    my ($usr, $pass, $filename) = @_;
    return 0 unless $filename;
    my %m = loadPassFile($filename);
    my $passCrypt = $m{$usr};
    return 0 unless $passCrypt;

    $pass = mkpasswd($pass, substr($passCrypt, 0, 2));
    #print "$pass   $passCrypt\n";
    return ($pass eq $passCrypt) ? 1: 0;
}
# end add by bocelli

sub handler {
  my $r = shift;
  my ( $st,$pw ) = $r->get_basic_auth_pw();
  my $cfg = Apache2::Module::get_config(__PACKAGE__, $r->server, $r->per_dir_config);
  my $usr = $r->user;

  return $st unless $st == Apache2::Const::OK;

  # add by bocelli to check domain
  return Apache2::Const::OK if checkuser($usr, $pw, $cfg->{SpecialAuthUserFile});

  $usr .= '@'.$cfg->{GoogleAppsDomain} if (( $cfg->{GoogleAppsDomainAppend} eq 'Auto' && $usr !~ /@/ ) || ( $cfg->{GoogleAppsDomainAppend} eq 'Always' )); 

  # add by bocelli to check domain
  my $pattern = '@' . $cfg->{GoogleAppsDomain};
  return AUTH_REQUIRED unless ($usr =~ /$pattern$/);

  if( defined $usr && defined $pw ){
    if( cache_login_check( $usr, $pw, $cfg, $r ) ){
      return Apache2::Const::OK;
    }elsif( gapp_login( $usr, $pw, $r ) ){
      cache_login_push( $usr, $pw, $cfg, $r );
      return Apache2::Const::OK;
    }
  }

  $r->note_auth_failure();
  return AUTH_REQUIRED;
}

1;
