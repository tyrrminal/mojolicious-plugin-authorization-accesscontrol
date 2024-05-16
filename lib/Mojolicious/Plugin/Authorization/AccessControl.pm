package Mojolicious::Plugin::Authorization::AccessControl;
use v5.26;
use warnings;

use Mojo::Base 'Mojolicious::Plugin';

use Authorization::AccessControl qw(acl);
use Readonly;
use Syntax::Keyword::Try;

use experimental qw(signatures);

Readonly::Scalar my $DEFAULT_PREFIX => 'authz';

sub register($self, $app, $args) {
  my $prefix = $args->{prefix} // $DEFAULT_PREFIX;
  my $stash_ac = "_$prefix.request.accesscontrol";

  my $get_roles = sub($c) { $c->current_user_roles };
  $get_roles = $args->{get_roles}//sub($c){[]} if(exists($args->{get_roles}));
  die("get_roles must be a CODEREF/anonymous subroutine") if(defined($get_roles) && ref($get_roles) ne 'CODE');
  
  my $log_f = sub($m) { $app->log->info($m) };
  if(exists($args->{log})) {
    if(defined($args->{log})) {
      if(ref($args->{log}) && $args->{log}->isa('Mojo::Log')) {
        $log_f = sub($m) { $args->{log}->info($m) };
      }
    } else { $log_f = sub {} }
  }

  acl->hook(on_permit => sub ($ctx) { $log_f->("[Authorization::AccessControl] Granted: $ctx") });
  acl->hook(on_deny   => sub ($ctx) { $log_f->("[Authorization::AccessControl] Denied: $ctx") });

  my $get_ac = sub($c) {
    my $ac = acl;
    if($c->tx->connection) {
      $c->stash($stash_ac => $ac->clone) unless(defined($c->stash($stash_ac)));
      $ac = $c->stash($stash_ac);
    }
    return $ac;
  };

  $app->helper("$prefix.acl" => sub ($c) {
    return $get_ac->($c);
  });

  $app->helper("$prefix.role" => sub ($c, @params) {
    return $get_ac->($c)->role(@params);
  });

  my @get_attrs;
  $app->helper("$prefix.dynamic_attrs" => sub ($c, @params) {
    my $get_attrs = { handler => pop(@params) };
    $get_attrs->{resource} = shift(@params) if(@params);
    $get_attrs->{action}   = shift(@params) if(@params);
    push(@get_attrs, $get_attrs);
  });

  my $get_get_attrs = sub ($resource, $action) {
    my @c = @get_attrs;
    @c = grep { !defined($_->{resource}) || $_->{resource} eq $resource } @c if(defined($resource));
    @c = grep { !defined($_->{action}) || $_->{action} eq $action } @c if(defined($action));
    @c = sort { defined($b->{resource}) + defined($b->{action}) - (defined($a->{resource}) + defined($a->{action})) } @c;
    return ($c[0]//{})->{handler};
  };

  $app->helper("$prefix.request" => sub ($c, $resource = undef, $action = undef) {
    my $roles = [];
    try { $roles = $get_roles->($c) } catch($e) {}
    
    my $req = $get_ac->($c)->request->with_roles($roles->@*);
    $req = $req->with_action($action) if(defined($action));
    $req = $req->with_resource($resource) if(defined($resource));
    if(my $f = $get_get_attrs->($resource, $action)) {
      $req = $req->with_get_attrs(sub($ctx){ $f->($c, $ctx) });
    }

    return $req;
  });
}


=head1 AUTHOR

Mark Tyrrell C<< <mark@tyrrminal.dev> >>

=head1 LICENSE

Copyright (c) 2024 Mark Tyrrell

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

=cut

1;

__END__
