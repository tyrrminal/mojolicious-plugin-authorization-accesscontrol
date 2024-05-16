package Mojolicious::Plugin::Authorization::AccessControl;
use v5.26;
use warnings;

use Mojo::Base 'Mojolicious::Plugin';

use Authorization::AccessControl qw(ac);
use Readonly;

use experimental qw(signatures);

Readonly::Scalar my $DEFAULT_PREFIX => 'authz';

sub register($self, $app, $args) {
  my $prefix = $args->{prefix} // $DEFAULT_PREFIX;
  my $stash_ac = "_$prefix.request.accesscontrol";

  my $get_roles = $args->{get_roles} // sub($c) { $c->current_user_roles };
  
  my $log_f = sub($m) { $app->log->info($m) };
  if(exists($args->{log})) {
    if(defined($args->{log})) {
      if(ref($args->{log}) && $args->{log}->isa('Mojo::Log')) {
        $log_f = sub($m) { $args->{log}->info($m) };
      }
    } else { $log_f = sub {} }
  }

  my $get_ac = sub($c) {
    my $ac = ac;
    if($c->tx->connection) {
      $c->stash($stash_ac => ac->clone) unless(defined($self->stash($stash_ac)));
      $ac = $self->stash($stash_ac);
    }
    return $ac;
  }

  $app->helper("$prefix.role" => sub ($c, @params) {
    return $get_ac->($c)->role(@params);
  });

  $app->helper("$prefix.grant" => sub ($c, @params) {
    return $get_ac->($c)->grant(@params);
  });

  my $get_dyn_attrs = sub ($c, $resource, $action) {
    my @prefixes = ($DEFAULT_PREFIX);
    unshift(@prefixes, $prefix) if($prefix ne $DEFAULT_PREFIX);

    my $n = 'extract_attrs';
    foreach ([$resource, $action], [$resource], []) {
      my $cm = join('_', ($n, map { s/[^a-zA-Z0-9_]/_/gr } $_->@*));
      if($c->can($cm)) {
        try { return sub($ctx) { $c->$cm($ctx) } } catch($e) { $c->log->warn($e); return {} }
      }
      foreach my $p (@prefixes) {
        my $ri = join('_', $_->@*);
        my $hm = join('.', ($p, $n, ($ri ? ($ri) : ()) ));
        if(my $h = $c->app->renderer->get_helper($hm)) {
          try { return sub($ctx) { $h->($c, $ctx) } } catch($e) { $c->log->warn($e); return {} }
        }
      }
    }
    return undef;
  };

  $app->helper("$prefix.predicate" => sub ($c, $resource = undef, $action = undef) {
    my $roles = $c->tx->connection ? $get_roles->($c) : [];
    
    my $pred = $get_ac->($c)->roles($roles->@*);
    $pred = $pred->perform($action) if(defined($action));
    $pred = $pred->on_resource($resource) if(defined($resource));
    my $f = $get_dyn_attr_f->($c, $resource, $action);
    $pred = $pred->with_get_attrs($f) if($f);

    return $pred;
  })
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
