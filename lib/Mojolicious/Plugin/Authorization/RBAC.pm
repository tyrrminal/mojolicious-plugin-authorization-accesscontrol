package Mojolicious::Plugin::Authorization::RBAC;
use v5.26;

#ABSTRACT: provides Role-Based Access Control for Mojolicious applications

=encoding UTF-8

=head1 NAME

Mojolicious::Plugin::Authorization::RBAC - provides Role-Based Access Control
for Mojolicious applications

=head1 SYNOPSIS

  $self->plugin('Authorization::RBAC' => {get_roles => sub($c) {...}});

  # in, e.g., controller
  use Mojolicious::Plugin::Authorization::RBAC qw(priv role any_role);

  BEGIN {
    role(admin => [
      priv(Book => 'add'),
      priv(Book => 'remove'),
      priv(Book => 'edit'),
      priv(Book => 'list'),
    ]);
    any_role(
      priv(Book => 'read'),
      priv(Book => 'search'),
    );
  }

  # action of route('Book#edit')
  sub edit($self) {
    return $self->render(status => 401) unless($self->authz->permitted(Book => 'edit'));
    ...
  }

In this simple static example, admin users (see L</get_roles>) will pass the 
check and continue into the C<edit> implementation, while others will receive an 
C<unauthorized> error.

Some applications may function this way, but for most, a bit more granularity is
required:

  BEGIN {
    role(admin => [
      priv(Book => 'remove'),
      priv(Book => 'edit'),
      priv(Book => 'list'),
    ]);
    any_role(
      priv(Book => 'add'),
      priv(Book => 'read',   {owned  => true}),
      priv(Book => 'read',   {public => true}),
      priv(Book => 'search', {owned  => true}),
      priv(Book => 'search', {public => true}),
      priv(Book => 'edit',   {owned  => true}),
      priv(Book => 'remove,  {owned  => true}),
    );
  }

  sub edit($self) {
    my $book = db->model('book')->get($self->param('id'));
    return $self->render(status => 401) unless($self->authz->permitted(Book => 'edit', 
      {owned => $book->owner->id == $self->current_user->id, public = $book->is_public }));
    ...
  }
  
In this example, we've aded some restrictions to our rules. Restrictions are 
key/value pairs which impose additional qualifications on a privilege. All 
restrictions of a privilege must be met for the it to pass, but multiple rules 
can be created with different restrictions -- if any passes, the privilege is 
considered granted. Therefore, in this example, the edit operation will fail, 
except in any of the following cases:

=over

=item * if the user has the C<admin> role

=item * if the book's C<is_public> property is true

=item * if the user is the book's owner

=back

This works well enough, but can be a bit verbose, especially if you need to pass
multiple permissons checks.

  BEGIN {
    any_role(
      priv(Book => 'edit', {owner => true}),
      priv(Book => 'edit', {public => true}),
    );
  }

  sub extract_attrs($c, $ctx) {
    +{
      owned => $ctx->owner->id == $c->current_user->id,
      public => $ctx->is_public
    }
  }

  sub edit($self) {
    my $book = db->model('book')->get($self->param('id'));
    return $self->render(status => 401) unless($self->authz->permitted(Book => 'edit', {}, $book));
    ...
  }

By registering...

Finally, the L<yield|/authz.yield-($cb,-@args)> method can be used to cleanly
isolate the code that obtains instances of protected data from the code that
consumes them. The value returned by the C<$cb> callback is passed through the
attribute callback, and then those attributes are used to determine whether to
grant or deny access. The produced value is accessible only from the C<granted>
callback. See L<Mojolicious::Plugin::Authorization::YieldResult> for more
information.

  BEGIN {
    any_role(
      priv(Book => 'edit', {owner => true}),
      priv(Book => 'edit', {public => true}),
    );
  }

  sub extract_attrs($c, $ctx) {
    +{
      owned => $ctx->owner->id == $c->current_user->id,
      public => $ctx->is_public
    }
  }

  sub edit($self) {
    try {
      my $book = $self->authz->yield(sub() {
        db->model('book')->get($self->param('id'));
      }, Book => 'edit')
      ->granted(sub ($book) {
        # handle edit logic here
        $book->update(...);
        $self->render(json => $book)
      })
      ->denied(sub() {
        # if all privilege checks fail
        return $self->render(status => 401)
      })
      ->null(sub() {
        # if the value returned by the sub is undef
        return $self->render(status => 404)
      })
    } catch($e) {
      # if any die/croak/raise occurs
      return $self->render(status => 400, text => $e)
    }
  }

This module also supports dynamic privileges - these are rules that are registered
for a single Request, so they can be loaded from the database at the beginning
of each request, ensuring that they are always up-to-date.

  $app->plugin('Authorization::RBAC' => {
    get_roles => sub($c) {
      [
        $c->current_user_roles->@*, # static roles, e.g., from Authorization Server
        map { $_->name } $c->current_user->groups # dynamic roles from database
      ];
    }
  })

  # get rules from database and register them on request controller
  $app->hook(before_dispatch => sub($c) {
    foreach my $g (db->model('group')->all) {
      $c->authz->role($g->name => [
        map { priv(Book => $_->permission, {
          book_id => $_->book_id
        }) } $g->book_permissions->all
      ]);
    }
  });

  BEGIN {
    any_role(
      priv(Book => 'edit', {owner => true}),
      priv(Book => 'edit', {public => true}),
    );
  }

  # match the restrictions in the dynamic rules with Book-specific attributes
  helper(extract_attrs => sub($c, $ctx) {
    +{
      book_id => $ctx->id,
    }
  });

Now, when the privileges are checked, the user's group must match, and the 
C<book_id> attribute must also match, allowing for fine-grained privilege
application.

=head1 DESCRIPTION

This plugin provides facilities for role-based access control in Mojolicious, 
allowing you to declaratively add access control rules via a simple interface.

Several pathways are available to handle application authorization workflows, 
depending on the complexity and other requirements of the application. Static
rules can be declared via the functional interface: L</priv>, L</role>, and 
L</any_role>. These rules exist for the application's lifetime and should be
used for giving unprivileged users their base permissions or giving admin users
superuser permissions.

Dynamic rules can be added to the current request only by calling the matching
L<authz.role|/authz.role-($role-=E<gt>-\@privs,...)> and 
L<authz.any_role|/authz.any_role-(@privs)> helpers on the request controller object.
These rules will not exist beyond the current request, so they can be loaded in
from the database before processing each request, ensuring that any runtime
changes to these rules are taken into account. There is a corresponding 
L<authz.priv|/authz.priv-($resource,-$action-[,-$attrs])> helper, but as it and 
L</priv> simply return a 
L<Privilege|Mojolicious::Plugin::Authorization::RBAC::Privilege> object without 
registering it, there is no difference between these. The helper version is merely
provided as a convenience.

When it comes to checking privileges, a few options are available as well. The
simplest is the L<authz.permitted|/authz.permitted-($resource,-$action-[,-$attrs])> 
helper. Or, you can use L<authz.yield|/authz.yield-($cb,-@args)> to invoke the 
L<Mojolicious::Plugin::Authorization::RBAC::YieldResult> workflow and ensure 
that privileged data objects are only made available to application logic once 
privilege checks are passed.

=cut

use Mojo::Base 'Mojolicious::Plugin';

use Exporter 'import';
use Mojolicious::Plugin::Authorization::RBAC::Privilege;
use Mojolicious::Plugin::Authorization::RBAC::YieldResult;
use Readonly;
use Syntax::Keyword::Try;

use experimental qw(signatures);

Readonly::Scalar my $DEFAULT_PREFIX => 'authz';

our @EXPORT_OK = qw(role priv any_role);

# Global datastore for static rules and callbacks
my @privs;

=head1 FUNCTIONS

The following functions can be exported by request. None are exported by default

=cut

sub _add_priv($priv, $container) {
  my @all_privs = @privs;
  if(defined($container)) {
    push(@all_privs, $container->@*);
  } else {
    $container = \@privs;
  }
  die('Invalid privilege object') unless(ref($priv) && $priv->isa('Mojolicious::Plugin::Authorization::RBAC::Privilege'));
  warn("Duplicate privilege skipped: $priv\n") and return if (grep { $priv->is_equal($_) } @all_privs);
  push($container->@*, $priv);
}

=head2 role($role => \@privs,...)

Declares role-specific static privileges.

Accepts a hash whose keys are role names (string) and whose values are ArrayRefs
of L<Privileges|Mojolicious::Plugin::Authorization::RBAC::Privilege>. Normally,
these privileges are created via the L</priv> function.

=cut

sub role(%params) {
  _role(\%params)
}

sub _role($params, $container = undef) {
  foreach my $role (keys($params->%*)) {
    die("Invalid RBAC role name: '$role'\n") if($role !~ /\w/);
    foreach($params->{$role}->@*) {
      $_->role($role);
      _add_priv($_, $container);
    }
  }
}

=head2 any_role(@privs)

Declares static privileges that apply to all users regardless of role

Accepts an array of 
L<Privileges|Mojolicious::Plugin::Authorization::RBAC::Privilege>. Normally,
these privileges are created via the L</priv> function.

=cut

sub any_role(@privs) {
  _any_role(\@privs)
}

sub _any_role($privs, $container = undef) {
  _add_priv($_, $container) foreach($privs->@*);
}

=head2 priv($resource, $action[, $restrictions])

Returns a L<Privilege|Mojolicious::Plugin::Authorization::RBAC::Privilege> object
for the passed resource/action and optional restrictions on that privilege.

N.B. the returned object is not registered and must be declared with, e.g.,
L</role>/L</any_role> to be used for 
L<authz.permitted|/authz.permitted-($resource,-$action-[,-$attrs])>  checks.

=cut

sub priv($resource, $action, $restrictions = {}) {
  Mojolicious::Plugin::Authorization::RBAC::Privilege->new(
    resource     => $resource,
    action       => $action,
    restrictions => $restrictions
  )
}

=head1 METHODS

L<Mojolicious::Plugin::Authorization::RBAC> inherits all methods from 
L<Mojolicious::Plugin> and implements the following new ones

=head2 register( \%params )

Register plugin in L<Mojolicious> application. Configuration is done via the
C<\%params> HashRef, given the following keys

=head4 get_roles

Sets the callback to produce the user's roles for role-checking. Must return
an ArrayRef of strings.

Default: C<sub($c) { $c-E<gt>current_user_roles }>

=head4 prefix

Sets the prefix used for helper methods and stash values. Documentation assumes
that this is left unchanged.

Default: C<authz>

=head4 log

Set an alternative L<Mojo::Log> instance for writing access log messages to. Set
to undef to disable authorization logging.

Default: C<app-E<gt>log>

=cut

sub register($self, $app, $args) {
  my $get_roles = $args->{get_roles} // sub($c) { $c->current_user_roles };
  my $log_f = sub($m) { $app->log->info($m) };
  if(exists($args->{log})) {
    if(defined($args->{log})) {
      if(ref($args->{log}) && $args->{log}->isa('Mojo::Log')) {
        $log_f = sub($m) { $args->{log}->info($m) };
      }
    } else {
      $log_f = sub {};
    }
  }

  my $prefix = $args->{prefix} // $DEFAULT_PREFIX;
  Readonly::Scalar my $REQ_PRIVS => "_${DEFAULT_PREFIX}.privs";

=head2 authz.priv ($resource, $action [, $attrs])

Functionally identical to L</priv>. Provided so that the import can be skipped
in contexts where only dynamic privileges are being created.

=cut

  $app->helper($prefix.'.priv' => sub($c, @params) { priv(@params) });

=head2 authz.role ($role => \@privs,...)

Registers privileges for one or more roles, as L</role> does.

If called on a request controller, the roles are dynamically added for that
request only. Otherwise, functions identically to the C</role> function.

=cut

  $app->helper($prefix.'.role' => sub($c, @params) {
    if($c->tx->connection) { # if this is a "real" controller, store the priv in stash
      $c->stash($REQ_PRIVS => []) unless(defined($c->stash($REQ_PRIVS)));
      _role({@params}, $c->stash($REQ_PRIVS));
    } else {
      role(@params);
    }
  });

=head2 authz.any_role (@privs)

Registers privileges for all users, as L</any_role> does.

If called on a request controller, the roles are dynamically added for that
request only. Otherwise, functions identically to the C</any_role> function.

=cut

  $app->helper($prefix.'.any_role' => sub($c, @params) { 
    if($c->tx->connection) { # if this is a "real" controller, store the priv in stash
      $c->stash($REQ_PRIVS => []) unless(defined($c->stash($REQ_PRIVS)));
      _any_role(\@params, $c->stash($REQ_PRIVS)); 
    } else {
      any_role(@params);
    }
  });

=head2 authz.permitted ($resource, $action [, $attrs, [, $value]])

Check if an action is allowed by privilege rules. Returns true if any registered
rule (static or dynamic) applies, false otherwise. Role, resource, action, and
all privilege attributes must match.

C<$resource> and C<$action> are strings, C<$attrs> is an optional HashRef of
static attributes, that is to say, attributes related to the request itself, and
not the specific data value(s) being requested. Dynamic attributes (those
related to the data value) can be extrapolated by passing the data C<value> as 
the final argument. An L<extraction method|/attribute-extraction> will then be 
called on this value and the result will be merged with the static C<$attrs> to 
determine the final attribute set. If the resource, action, and user's role(s) 
match any registered privilege, and that privilege's restrictions are met by the
attributes, then the permission check passes.

Logs a "granted" or "denied" message to the selected C<Mojo::Log> instance

=head4 Attribute Extraction

The module will look in a number of places to find an appropriate method to
extract the data value's authorization attributes, in order from most-specific
to most-general. The first match that is found is used and the rest are ignored
for that check. If L<prefix> has been changed, both the custom prefix and the 
default are checked, in that order. Any characters in C<$resource> and 
C<$action> that are not permitted in method names are replaced by C<_> 
underscore characters - with the exception that periods are also left in when
constructing helper names.

=over

=item * B<controller method> C<extract_attrs_$resource_$action>

=item * B<helper> C<$prefix.extract_attrs.$resource_$action>

=back

If no match is found, it continues without the C<$action>

=over

=item * B<controller method> C<extract_attrs_$resource>

=item * B<helper> C<$prefix.extract_attrs.$resource>

=back

And finally, without the C<$resource>

=over

=item * B<controller method> C<extract_attrs>

=item * B<helper> C<$prefix.extract_attrs>

=back

Regardless of which method is used, it receives one parameter (besides the 
controller object): the protected data value. It must return a HashRef (which
can be empty, but must not be undefined) of attribute labels and their 
corresponding values for the protected data.

=cut

  my $get_dyn_attrs = sub ($c, $ctx, $resource, $action) {
    return {} unless(defined($ctx));
    my @prefixes = ($DEFAULT_PREFIX);
    unshift(@prefixes, $prefix) if($prefix ne $DEFAULT_PREFIX);

    my $n = 'extract_attrs';
    foreach ([$resource, $action], [$resource], []) {
      my $cm = join('_', ($n, map { s/[^a-zA-Z0-9_]/_/gr } $_->@*));
      if($c->can($cm)) {
        try { return $c->$cm($ctx) } catch($e) { $c->log->warn($e); return {} }
      }
      foreach my $p (@prefixes) {
        my $hm = join('.', ($p, $n, join('_', $_->@*)));
        if(my $h = $c->app->renderer->get_helper($hm)) {
          try { return $h->($c, $ctx) } catch($e) { $c->log->warn($e); return {} }
        }
      }
    }
    return {};
  };

  $app->helper($prefix.'.permitted' => 
    sub($c, $resource, $action, $attrs = undef, $ctx = undef) {
      my @roles = $get_roles->($c)->@*;
      # merge dynamic attributes from ctx object into $attrs
      $attrs = {} unless(defined($attrs) && ref($attrs) eq 'HASH');
      my $dyn = $get_dyn_attrs->($c, $ctx, $resource, $action)//{};
      $attrs = {$attrs->%*, $dyn->%*};

      my @all_privs = (@privs, ($c->stash($REQ_PRIVS)||[])->@*);
      my @p = grep { $_->accepts(
        resource   => $resource, 
        action     => $action, 
        attributes => $attrs, 
        roles      => [@roles],
      ) } (@all_privs);

      if(@p) { $log_f->("[Authorization::RBAC] Granted: ".$p[0]); return 1; }
      my $role_str = @roles ? '['.join(',', @roles).'] ' : '';
      my $attr_str = '('.join(',',(map { "$_=".$attrs->{$_} } (keys(($attrs//{})->%*)))).')';
      my $check = sprintf("$role_str$resource => $action$attr_str");
      $log_f->("[Authorization::RBAC] Denied: $check");
      return 0;
    }
  );

=head2 authz.yield ($get_value_cb, $resource, $action, $attrs)

Yield a protected data value, if permitted. The first argument callback should
perform the minimum necessary to obtain the data value and immediately return it.
This value is then passed through C<extract_attrs> and the dynamic attributes 
are merged with the static C<$attrs> Hash passed in. Then 
L<authz.permitted|/authz.permitted-($resource,-$action-[,-$attrs])> is called
to check the resource/action/attrs against all registered privileges.

Returns a L<Mojolicious::Plugin::Authorization::RBAC::YieldResult>, upon which
callbacks may be registered to handle the result of the authorization check.

=cut
  
  $app->helper($prefix.'.yield' => 
    sub($c, $get_obj, $resource, $action, $attrs = {}) {

      my $obj = $get_obj->();
      # If we got back null from the callback, we'll create an empty yield result so the caller can handle it on ->nullyield
      return Mojolicious::Plugin::Authorization::RBAC::YieldResult->new(granted => undef, entity => undef) unless(defined($obj));
      # check permissions and create appropriate yield result object
      my $permitted = $c->app->renderer->get_helper($prefix)->($c)->permitted($resource, $action, $attrs, $obj);
      return Mojolicious::Plugin::Authorization::RBAC::YieldResult->new(granted => 1, entity => $obj) if($permitted);
      return Mojolicious::Plugin::Authorization::RBAC::YieldResult->new(granted => 0, entity => undef);
    }
  );

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
