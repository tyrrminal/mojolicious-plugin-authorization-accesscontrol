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
      priv(Book => 'read',   [qw(owned)]),
      priv(Book => 'read',   [qw(public)]),
      priv(Book => 'search', [qw(owned)]),
      priv(Book => 'search', [qw(public)]),
      priv(Book => 'edit',   [qw(owned)]),
      priv(Book => 'remove,  [qw(owned)]),
    );
  }

  sub edit($self) {
    my $book = db->model('book')->get($self->param('id'));
    return $self->render(status => 401) unless($self->authz->permitted(Book => 'edit', 
      {owned => $book->owner->id == $self->current_user->id, public = $book->is_public }));
    ...
  }
  
In this example, we've aded some attributes to our rules. Attributes are simple
strings which express additional qualifications of a rule. All attributes of a 
rule must be met for the rule to pass, but multiple rules can be created with
different attributes -- if any rule passes, the privilege is granted. Therefore,
in this example, the edit operation will fail, except in any of the following cases:

=over

=item * if the user has the C<admin> role

=item * if the book's C<is_public> property is true

=item * if the user is the book's owner

=back

This works well enough, but can be a bit verbose, especially if you need to pass
multiple permissons checks

  BEGIN {
    any_role(
      priv(Book => 'edit', [qw(owner)]),
      priv(Book => 'edit', [qw(public)]),
    );
    attr_cb(Book => sub($c, $ctx) {
      +{
        owned => $ctx->owner->id == $c->current_user->id,
        public => $ctx->is_public
      }
    })
  }

  sub edit($self) {
    my $book = db->model('book')->get($self->param('id'));
    return $self->render(status => 401) unless($self->authz->context($book)->permitted(Book => 'edit'));
    ...
  }

By registering an attribute callback with L</attr_cb> and establishing an authz
L<context|/authz.context-($value)> prior to checking privileges, the entity's attributes 
will be calculated for you.

Finally, the L<yield|/authz.yield-($cb,-@args)> method allows you to guard the 
privileged data retrieval and establish context at the same time, preventing any
inadvertent leakage of data. With this approach, permission denials are thrown 
as exceptions -- L<Syntax::Keyword::Try>'s C<typed> exception functionality is 
helpful for handling these (though not required).

  BEGIN {
    any_role(
      priv(Book => 'edit', [qw(owner)]),
      priv(Book => 'edit', [qw(public)]),
    );
    attr_cb(Book => sub($c, $ctx) {
      +{
        owned => $ctx->owner->id == $c->current_user->id,
        public => $ctx->is_public
      }
    })
  }

  use Symtax::Keyword::Try qw(try :experimental(typed));

  sub edit($self) {
    try {
      my $book = $self->authz->yield(sub() {
        db->model('book')->get($self->param('id'));
      }, Book => 'edit');
      # handle edit logic here
      $book->update(...);
    } catch($e isa Authorization::RBAC::NullYield) {
      # thrown if the value returned by the sub is undef
      return $self->render(status => 404)
    } catch($e isa Authorization::RBAC::Failure) {
      # thrown if all privilege checks fail
      return $self->render(status => 401)
    } catch($e) {
      return $self->render(status => 400)
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
        map { priv(Book => $_->permission, [
          sprintf('book_id[%d]', $_->book_id)
        ]) } $g->book_permissions->all
      ]);
    }
  });

  BEGIN {
    any_role(
      priv(Book => 'edit', [qw(owner)]),
      priv(Book => 'edit', [qw(public)]),
    );
    # match the attributes created in the dynamic rules with per-Book attributes
    attr_cb(Book => sub($c, $ctx) {
      +{
        sprintf('book_id[%d]', $ctx->id) => 1,
      }
    })
  }

Now, when the privileges are checked, the user's group must match, and the 
C<book_id[n]> attribute must also match, allowing for fine-grained privilege
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
helper, which can be optionally provided an C<attributes> array or combined with 
a data context via the L<authz.context|/authz.context-($value)> helper and the 
corresponding L</attr_cb> callback. Or, you can use 
L<authz.yield|/authz.yield-($cb,-@args)> to invoke the exception-based workflow 
and ensure that privileged data objects are only made available to application 
logic once privilege checks are passed.

=cut

use Mojo::Base 'Mojolicious::Plugin';

use Exporter 'import';
use Mojo::Exception qw(raise);
use Mojolicious::Plugin::Authorization::RBAC::Privilege;
use Readonly;
use Syntax::Keyword::Try;

use experimental qw(signatures);

Readonly::Scalar my $PREFIX => 'authz';

Readonly::Scalar my $PRIV_CLASS       => 'Mojolicious::Plugin::Authorization::RBAC::Privilege';

Readonly::Scalar my $EXCEPTION_UNAUTH => 'Authorization::RBAC::Failure';
Readonly::Scalar my $EXCEPTION_NULL   => 'Authorization::RBAC::NullYield';

our @EXPORT_OK = qw(role priv any_role attr_cb);

# Global datastore for static rules and callbacks
my @privs;
my %cb;

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

=head2 priv($resource, $action[, $attrs])

Returns a L<Privilege|Mojolicious::Plugin::Authorization::RBAC::Privilege> object
for the passed resource/action and optional attributes.

N.B. the returned object is not registered and must be declared with, e.g.,
L</role>/L</any_role> to be used for 
L<authz.permitted|/authz.permitted-($resource,-$action-[,-$attrs])>  checks.

=cut

sub priv($resource, $action, $attrs = []) {
  Mojolicious::Plugin::Authorization::RBAC::Privilege->new(
    resource   => $resource,
    action     => $action,
    attributes => $attrs
  )
}

=head2 attr_cb($resource, sub($c, $ctx) {...})

Registers a callback for a given resource type. The callback receives the 
controller object and the RBAC context as arguments, and returns a HashRef of
attributes which apply to that context whose values are boolean.

=cut

sub attr_cb($resource, $cb) {
  $cb{$resource} = $cb;
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

  my $prefix = $args->{prefix} // $PREFIX;
  Readonly::Scalar my $REQ_PRIVS => "_${prefix}.privs";
  Readonly::Scalar my $REQ_CTX   => "_${prefix}.ctx";

=head2 authz.priv ($resource, $action [, $attrs])

Identical to L</priv>

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

=head2 authz.context ($value)

Sets a value as the authorization context for the current request. This value is
typically the data being guarded by privilege rules, e.g., a database record 
object. Setting a context allows L</attr_cb> callbacks to render attributes for
evaluation.

Chainable, e.g.,

  $c->authz->context($my_book)->permitted(Book => 'edit');

=cut

  $app->helper($prefix.'.context'  => sub($c, $ctx) {
    if($c->tx->connection) {
      $c->stash->{$REQ_CTX} = $ctx; $c->app->renderer->get_helper($prefix)->($c) 
    } else {
      die("[Authorization::RBAC] context can only be set from active request controller")
    }
  });

=head2 authz.permitted ($resource, $action [, $attrs])

Check if an action is allowed by privilege rules. Returns true if any registered
rule (static or dynamic) applies, false otherwise. Role, resource, action, and
all privilege attributes must match.

C<$resource> and C<$action> are strings, C<$attrs> is an optional HashRef whose
keys are strings and values are booleans.

Logs a "granted" or "denied" message to the selected C<Mojo::Log> instance

=cut

  $app->helper($prefix.'.permitted' => 
    sub($c, $resource, $action, $attrs = undef) {
      my @roles = $get_roles->($c)->@*;
      if(!defined($attrs) && $cb{$resource}) {
        try { $attrs = $cb{$resource}->($c, $c->stash->{$REQ_CTX}) } catch($e) { warn($e)}
      }
      
      my @p = grep { 
           $_->match_role(@roles)        
        && $_->match_resource($resource) 
        && $_->match_action($action)     
        && $_->match_attributes($attrs)  
      } (@privs, ($c->stash($REQ_PRIVS)||[])->@*);

      if(@p) { $log_f->("[Authorization::RBAC] Granted: ".$p[0]); return 1; }
      $log_f->("[Authorization::RBAC] Denied: [".join(', ', @roles)."] $resource => $action(".join(', ', grep { $attrs->{$_} } keys($attrs->%*)).")"); return 0;
    }
  );

=head2 authz.yield ($cb, @args)

Produce a guarded data value, if permitted. The first argument callback should
perform the minimum necessary to obtain the data value, and return it. This
value is then automatically set as the request's authorization context, and then
the privilege rules are evaluated. If the callback returns C<undef>, an 
C<Authorization::RBAC::NullYield> exception is thrown.

C<@args> must be in one of two possible formats. For a single privilege check,
C<($resource, $action [, $attrs])>, just like the arguments to 
L<authz.permitted|/authz.permitted-($resource,-$action-[,-$attrs])>

However, in some cases, multiple privileges should be checked before the data
should be yielded. For example, a photo gallery app might check both the 
C<media.view> and C<media.view.full_size> privileges before rendering a 
full-size image. In these cases, an array of 
L<Privileges|Mojolicious::Plugin::Authorization::RBAC::Privilege> (as from 
L</priv>) may be passed instead -- however, please note that only the
L<resource|Mojolicious::Plugin::Authorization::RBAC::Privilege/resource> and
L<action|Mojolicious::Plugin::Authorization::RBAC::Privilege/action> properties
are respected on these objects. 

An authorization log message is emitted for each privilege checked.

If all privilege checks pass, the data is returned. If any check fails, an
C<Authorization::RBAC::Failure> exception is thrown.

=cut
  
  $app->helper($prefix.'.yield' => 
    sub($c, $cb, @args) {
      my ($resource, $action, $attrs);
      if(!ref($args[0]) || !$args[0]->isa($PRIV_CLASS)) {
        ($resource, $action, $attrs) = @args;
        @args = (priv($resource, $action));
      }

      my $authz = $c->app->renderer->get_helper($prefix)->($c);
      # if $attrs exists, we don't need to evaluate the callback to populate it, so we can fail fast
      if($attrs) { raise($EXCEPTION_UNAUTH, 'Unauthorized') unless($authz->permitted($resource, $action, $attrs)) };
      my $obj = $cb->();
      # If we got back null from the callback, proceeding is nonsense, so let the caller catch that specific exception
      raise($EXCEPTION_NULL, 'RBAC yield callback returned undef') unless(defined($obj));
      $authz->context($obj);
      # Once the context is set, we can check permitted with evaluated attrs
      if(!$attrs) { foreach (@args) { raise($EXCEPTION_UNAUTH, 'Unauthorized') unless($authz->permitted($_->resource, $_->action)) } }
      return $obj;
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
