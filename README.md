# NAME

Mojolicious::Plugin::Authorization::RBAC - provides Role-Based Access Control
for Mojolicious applications

# SYNOPSIS

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

In this simple static example, admin users (see ["get\_roles"](#get_roles)) will pass the 
check and continue into the `edit` implementation, while others will receive an 
`unauthorized` error.

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

- if the user has the `admin` role
- if the book's `is_public` property is true
- if the user is the book's owner

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

By registering an attribute callback with ["attr\_cb"](#attr_cb) and establishing an authz
[context](#authz-context-value) prior to checking privileges, the entity's attributes 
will be calculated for you.

Finally, the [yield](#authz-yield-cb-args) method allows you to guard the 
privileged data retrieval and establish context at the same time, preventing any
inadvertent leakage of data. With this approach, permission denials are thrown 
as exceptions -- [Syntax::Keyword::Try](https://metacpan.org/pod/Syntax%3A%3AKeyword%3A%3ATry)'s `typed` exception functionality is 
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
`book_id[n]` attribute must also match, allowing for fine-grained privilege
application.

# DESCRIPTION

This plugin provides facilities for role-based access control in Mojolicious, 
allowing you to declaratively add access control rules via a simple interface.

Several pathways are available to handle application authorization workflows, 
depending on the complexity and other requirements of the application. Static
rules can be declared via the functional interface: ["priv"](#priv), ["role"](#role), and 
["any\_role"](#any_role). These rules exist for the application's lifetime and should be
used for giving unprivileged users their base permissions or giving admin users
superuser permissions.

Dynamic rules can be added to the current request only by calling the matching
[authz.role](#authz-role-role-privs) and 
[authz.any\_role](#authz-any_role-privs) helpers on the request controller object.
These rules will not exist beyond the current request, so they can be loaded in
from the database before processing each request, ensuring that any runtime
changes to these rules are taken into account. There is a corresponding 
[authz.priv](#authz-priv-resource-action-attrs) helper, but as it and 
["priv"](#priv) simply return a 
[Privilege](https://metacpan.org/pod/Mojolicious%3A%3APlugin%3A%3AAuthorization%3A%3ARBAC%3A%3APrivilege) object without 
registering it, there is no difference between these. The helper version is merely
provided as a convenience.

When it comes to checking privileges, a few options are available as well. The
simplest is the [authz.permitted](#authz-permitted-resource-action-attrs) 
helper, which can be optionally provided an `attributes` array or combined with 
a data context via the [authz.context](#authz-context-value) helper and the 
corresponding ["attr\_cb"](#attr_cb) callback. Or, you can use 
[authz.yield](#authz-yield-cb-args) to invoke the exception-based workflow 
and ensure that privileged data objects are only made available to application 
logic once privilege checks are passed.

# FUNCTIONS

The following functions can be exported by request. None are exported by default

## role($role => \\@privs,...)

Declares role-specific static privileges.

Accepts a hash whose keys are role names (string) and whose values are ArrayRefs
of [Privileges](https://metacpan.org/pod/Mojolicious%3A%3APlugin%3A%3AAuthorization%3A%3ARBAC%3A%3APrivilege). Normally,
these privileges are created via the ["priv"](#priv) function.

## any\_role(@privs)

Declares static privileges that apply to all users regardless of role

Accepts an array of 
[Privileges](https://metacpan.org/pod/Mojolicious%3A%3APlugin%3A%3AAuthorization%3A%3ARBAC%3A%3APrivilege). Normally,
these privileges are created via the ["priv"](#priv) function.

## priv($resource, $action\[, $attrs\])

Returns a [Privilege](https://metacpan.org/pod/Mojolicious%3A%3APlugin%3A%3AAuthorization%3A%3ARBAC%3A%3APrivilege) object
for the passed resource/action and optional attributes.

N.B. the returned object is not registered and must be declared with, e.g.,
["role"](#role)/["any\_role"](#any_role) to be used for 
[authz.permitted](#authz-permitted-resource-action-attrs)  checks.

## attr\_cb($resource, sub($c, $ctx) {...})

Registers a callback for a given resource type. The callback receives the 
controller object and the RBAC context as arguments, and returns a HashRef of
attributes which apply to that context whose values are boolean.

# METHODS

[Mojolicious::Plugin::Authorization::RBAC](https://metacpan.org/pod/Mojolicious%3A%3APlugin%3A%3AAuthorization%3A%3ARBAC) inherits all methods from 
[Mojolicious::Plugin](https://metacpan.org/pod/Mojolicious%3A%3APlugin) and implements the following new ones

## register( \\%params )

Register plugin in [Mojolicious](https://metacpan.org/pod/Mojolicious) application. Configuration is done via the
`\%params` HashRef, given the following keys

#### get\_roles

Sets the callback to produce the user's roles for role-checking. Must return
an ArrayRef of strings.

Default: `sub($c) { $c->current_user_roles }`

#### prefix

Sets the prefix used for helper methods and stash values. Documentation assumes
that this is left unchanged.

Default: `authz`

#### log

Set an alternative [Mojo::Log](https://metacpan.org/pod/Mojo%3A%3ALog) instance for writing access log messages to. Set
to undef to disable authorization logging.

Default: `app->log`

## authz.priv ($resource, $action \[, $attrs\])

Identical to ["priv"](#priv)

## authz.role ($role => \\@privs,...)

Registers privileges for one or more roles, as ["role"](#role) does.

If called on a request controller, the roles are dynamically added for that
request only. Otherwise, functions identically to the `/role` function.

## authz.any\_role (@privs)

Registers privileges for all users, as ["any\_role"](#any_role) does.

If called on a request controller, the roles are dynamically added for that
request only. Otherwise, functions identically to the `/any_role` function.

## authz.context ($value)

Sets a value as the authorization context for the current request. This value is
typically the data being guarded by privilege rules, e.g., a database record 
object. Setting a context allows ["attr\_cb"](#attr_cb) callbacks to render attributes for
evaluation.

Chainable, e.g.,

    $c->authz->context($my_book)->permitted(Book => 'edit');

## authz.permitted ($resource, $action \[, $attrs\])

Check if an action is allowed by privilege rules. Returns true if any registered
rule (static or dynamic) applies, false otherwise. Role, resource, action, and
all privilege attributes must match.

`$resource` and `$action` are strings, `$attrs` is an optional HashRef whose
keys are strings and values are booleans.

Logs a "granted" or "denied" message to the selected `Mojo::Log` instance

## authz.yield ($cb, @args)

Produce a guarded data value, if permitted. The first argument callback should
perform the minimum necessary to obtain the data value, and return it. This
value is then automatically set as the request's authorization context, and then
the privilege rules are evaluated. If the callback returns `undef`, an 
`Authorization::RBAC::NullYield` exception is thrown.

`@args` must be in one of two possible formats. For a single privilege check,
`($resource, $action [, $attrs])`, just like the arguments to 
[authz.permitted](#authz-permitted-resource-action-attrs)

However, in some cases, multiple privileges should be checked before the data
should be yielded. For example, a photo gallery app might check both the 
`media.view` and `media.view.full_size` privileges before rendering a 
full-size image. In these cases, an array of 
[Privileges](https://metacpan.org/pod/Mojolicious%3A%3APlugin%3A%3AAuthorization%3A%3ARBAC%3A%3APrivilege) (as from 
["priv"](#priv)) may be passed instead -- however, please note that only the
[resource](https://metacpan.org/pod/Mojolicious%3A%3APlugin%3A%3AAuthorization%3A%3ARBAC%3A%3APrivilege#resource) and
[action](https://metacpan.org/pod/Mojolicious%3A%3APlugin%3A%3AAuthorization%3A%3ARBAC%3A%3APrivilege#action) properties
are respected on these objects. 

An authorization log message is emitted for each privilege checked.

If all privilege checks pass, the data is returned. If any check fails, an
`Authorization::RBAC::Failure` exception is thrown.

# AUTHOR

Mark Tyrrell `<mark@tyrrminal.dev>`

# LICENSE

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
