# NAME

Mojolicious::Plugin::Authorization::AccessControl - provides hybrid RBAC-ABAC
for Mojolicious applications

# SYNOPSIS

    $self->plugin('Authorization::AccessControl' => {get_roles => sub($c) {...}});

    # in, e.g., controller
    use Mojolicious::Plugin::Authorization::AccessControl qw(priv role any_role);

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

- if the user has the `admin` role
- if the book's `is_public` property is true
- if the user is the book's owner

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

Finally, the [yield](#authz-yield-cb-args) method can be used to cleanly
isolate the code that obtains instances of protected data from the code that
consumes them. The value returned by the `$cb` callback is passed through the
attribute callback, and then those attributes are used to determine whether to
grant or deny access. The produced value is accessible only from the `granted`
callback. See [Mojolicious::Plugin::Authorization::YieldResult](https://metacpan.org/pod/Mojolicious%3A%3APlugin%3A%3AAuthorization%3A%3AYieldResult) for more
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

    $app->plugin('Authorization::AccessControl' => {
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
      );
    }

    # match the restrictions in the dynamic rules with Book-specific attributes
    helper(extract_attrs => sub($c, $ctx) {
      +{
        book_id => $ctx->id,
      }
    });

Now, when the privileges are checked, the user's group must match (unless they 
are the owner), or there must be a dynamic rule for a role belonging to the user,
with a matching book\_id in order to access that book.

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
[Privilege](https://metacpan.org/pod/Mojolicious%3A%3APlugin%3A%3AAuthorization%3A%3AAccessControl%3A%3APrivilege) object without 
registering it, there is no difference between these. The helper version is merely
provided as a convenience.

When it comes to checking privileges, a few options are available as well. The
simplest is the [authz.permitted](#authz-permitted-resource-action-attrs) 
helper. Or, you can use [authz.yield](#authz-yield-cb-args) to invoke the 
[Mojolicious::Plugin::Authorization::AccessControl::YieldResult](https://metacpan.org/pod/Mojolicious%3A%3APlugin%3A%3AAuthorization%3A%3AAccessControl%3A%3AYieldResult) workflow and ensure 
that privileged data objects are only made available to application logic once 
privilege checks are passed.

# FUNCTIONS

The following functions can be exported by request. None are exported by default

## role($role => \\@privs,...)

Declares role-specific static privileges.

Accepts a hash whose keys are role names (string) and whose values are ArrayRefs
of [Privileges](https://metacpan.org/pod/Mojolicious%3A%3APlugin%3A%3AAuthorization%3A%3AAccessControl%3A%3APrivilege). Normally,
these privileges are created via the ["priv"](#priv) function.

## any\_role(@privs)

Declares static privileges that apply to all users regardless of role

Accepts an array of 
[Privileges](https://metacpan.org/pod/Mojolicious%3A%3APlugin%3A%3AAuthorization%3A%3AAccessControl%3A%3APrivilege). Normally,
these privileges are created via the ["priv"](#priv) function.

## priv($resource, $action\[, $restrictions\])

Returns a [Privilege](https://metacpan.org/pod/Mojolicious%3A%3APlugin%3A%3AAuthorization%3A%3AAccessControl%3A%3APrivilege) object
for the passed resource/action and optional restrictions on that privilege.

N.B. the returned object is not registered and must be declared with, e.g.,
["role"](#role)/["any\_role"](#any_role) to be used for 
[authz.permitted](#authz-permitted-resource-action-attrs)  checks.

# METHODS

[Mojolicious::Plugin::Authorization::AccessControl](https://metacpan.org/pod/Mojolicious%3A%3APlugin%3A%3AAuthorization%3A%3AAccessControl) inherits all methods from 
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

Functionally identical to ["priv"](#priv). Provided so that the import can be skipped
in contexts where only dynamic privileges are being created.

## authz.role ($role => \\@privs,...)

Registers privileges for one or more roles, as ["role"](#role) does.

If called on a request controller, the roles are dynamically added for that
request only. Otherwise, functions identically to the `/role` function.

## authz.any\_role (@privs)

Registers privileges for all users, as ["any\_role"](#any_role) does.

If called on a request controller, the roles are dynamically added for that
request only. Otherwise, functions identically to the `/any_role` function.

## authz.permitted ($resource, $action \[, $attrs, \[, $value\]\])

Check if an action is allowed by privilege rules. Returns true if any registered
rule (static or dynamic) applies, false otherwise. Role, resource, action, and
all privilege attributes must match.

`$resource` and `$action` are strings, `$attrs` is an optional HashRef of
static attributes, that is to say, attributes related to the request itself, and
not the specific data value(s) being requested. Dynamic attributes (those
related to the data value) can be extrapolated by passing the data `value` as 
the final argument. An [extraction method](#attribute-extraction) will then be 
called on this value and the result will be merged with the static `$attrs` to 
determine the final attribute set. If the resource, action, and user's role(s) 
match any registered privilege, and that privilege's restrictions are met by the
attributes, then the permission check passes.

Logs a "granted" or "denied" message to the selected `Mojo::Log` instance

#### Attribute Extraction

The module will look in a number of places to find an appropriate method to
extract the data value's authorization attributes, in order from most-specific
to most-general. The first match that is found is used and the rest are ignored
for that check. If [prefix](https://metacpan.org/pod/prefix) has been changed, both the custom prefix and the 
default are checked, in that order. Any characters in `$resource` and 
`$action` that are not permitted in method names are replaced by `_` 
underscore characters - with the exception that periods are also left in when
constructing helper names.

- **controller method** `extract_attrs_$resource_$action`
- **helper** `$prefix.extract_attrs.$resource_$action`

If no match is found, it continues without the `$action`

- **controller method** `extract_attrs_$resource`
- **helper** `$prefix.extract_attrs.$resource`

And finally, without the `$resource`

- **controller method** `extract_attrs`
- **helper** `$prefix.extract_attrs`

Regardless of which method is used, it receives one parameter (besides the 
controller object): the protected data value. It must return a HashRef (which
can be empty, but must not be undefined) of attribute labels and their 
corresponding values for the protected data.

## authz.yield ($get\_value\_cb, $resource, $action, $attrs)

Yield a protected data value, if permitted. The first argument callback should
perform the minimum necessary to obtain the data value and immediately return it.
This value is then passed through `extract_attrs` and the dynamic attributes 
are merged with the static `$attrs` Hash passed in. Then 
[authz.permitted](#authz-permitted-resource-action-attrs) is called
to check the resource/action/attrs against all registered privileges.

Returns a [Mojolicious::Plugin::Authorization::AccessControl::YieldResult](https://metacpan.org/pod/Mojolicious%3A%3APlugin%3A%3AAuthorization%3A%3AAccessControl%3A%3AYieldResult), upon which
callbacks may be registered to handle the result of the authorization check.

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
