use v5.26;
use warnings;

use Test2::V0;

use Mojolicious::Lite;

use Mojolicious::Plugin::Authorization::RBAC qw(role priv any_role);

use experimental qw(signatures);

plugin('Authorization::RBAC',
  get_roles => sub($c) { return [] },
  log => undef,
);

any_role(
  # always allow
  priv(Book => 'list'),
  # require just the "own" attribute
  priv(User => 'read',   [qw(own)]),
  priv(User => 'edit',   [qw(own)]),
  # require either the "own" or "public" attribute
  priv(Book => 'get',    [qw(own)]),
  priv(Book => 'get',    [qw(public)]),
  # require both the "own" and "unlocked" attributes
  priv(Book => 'delete', [qw(own unlocked)]),
);
role(admin => [
  # always allow for admins
  priv(User => 'list'),
  priv(User => 'edit'),
]);

is(app->authz->permitted(User => 'modify'), bool(0), 'check non-registered action');
is(app->authz->permitted(Users => 'edit'),  bool(0), 'check non-registered resource');


is(app->authz->permitted(User => 'edit'),             bool(0), 'check non-admin edit');
is(app->authz->permitted(User => 'edit', {own => 0}), bool(0), 'check non-admin non-owner edit');
is(app->authz->permitted(User => 'edit', {own => 1}), bool(1), 'check non-admin owner edit');

is(app->authz->permitted(Book => 'get', {own => 1, public => 0}), bool(1), 'check own book get');
is(app->authz->permitted(Book => 'get', {own => 0, public => 1}), bool(1), 'check public book get');

is(app->authz->permitted(Book => 'delete', {own => 1}),                bool(0), 'check half attr(own) delete');
is(app->authz->permitted(Book => 'delete', {unlocked => 1}),           bool(0), 'check half attr(unlocked) delete');
is(app->authz->permitted(Book => 'delete', {unlocked => 1, own => 1}), bool(1), 'check multi attr delete');

plugin('Authorization::RBAC',
  get_roles => sub($c) { return [qw(admin)] },
  log => undef,
);

is(app->authz->permitted(User => 'edit'),             bool(1), 'check admin edit');
is(app->authz->permitted(User => 'edit', {own => 1}), bool(1), 'check admin owner edit');

done_testing;
