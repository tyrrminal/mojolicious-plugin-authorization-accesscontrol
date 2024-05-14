use v5.26;
use warnings;

use Test2::V0;

use Mojolicious::Lite;

use Mojolicious::Plugin::Authorization::AccessControl qw(role priv any_role);

use experimental qw(signatures);

my @roles;

use Test::Mojo;
my $t = Test::Mojo->new();

role(admin => [
  priv(Book => 'read')
]);

plugin('Authorization::AccessControl',
  get_roles => sub($c) { return [@roles] },
);

app->authz->role(vip => [
  priv(Book => 'read')
]);

get('/book' => sub($c) {
  return $c->render(status => 401, text => 'Unauthorized') unless($c->authz->permitted(Book => 'read'));
  return $c->render(text => 'Hello World')
});

@roles = ('vip');

$t->get_ok('/book')->status_is(200);

@roles = ('admin');

$t->get_ok('/book')->status_is(200);

@roles = ('friends');

$t->get_ok('/book')->status_is(401);

hook(before_dispatch => sub($c) {
  $c->authz->role("friends" => [
    priv(Book => 'read')
  ]);
});

$t->get_ok('/book')->status_is(200)->content_is("Hello World");

@roles = ();

$t->get_ok('/book')->status_is(401);

done_testing;
