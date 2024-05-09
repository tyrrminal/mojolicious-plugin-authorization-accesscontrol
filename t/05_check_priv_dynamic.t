use v5.26;
use warnings;

use Test2::V0;

use Mojolicious::Lite;

use Mojolicious::Plugin::Authorization::RBAC qw(role priv any_role);

use experimental qw(signatures);

my @roles;
my $add_dynamic_rules = 0;

use Test::Mojo;
my $t = Test::Mojo->new();

role(admin => [
  priv(Book => 'read')
]);

plugin('Authorization::RBAC',
  get_roles => sub($c) { return [@roles] },
);

app->authz->role(vip => [
  priv(Book => 'list')
]);

hook(before_dispatch => sub($c) {
  if($add_dynamic_rules) {
    $c->authz->role("app-friends" => [
      priv(Book => 'read')
    ]);
  }
});

get('/book' => sub($c) {
  return $c->render(status => 401, text => 'Unauthorized') unless($c->authz->permitted(Book => 'read'));
  return $c->render(text => 'Hello World')
});

$t->get_ok('/book')->status_is(401);

$add_dynamic_rules = 1;

$t->get_ok('/book')->status_is(401);

@roles = ('app-friends');

$t->get_ok('/book')->status_is(200)->content_is("Hello World");

done_testing;
