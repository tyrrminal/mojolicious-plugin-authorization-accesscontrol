use v5.26;
use warnings;

use Test2::V0;

use Mojolicious::Lite;

use experimental qw(signatures);

plugin('Authorization::AccessControl' => {
  get_roles => sub($c) {[]},
  prefix => 'authorization'
});

ok(dies { app->authz->priv(Book => 'view') } , 'use default prefix');

ok(lives { app->authorization->any_role(app->authorization->priv(Book => 'view')) }, 'use custom prefix');

get("/books" => sub($c) { return $c->render(status => 401, text => '') unless($c->authorization->permitted(Book => 'view')); $c->render(text => '') });
del("/books" => sub($c) { return $c->render(status => 401, text => '') unless($c->authorization->permitted(Book => 'delete')); $c->render(text => '') });

use Test::Mojo;
my $t = Test::Mojo->new();

$t->get_ok('/books')->status_is(200);
$t->delete_ok('/books')->status_is(401);

done_testing;
