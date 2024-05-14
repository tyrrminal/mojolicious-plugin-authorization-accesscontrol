use v5.26;
use warnings;

use Test2::V0;

use Mojolicious::Lite;

use List::Util qw(first);
use Mojolicious::Plugin::Authorization::AccessControl qw(role priv any_role);
use Syntax::Keyword::Try;
use Test::Mojo;

use experimental qw(signatures);

# Set up our "database" of users and products
my @users = (
  { id => 1, username => 'tyrrminal', roles => [qw(user)] },
  { id => 2, username => 'mark'     , roles => []         },
  { id => 7, username => 'bigboss'  , roles => [qw(user admin)]},
);

my @products = (
  { id => 1, name => "CTX-101", owner_id => 7 },
  { id => 2, name => "CTZ-870", owner_id => 3 },
  { id => 3, name => 'RTZ-113', owner_id => 1 },
  { id => 4, name => "AGT-541", owner_id => 2 },
);

# initialize the plugin and tell it how to get the current_user's roles
my $current_user;
plugin('Authorization::AccessControl' => {
  get_roles => sub($c) { $current_user->{roles} }
});

# set up routes and implementations for get-product-by-id
get('/product/<id:num>' => sub($c) {
  my $id = $c->param('id');
  try {
    $c->authz->yield(sub() {
      my ($item) = grep { $_->{id} == $id } @products;
      $item;
    }, Product => 'view')
    ->granted(sub ($product) { $c->render(status => 200, json => $product)    })
    ->denied(sub () {          $c->render(status => 401, text => 'auth fail') })
    ->null(sub () {            $c->render(status => 404, text => 'not found') })
  } catch($e) {
    $c->render(status => 400, text => $e)
  }
});

# and delete-product-by-id
del('/product/<id:num>' => sub($c) {
  my $id = $c->param('id');
  try {
    $c->authz->yield(sub() {
      my ($item) = grep { $_->{id} == $id } @products;
      $item;
    }, Product => 'delete')
    ->granted(sub ($product) { 
      my $idx = first { $products[$_]->{id} == $id } 0..$#products;
      splice(@products, $idx, 1);
      $c->render(status => 204, text => '');
     })
    ->denied(sub () { $c->render(status => 401, text => 'auth fail') })
    ->null(sub () { $c->render(status => 404, text => 'not found') })
  } catch($e) {
    $c->render(status => 400, text => $e)
  }
});

# declare static privileges:
# - anyone can view any record
# - those in the user group can create records, as well as edit/delete their own
# - those in the admin group can do everything
any_role(
  priv(Product => 'view'),
  priv(Book    => 'delete'), # don't cross the streams
);
role(user => [
  priv(Product => 'create'),
  priv(Product => 'edit',   {owned => 1}),
  priv(Product => 'delete', {owned => 1}),
]);
role(admin => [
  priv(Product => 'create'),
  priv(Product => 'edit'),
  priv(Product => 'delete'),
]);

# configure a callback to generate product attributes
helper('authz.extract_attrs' => sub($c, $ctx) {
  {
    owned => $ctx->{owner_id} == $current_user->{id}
  };
});

my $t = Test::Mojo->new();

$current_user = $users[1];
# not in any groups; can't delete anything (including their own stuff!)
$t->delete_ok("/product/4")->status_is(401);
$t->delete_ok("/product/3")->status_is(401);
# but they can stil view
$t->get_ok("/product/4")->status_is(200);
$t->get_ok("/product/3")->status_is(200);

$current_user = $users[0];
# 'user' can view anything and only delete their own
$t->get_ok("/product/1")->status_is(200);
$t->get_ok("/product/20")->status_is(404);
$t->delete_ok("/product/3")->status_is(204);
$t->get_ok("/product/3")->status_is(404);
$t->delete_ok("/product/1")->status_is(401);

$current_user = $users[2];
# 'admin' can view and delete everything whether it's theirs or not
$t->delete_ok("/product/1")->status_is(204);
$t->get_ok("/product/1")->status_is(404);
$t->delete_ok("/product/4")->status_is(204);

# all other products deleted
is(\@products, [{id => 2, name => "CTZ-870", owner_id => 3}], 'final array');

done_testing;
