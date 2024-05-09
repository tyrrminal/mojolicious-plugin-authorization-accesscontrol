use v5.26;
use warnings;

use Test2::V0;

use Mojolicious::Plugin::Authorization::RBAC::Privilege;

ok(dies { Mojolicious::Plugin::Authorization::RBAC::Privilege->new() } , 'fail without resource');

ok(dies { Mojolicious::Plugin::Authorization::RBAC::Privilege->new(resource => 'User') } , 'fail without action');

ok(Mojolicious::Plugin::Authorization::RBAC::Privilege->new(resource => 'User', action => 'read'), 'required params');

ok(dies { Mojolicious::Plugin::Authorization::RBAC::Privilege->new(resource => 'User', action => 'read', context => 1) } , 'fail with extra params');

ok(Mojolicious::Plugin::Authorization::RBAC::Privilege->new(resource => 'User', action => 'read', attributes => [qw(owned)]), 'required params and attributes');

ok(dies { Mojolicious::Plugin::Authorization::RBAC::Privilege->new(resource => undef, action => 'read', context => 1) }, 'fail with undef resource');

ok(dies { Mojolicious::Plugin::Authorization::RBAC::Privilege->new(resource => 'User', action => undef, context => 1) }, 'fail with undef action');

my $priv1 = Mojolicious::Plugin::Authorization::RBAC::Privilege->new(resource => 'User', action => 'read');
my $priv1a = Mojolicious::Plugin::Authorization::RBAC::Privilege->new(resource => 'User', action => 'read');
my $priv2 = Mojolicious::Plugin::Authorization::RBAC::Privilege->new(resource => 'User', action => 'read', attributes => [qw(owned)]);
my $priv2a = Mojolicious::Plugin::Authorization::RBAC::Privilege->new(resource => 'User', action => 'read', attributes => [qw(own)]);
my $priv3 = Mojolicious::Plugin::Authorization::RBAC::Privilege->new(resource => 'Book', action => 'read');
my $priv4 = Mojolicious::Plugin::Authorization::RBAC::Privilege->new(resource => 'User', action => 'create');

is($priv1->is_equal($priv1a), bool(1), 'check equal');
is($priv1->is_equal($priv2), bool(0), 'check unequal (attrs)');
is($priv2->is_equal($priv2a), bool(0), 'check unequal (attrs)');
is($priv1->is_equal($priv3), bool(0), 'check unequal (resource)');
is($priv1->is_equal($priv4), bool(0), 'check unequal (action)');

done_testing;
