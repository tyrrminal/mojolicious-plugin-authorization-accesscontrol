use v5.26;
use warnings;

use Test2::V0;

use Mojolicious::Plugin::Authorization::AccessControl qw(role priv any_role);

ok(!warns { role(admin => [priv(User => 'read')]) }, 'check role/priv add');

ok(warns { role(admin => [priv(User => 'read')]) }, "check can't add dupe priv");

ok(!warns { role(admin => [priv(User => 'read', {owner => !0})]) }, 'check add dupe priv w/ attribute');

ok(warns { role(admin => [priv(User => 'read', {owner => !0})]) }, "check can't add dupe priv w/ attribute");

ok(!warns { role(admin => [priv(User => 'create')]) }, 'check can add non-dupe');

ok(!warns { any_role(priv(User => 'read')) }, 'check any role/priv add');

ok(warns { any_role(priv(User => 'read')) }, 'check dupe any role/priv add');

done_testing;
