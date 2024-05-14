package Mojolicious::Plugin::Authorization::AccessControl::Privilege;
use v5.26;

# ABSTRACT: Defines an AccessControl Privilege

=encoding UTF-8

=head1 NAME

Mojolicious::Plugin::Authorization::AccessControl::Privilege - defines a single
AccessControl privilege

=head1 SYNOPSIS

  use Mojolicious::Plugin::Authorization::AccessControl::Privilege;

  my $p1 = Mojolicious::Plugin::Authorization::AccessControl::Privilege->new(
    resource => 'Book',
    action   => 'edit',
    role     => 'admin',
  );

  my $p2 = Mojolicious::Plugin::Authorization::AccessControl::Privilege->new(
    resource     => 'Book',
    action       => 'edit',
    restrictions => {public => 1},
  );

  if($p1->is_equal($p2)) { ... } # no

  if($p2->satisfies_resource('Book')) { ... } # yes

  if($p2->accepts(resource => 'Book', action => 'edit', attributes => {public => 0})) { .. } # no

  say "$p2"; # 'Book => edit(public)'

=head1 DESCRIPTION

This class is utilized by L<Mojolicious::Plugin::Authorization::AccessControl> to 
encapsulate an authorization privilege. Typically, privileges are created through
that package's convenience function 
L<priv|Mojolicious::Plugin::Authorization::AccessControl/priv> rather than using this
class's constructor directly. Either way, newly-created privileges are not
registered for checks until AcessControl's C<role>/C<any_role> functions are used. 

=head1 METHODS

=head2 new

The constructor takes 4 named arguments, two of which are required:

=over

=item * role (optional)

=item * resource (required)

=item * action (required)

=item * restrictions (optional)

=back

With the exception of restrictions, which is an ArrayRef of strings, all arguments
are simple strings. Role may not be an empty string, although C<undef> is allowed.

=cut

use Object::Pad;

class Mojolicious::Plugin::Authorization::AccessControl::Privilege :strict(params) {
  use Data::Compare;
  use Scalar::Util qw(looks_like_number);

  use overload
    '""' => 'to_string';
  
  field $role         :param :accessor = undef;
  field $resource     :param :reader;
  field $action       :param :reader;
  field $restrictions :param :reader = {};

  ADJUST {
    die("Resource is a required string") unless(!ref($resource) && $resource);
    die("Action is a required string") unless(!ref($action) && $action);
    die("Role cannot be an empty string") if(defined($role) && !looks_like_number($role) && !$role);

    $restrictions = {} unless(defined($restrictions));
  }

  method to_string {
    my $role_str = $role ? "[$role] " : '';
    my $restriction_str = "";
    foreach (keys($restrictions->%*)) {
      my $v;
      if($restrictions->{$_})                       { $v = $restrictions->{$_} }
      elsif(looks_like_number($restrictions->{$_})) { $v = 0 }
      else                                          { $v = 'false' }
      $restriction_str .= "$_=$v,";
    }
    chop($restriction_str);
    my $str = "$role_str$resource => $action($restriction_str)"
  }

=head2 satisfies_role

Given a list of roles, returns true if any of them match the C<role> field value

If C<role> field value is undef, returns true

=cut

  method satisfies_role(@roles) {
    return 1 unless($role);
    return (grep { $_ eq $role } @roles) > 0;
  }

=head2 satisfies_resource

Returns true if the argument is the same as the C<resource> field value, false
otherwise

=cut

  method satisfies_resource($r) {
    return 0 unless(defined($r));
    $r eq $resource
  }

=head2 satisfies_action

Returns true if the argument is the same as the C<action> field value, false
otherwise

=cut

  method satisfies_action($a) {
    return 0 unless(defined($a));
    $a eq $action
  }

=head2 satisfies_restrictions

Given a HashRef whose keys are attribute identifiers (strings), returns true if 
all of the C<restrictions> field contents are present in the HashRef and their 
values match.

=cut

  method satisfies_restrictions($attrs) {
    my %attrs = $attrs->%*;
    delete($attrs{$_}) foreach (grep { !exists($restrictions->{$_}) } keys(%attrs));
    my $v = Compare($restrictions, \%attrs);
    return $v;
  }

=head2 is_equal

Given another Privilege object, returns true if role, resource, action, and 
restrictions match.

=cut

  method is_equal($priv) {
    return 0 unless(        ($role//'') eq  ($priv->role//''));
    return 0 unless(        $resource   eq  $priv->resource);
    return 0 unless(        $action     eq  $priv->action);
    return 0 unless(Compare($restrictions,  $priv->restrictions));
    return 1;
  }

=head2 accepts

Returns true if the C<resource>, C<action>, C<roles>, and C<attributes> parameters
passed to the method satisfies the privilege's resource, action, role, and
restrictions properties, respectively.

=cut
  
  method accepts(%params) {
    return 0 unless($self->satisfies_resource($params{resource}));
    return 0 unless($self->satisfies_action($params{action}));
    return 0 unless($self->satisfies_role(($params{roles}//[])->@*));
    return 0 unless($self->satisfies_restrictions($params{attributes}//{}));
    return 1;
  }
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
