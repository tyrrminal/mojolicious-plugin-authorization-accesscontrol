package Mojolicious::Plugin::Authorization::RBAC::Privilege;
use v5.26;

# ABSTRACT: Defines an RBAC Privilege

=encoding UTF-8

=head1 NAME

Mojolicious::Plugin::Authorization::RBAC::Privilege - defines a single RBAC
privilege

=head1 SYNOPSIS

  use Mojolicious::Plugin::Authorization::RBAC::Privilege;

  my $p1 = Mojolicious::Plugin::Authorization::RBAC::Privilege->new(
    resource => 'Book',
    action   => 'edit',
    role     => 'admin',
  );

  my $p2 = Mojolicious::Plugin::Authorization::RBAC::Privilege->new(
    resource   => 'Book',
    action     => 'edit',
    attributes => [qw(public)]
  );

  if($p1->is_equal($p2)) { ... } # no

  if($p2->match_resource('Book')) { ... } # yes

  say "$p2"; # 'Book => edit(public)'

=head1 DESCRIPTION

This class is utilized by L<Mojolicious::Plugin::Authorization::RBAC> to 
encapsulate an authorization privilege. Typically, privileges are created through
that package's convenience function 
L<priv|Mojolicious::Plugin::Authorization::RBAC/priv> rather than using this
class's constructor directly. Either way, newly-created privileges are not
registered as "active" for checks until RBAC's C<role>/C<any_role> functions are
used. 

=head1 METHODS

=head2 new

The constructor takes 4 named arguments, two of which are required:

=over

=item * role (optional)

=item * resource (required)

=item * action (required)

=item * attributes (optional)

=back

With the exception of attributes, which is an ArrayRef of strings, all arguments
are simple strings.

=cut

use Object::Pad;

class Mojolicious::Plugin::Authorization::RBAC::Privilege :strict(params) {
  use List::Util qw(reduce);

  use overload
    '""' => 'to_string';
  
  field $role       :param :accessor :mutator(_role) = undef;
  field $resource   :param :accessor;
  field $action     :param :accessor;
  field $attributes :param :accessor = [];

  ADJUST {
    die("Resource is a required string") unless(!ref($resource) && $resource);
    die("Action is a required string") unless(!ref($action) && $action);
  }

  method to_string {
    my $r = defined($role) ? "[$role] " : '';
    "$r$resource => $action(".join(',',$attributes->@*).")"
  }

=head1 match_role

Given a list of roles, returns true if any of them match the C<role> field value

If C<role> field value is undef, returns true

=cut

  method match_role(@roles) {
    return 1 unless(defined($role));
    return grep { defined($_) && $role eq $_ } @roles;
  }

=head1 match_resource

Returns true if the argument is the same as the C<resource> field value, false
otherwise

=cut

  method match_resource($r) {
    $r eq $resource
  }

=head1 match_action

Returns true if the argument is the same as the C<action> field value, false
otherwise

=cut

  method match_action($a) {
    $a eq $action
  }

=head1 match_attributes

Given a HashRef whose keys are attribute identifiers (strings) and whose values
are booleans, returns true if all of the C<attributes> field contents are 
present in the HashRef and their values are true.

=cut

  method match_attributes($attrs) {
    reduce { $a && $b } (1, @{$attrs}{$attributes->@*})
  }

=head1 is_equal

Given another Privilege object, returns true if role, resource, action, and 
attributes match.

=cut

  method is_equal($priv) {
    return 0 unless($priv->match_role($role));
    return 0 unless($priv->match_resource($resource));
    return 0 unless($priv->match_action($action));
    return 0 unless(
      $priv->match_attributes({map { $_ => 1 } $attributes->@*}) &&
      $self->match_attributes({map { $_ => 1 } $priv->attributes->@*})
    );
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
