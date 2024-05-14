package Mojolicious::Plugin::Authorization::RBAC::YieldResult;
use v5.26;

# ABSTRACT: Provides mechanism for handling the result of RBAC's yield method

=encoding UTF-8

=head1 NAME

Mojolicious::Plugin::Authorization::RBAC::YieldResult - provides mechanism for
handling the result of RBAC's yield method

=head1 SYNOPSIS

  $c->yield(sub () { db->model('Book')->get($id) }, $PRIV_RESOURCE_BOOK => $PRIV_ACTION_GET)
    ->null(sub () { $c->render(status => 404, text => "Book $id not found") })
    ->denied(sub () { $c->render(status => 401, text => "Access denied") })
    ->granted(sub ($book) { $c->render(status => 200, json => $book) })
    ->granted(sub ($book) { db->model('AuditLog')->create(
        action        => $PRIV_ACTION_GET, 
        resource_type => $PRIV_RESOURCE_BOOK, 
        resource      => to_json($book),
        user          => to_json($c->current_user),
        accessed_at   => DateTime->now,
      ) });

=head1 DESCRIPTION

This class utilizes a promise-style callback (though to be clear, it is entirely
synchronous and will call each of your handlers in exactly the order that they
are added to the chain) interface to facilitate clean segregation of data. The
protected data value is exposed minimally, to the C<granted> subroutines, while
providing simple mechanisms to handle the alternative path(s).

Normally, you will not create instances of this class yourself; instead, one 
will be returned from L<Mojolicious::Plugin::Authorization::RBAC>'s C<authz.yield>
helper. Each of its main methods (L<granted>, L<denied>, L<null>) is chainable
so that more of those can be called on the result, as shown above.

Once the chain is "complete", you can call one final method L<is_granted>, which
returns a boolean value, rather than the chained instance.

=head1 CONSTRUCTOR

C<new> creates new instances of the class. There are no required parameters.
C<granted> is an optional parameter to indicate whether this result expresses
a granted permission (true) or not (false). C<entity> is the protected data 
value which will be handed off to L<granted> handler(s) if C<granted> is true. 
If C<granted> is undefined, only the L<null> handler(s) will called.

=head1 METHODS

=cut

use Object::Pad;

class Mojolicious::Plugin::Authorization::RBAC::YieldResult :strict(params) {

  field $granted :param = undef;
  field $entity  :param = undef;

=head1 granted

Register a handler to be called when access is granted to the protected resource.
The handler receives one argumment: the resource value

Chainable

=cut

  method granted($sub) {
    $sub->($entity) if($granted);
    return $self;
  }

=head1 denied

Register a handler to be called when access is denied to the protected resource.
The handler receives no arguments.

Chainable

=cut

  method denied($sub) {
    $sub->() if(defined($granted) && !$granted);
    return $self;
  }

=head1 null

Register a handler to be called when access could not be evaluated for the
protected resource because it was undefined. The handler receives no arguments.

Chainable

=cut

  method null($sub) {
    $sub->() if(!defined($granted));
    return $self;
  }

=head1 is_granted

Returns a boolean reflecting whether the privilege was granted

Not chainable.

=cut

  method is_granted() {
    return ($granted//0) != 0
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
