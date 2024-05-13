package Mojolicious::Plugin::Authorization::RBAC::YieldResult;
use v5.26;

# ABSTRACT: 

=encoding UTF-8

=head1 NAME

=cut

use Object::Pad;

class Mojolicious::Plugin::Authorization::RBAC::YieldResult :strict(params) {

  field $granted :param = undef;
  field $entity  :param = undef;

  method granted($sub) {
    $sub->($entity) if($granted);
    return $self;
  }

  method denied($sub) {
    $sub->() if(defined($granted) && !$granted);
    return $self;
  }

  method null($sub) {
    $sub->() if(!defined($granted));
    return $self;
  }

  method is_granted() {
    return ($granted//0) != 0
  }
}
