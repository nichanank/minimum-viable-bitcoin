from io import BytesIO
from random import randint

import hashlib
import hmac

'''
A Field Element is an element in a Finite Field. Each is a member of a set of numbers that satisfy some properties. p is the order (size) of the set and is a prime number.

For a set of size p,
F(p) = {0, 1, 2, 3, ..., p - 1} where p is prime.
'''

class FieldElement:

  def __init__(self, num, prime):
    if num >= prime or num < 0:
      error = 'Number {} not in field range 0 to {}'.format(
          num, prime - 1)
      raise ValueError(error)
    self.num = num
    self.prime = prime

  def __repr__(self):
    return 'FieldElement_{}({})'.format(self.prime, self.num)

  def __eq__(self, other):
    if other is None:
        return False
    return self.num == other.num and self.prime == other.prime

  def __ne__(self, other):
    return self != other

  # Modulo arithmatic on field elements
  
  def __add__(self, other):
    if self.prime != other.prime:
        raise TypeError('Cannot add two numbers in different Fields')
    num = (self.num + other.num) % self.prime
    return self.__class__(num, self.prime)

  def __sub__(self, other):
    if self.prime != other.prime:
        raise TypeError('Cannot subtract two numbers in different Fields')
    num = (self.num - other.num) % self.prime
    return self.__class__(num, self.prime)

  def __mul__(self, other):
    if self.prime != other.prime:
        raise TypeError('Cannot multiply two numbers in different Fields')
    num = (self.num * other.num) % self.prime
    return self.__class__(num, self.prime)

  def __pow__(self, exponent):
    n = exponent % (self.prime - 1)
    num = pow(self.num, n, self.prime)
    return self.__class__(num, self.prime)

  def __truediv__(self, other):
    if self.prime != other.prime:
        raise TypeError('Cannot divide two numbers in different Fields')
    # Fermat's little theorem: self.num**(p-1) % p == 1
    # 1/n == pow(n, p-2, p)
    num = (self.num * pow(other.num, self.prime - 2, self.prime)) % self.prime
    return self.__class__(num, self.prime)

  def __rmul__(self, coefficient):
    num = (self.num * coefficient) % self.prime
    return self.__class__(num=num, prime=self.prime)