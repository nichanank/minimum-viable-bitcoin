from field_element import FieldElement

'''
We are interested in specific points on the elliptic curve. This means that the Point (x, y) satisfies some y**2 == x**3 + a*x + b

For any elliptic curve, a given line will intersect the curve at either 1 point or 3 points. EXCEPT when:
- the line is vertical
- the line is a tangent to the curve

Point addition:
Adding two EC points results in a third point that is also on the curve. Point addition is non-linear, while it is trivial to calculate C in A + B = C, it is very difficult to derive B given A and C.
'''

class Point:

  def __init__(self, x, y, a, b):
      self.a = a
      self.b = b
      self.x = x
      self.y = y

      # Point at Infinity
      if self.x is None and self.y is None:
          return
      
      # Validate that Point is on the elliptic curve y**2 == x**3 + a*x + b
      if self.y**2 != self.x**3 + a * x + b:
          raise ValueError('({}, {}) is not on the curve'.format(x, y))

  def __eq__(self, other):
      return self.x == other.x and self.y == other.y \
          and self.a == other.a and self.b == other.b

  def __ne__(self, other):
      # this should be the inverse of the == operator
      return self != other

  def __repr__(self):
      if self.x is None:
          return 'Point(infinity)'
      elif isinstance(self.x, FieldElement):
          return 'Point({},{})_{}_{} FieldElement({})'.format(
              self.x.num, self.y.num, self.a.num, self.b.num, self.x.prime)
      else:
          return 'Point({},{})_{}_{}'.format(self.x, self.y, self.a, self.b)

  def __add__(self, other):
      if self.a != other.a or self.b != other.b:
          raise TypeError('Points {}, {} are not on the same curve'.format(self, other))
      # Case 0.0: self is the point at infinity, return other
      if self.x is None:
          return other
      # Case 0.1: other is the point at infinity, return self
      if other.x is None:
          return self

      # Case 1: self.x == other.x, self.y != other.y
      # Result is point at infinity
      if self.x == other.x and self.y != other.y:
          return self.__class__(None, None, self.a, self.b)

      # Case 2: self.x ≠ other.x
      # Formula (x3,y3)==(x1,y1)+(x2,y2)
      # s=(y2-y1)/(x2-x1)
      # x3=s**2-x1-x2
      # y3=s*(x1-x3)-y1
      if self.x != other.x:
          s = (other.y - self.y) / (other.x - self.x)
          x = s**2 - self.x - other.x
          y = s * (self.x - x) - self.y
          return self.__class__(x, y, self.a, self.b)

      # Case 3: if we are tangent to the vertical line, we return the point at infinity
      # note instead of figuring out what 0 is for each type
      # we just use 0 * self.x
      if self == other and self.y == 0 * self.x:
          return self.__class__(None, None, self.a, self.b)

      # Case 4: self == other
      # Formula (x3,y3)=(x1,y1)+(x1,y1)
      # s=(3*x1**2+a)/(2*y1)
      # x3=s**2-2*x1
      # y3=s*(x1-x3)-y1
      if self == other:
          s = (3 * self.x**2 + self.a) / (2 * self.y)
          x = s**2 - 2 * self.x
          y = s * (self.x - x) - self.y
          return self.__class__(x, y, self.a, self.b)

  def __rmul__(self, coefficient):
      coef = coefficient
      current = self
      result = self.__class__(None, None, self.a, self.b)
      while coef:
          if coef & 1:
              result += current
          current += current
          coef >>= 1
      return result