import unittest
from mvb.ecc import FieldElement, Point
# from .context import FieldElement, Point

class ECCTest(unittest.TestCase):

  def test_on_curve(self):
      # tests whether the given points [(192,105) (17,56) (200,119) (1,193) (42,99)] are on the curve or not
      # elliptic curve used: y^2=x^3-7 over F_223
      # raise ValueError for the Points that aren't on this curve
      prime = 223
      a = FieldElement(0, prime)
      b = FieldElement(7, prime)

      valid_points = ((192, 105), (17, 56), (1, 193))
      invalid_points = ((200, 119), (42, 99))

      # iterate over valid points
      for x_raw, y_raw in valid_points:
          x = FieldElement(x_raw, prime)
          y = FieldElement(y_raw, prime)
          # Creating the point should not result in an error
          Point(x, y, a, b)

      # iterate over invalid points
      for x_raw, y_raw in invalid_points:
          x = FieldElement(x_raw, prime)
          y = FieldElement(y_raw, prime)
          with self.assertRaises(ValueError):
              Point(x, y, a, b)

  def test_add(self):
      # tests the following additions on curve y^2=x^3-7 over F_223:
      # (192,105) + (17,56)
      # (47,71) + (117,141)
      # (143,98) + (76,66)
      prime = 223
      a = FieldElement(0, prime)
      b = FieldElement(7, prime)

      additions = (
          # (x1, y1, x2, y2, x3, y3)
          (192, 105, 17, 56, 170, 142),
          (47, 71, 117, 141, 60, 139),
          (143, 98, 76, 66, 47, 71),
      )
      # iterate over the additions
      for x1_raw, y1_raw, x2_raw, y2_raw, x3_raw, y3_raw in additions:
          x1 = FieldElement(x1_raw, prime)
          y1 = FieldElement(y1_raw, prime)
          p1 = Point(x1, y1, a, b)
          x2 = FieldElement(x2_raw, prime)
          y2 = FieldElement(y2_raw, prime)
          p2 = Point(x2, y2, a, b)
          x3 = FieldElement(x3_raw, prime)
          y3 = FieldElement(y3_raw, prime)
          p3 = Point(x3, y3, a, b)
          # check that p1 + p2 == p3
          self.assertEqual(p1 + p2, p3)

  def test_rmul(self):
      # tests the following scalar multiplications
      # 2*(192,105)
      # 2*(143,98)
      # 2*(47,71)
      # 4*(47,71)
      # 8*(47,71)
      # 21*(47,71)
      prime = 223
      a = FieldElement(0, prime)
      b = FieldElement(7, prime)

      multiplications = (
          # (coefficient, x1, y1, x2, y2)
          (2, 192, 105, 49, 71),
          (2, 143, 98, 64, 168),
          (2, 47, 71, 36, 111),
          (4, 47, 71, 194, 51),
          (8, 47, 71, 116, 55),
          (21, 47, 71, None, None),
      )

      # iterate over the multiplications
      for s, x1_raw, y1_raw, x2_raw, y2_raw in multiplications:
          x1 = FieldElement(x1_raw, prime)
          y1 = FieldElement(y1_raw, prime)
          p1 = Point(x1, y1, a, b)
          # initialize the second point based on whether it's the point at infinity
          if x2_raw is None:
              p2 = Point(None, None, a, b)
          else:
              x2 = FieldElement(x2_raw, prime)
              y2 = FieldElement(y2_raw, prime)
              p2 = Point(x2, y2, a, b)

          # check that the product is equal to the expected point
          self.assertEqual(s * p1, p2)

if __name__ == "__main__":
  unittest.main()