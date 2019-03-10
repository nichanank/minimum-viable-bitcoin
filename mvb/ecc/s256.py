from io import BytesIO
from .field_element import FieldElement
from .point import Point
from .helper import encode_base58_checksum, hash160
import hmac
import hashlib

'''P = eG, where P is the public key and e is the private key, is an asymmetric equation. The private key is a single 256-bit number and the public key is a coordinate (x,y), where x and y are each 256-bit numbers.'''

'''secp256k1 constants'''
A = 0
B = 7
P = 2**256 - 2**32 - 977
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

class S256Field(FieldElement):
    
  def __init__(self, num, prime=None):
    super().__init__(num=num, prime=P)

  def __repr__(self):
    return '{:x}'.format(self.num).zfill(64)

  def sqrt(self):
    return self**((P + 1) // 4)


'''Public Keys in Elliptic Curves are Point coordinates in the form (x, y)'''
class S256Point(Point):

  def __init__(self, x, y, a=None, b=None):
    a, b = S256Field(A), S256Field(B)
    if type(x) == int:
        super().__init__(x=S256Field(x), y=S256Field(y), a=a, b=b)
    else:
        super().__init__(x=x, y=y, a=a, b=b)

  def __repr__(self):
    if self.x is None:
        return 'S256Point(infinity)'
    else:
        return 'S256Point({}, {})'.format(self.x, self.y)

  def __rmul__(self, coefficient):
    coef = coefficient % N
    return super().__rmul__(coef)

  def verify(self, z, sig):
    # By Fermat's Little Theorem, 1/s = pow(s, N-2, N)
    s_inv = pow(sig.s, N - 2, N)
    # u = z / s
    u = z * s_inv % N
    # v = r / s
    v = sig.r * s_inv % N
    # u*G + v*P should have as the x coordinate, r
    total = u * G + v * self
    return total.x.num == sig.r

  def sec(self, compressed=True):
    '''returns the binary version of the SEC format'''
    # if compressed, starts with b'\x02' if self.y.num is even, b'\x03' if self.y is odd then self.x.num
    # remember, you have to convert self.x.num/self.y.num to binary (some_integer.to_bytes(32, 'big'))
    if compressed:
        if self.y.num % 2 == 0:
            return b'\x02' + self.x.num.to_bytes(32, 'big')
        else:
            return b'\x03' + self.x.num.to_bytes(32, 'big')
    else:
        # if non-compressed, starts with b'\x04' followod by self.x and then self.y
        return b'\x04' + self.x.num.to_bytes(32, 'big') + \
            self.y.num.to_bytes(32, 'big')

  def hash160(self, compressed=True):
    return hash160(self.sec(compressed))

  def address(self, compressed=True, testnet=False):
    '''Returns the address string'''
    h160 = self.hash160(compressed)
    if testnet:
        prefix = b'\x6f'
    else:
        prefix = b'\x00'
    return encode_base58_checksum(prefix + h160)


  @classmethod
  def parse(self, sec_bin):
    '''takes a SEC binary and returns a Point object'''
    if sec_bin[0] == 4:
        x = int.from_bytes(sec_bin[1:33], 'big')
        y = int.from_bytes(sec_bin[33:65], 'big')
        return S256Point(x=x, y=y)
    is_even = sec_bin[0] == 2
    x = S256Field(int.from_bytes(sec_bin[1:], 'big'))

    '''Calculating y given x coordinate requires us to calculate a square root in a finite field.'''
    alpha = S256Field(B) + x**3 # right side of the equation y^2 = x^3 + 7
    beta = alpha.sqrt() # solve for left side
    if beta.num % 2 == 0:
        even_beta = beta
        odd_beta = S256Field(P - beta.num)
    else:
        even_beta = S256Field(P - beta.num)
        odd_beta = beta
    if is_even:
        return S256Point(x, even_beta)
    else:
        return S256Point(x, odd_beta)

'''secp256k1 constant for the generator point, to which we will multiply n times to get public key P'''
G = S256Point(
0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)

class Signature:

  def __init__(self, r, s):
    self.r = r
    self.s = s

  def __repr__(self):
    return 'Signature({:x},{:x})'.format(self.r, self.s)

  def der(self):
    rbin = self.r.to_bytes(32, byteorder='big')
    # remove all null bytes at the beginning
    rbin = rbin.lstrip(b'\x00')
    # if rbin has a high bit, add a \x00
    if rbin[0] & 0x80:
        rbin = b'\x00' + rbin
    result = bytes([2, len(rbin)]) + rbin  # <1>
    sbin = self.s.to_bytes(32, byteorder='big')
    # remove all null bytes at the beginning
    sbin = sbin.lstrip(b'\x00')
    # if sbin has a high bit, add a \x00
    if sbin[0] & 0x80:
        sbin = b'\x00' + sbin
    result += bytes([2, len(sbin)]) + sbin
    return bytes([0x30, len(result)]) + result

  @classmethod
  def parse(cls, signature_bin):
    s = BytesIO(signature_bin)
    compound = s.read(1)[0]
    if compound != 0x30:
        raise SyntaxError("Bad Signature")
    length = s.read(1)[0]
    if length + 2 != len(signature_bin):
        raise SyntaxError("Bad Signature Length")
    marker = s.read(1)[0]
    if marker != 0x02:
        raise SyntaxError("Bad Signature")
    rlength = s.read(1)[0]
    r = int.from_bytes(s.read(rlength), 'big')
    marker = s.read(1)[0]
    if marker != 0x02:
        raise SyntaxError("Bad Signature")
    slength = s.read(1)[0]
    s = int.from_bytes(s.read(slength), 'big')
    if len(signature_bin) != 6 + rlength + slength:
        raise SyntaxError("Signature too long")
    return cls(r, s)

class PrivateKey:

  def __init__(self, secret):
    self.secret = secret
    self.point = secret * G

  def hex(self):
    return '{:x}'.format(self.secret).zfill(64)

  def sign(self, z):
    k = self.deterministic_k(z)
    # r is the x coordinate of the resulting point k*G
    r = (k * G).x.num
    # remember 1/k = pow(k, N-2, N)
    k_inv = pow(k, N - 2, N)
    # s = (z+r*secret) / k
    s = (z + r * self.secret) * k_inv % N
    if s > N / 2:
        s = N - s
    # return an instance of Signature:
    # Signature(r, s)
    return Signature(r, s)

  def deterministic_k(self, z):
    k = b'\x00' * 32
    v = b'\x01' * 32
    if z > N:
        z -= N
    z_bytes = z.to_bytes(32, 'big')
    secret_bytes = self.secret.to_bytes(32, 'big')
    s256 = hashlib.sha256
    k = hmac.new(k, v + b'\x00' + secret_bytes + z_bytes, s256).digest()
    v = hmac.new(k, v, s256).digest()
    k = hmac.new(k, v + b'\x01' + secret_bytes + z_bytes, s256).digest()
    v = hmac.new(k, v, s256).digest()
    while True:
        v = hmac.new(k, v, s256).digest()
        candidate = int.from_bytes(v, 'big')
        if candidate >= 1 and candidate < N:
            return candidate
        k = hmac.new(k, v + b'\x00', s256).digest()
        v = hmac.new(k, v, s256).digest()

  def wif(self, compressed=True, testnet=False):
    # convert the secret from integer to a 32-bytes in big endian using num.to_bytes(32, 'big')
    secret_bytes = self.secret.to_bytes(32, 'big')
    # prepend b'\xef' on testnet, b'\x80' on mainnet
    if testnet:
        prefix = b'\xef'
    else:
        prefix = b'\x80'
    # append b'\x01' if compressed
    if compressed:
        suffix = b'\x01'
    else:
        suffix = b''
    # encode_base58_checksum the whole thing
    return encode_base58_checksum(prefix + secret_bytes + suffix)

def main():
    print('This is the S256 class')

if __name__ == "__main__":
    main()