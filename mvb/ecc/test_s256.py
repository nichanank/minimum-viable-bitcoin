import unittest
from random import randint
from .s256 import S256Field, S256Point, G, N, Signature, PrivateKey

class S256Test(unittest.TestCase):

  def test_order(self):
    point = N * G
    self.assertIsNone(point.x)

  def test_pubpoint(self):
    # write a test that tests the public point for the following
    points = (
        # secret, x, y
        (7, 0x5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc, 0x6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da),
        (1485, 0xc982196a7466fbbbb0e27a940b6af926c1a74d5ad07128c82824a11b5398afda, 0x7a91f9eae64438afb9ce6448a1c133db2d8fb9254e4546b6f001637d50901f55),
        (2**128, 0x8f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da, 0x662a9f2dba063986de1d90c2b6be215dbbea2cfe95510bfdf23cbf79501fff82),
        (2**240 + 2**31, 0x9577ff57c8234558f293df502ca4f09cbc65a6572c842b39b366f21717945116, 0x10b49c67fa9365ad7b90dab070be339a1daf9052373ec30ffae4f72d5e66d053),
    )

    # iterate over points
    for secret, x, y in points:
        # initialize the secp256k1 point (S256Point)
        point = S256Point(x, y)
        # check that the secret*G is the same as the point
        self.assertEqual(secret * G, point)

  def test_verify(self):
    point = S256Point(
        0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c,
        0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34)
    z = 0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60
    r = 0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395
    s = 0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4
    self.assertTrue(point.verify(z, Signature(r, s)))
    z = 0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d
    r = 0xeff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c
    s = 0xc7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6
    self.assertTrue(point.verify(z, Signature(r, s)))

  def test_sec(self):
    coefficient = 999**3
    uncompressed = '049d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d56fa15cc7f3d38cda98dee2419f415b7513dde1301f8643cd9245aea7f3f911f9'
    compressed = '039d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d5'
    point = coefficient * G
    self.assertEqual(point.sec(compressed=False), bytes.fromhex(uncompressed))
    self.assertEqual(point.sec(compressed=True), bytes.fromhex(compressed))
    coefficient = 123
    uncompressed = '04a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5204b5d6f84822c307e4b4a7140737aec23fc63b65b35f86a10026dbd2d864e6b'
    compressed = '03a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5'
    point = coefficient * G
    self.assertEqual(point.sec(compressed=False), bytes.fromhex(uncompressed))
    self.assertEqual(point.sec(compressed=True), bytes.fromhex(compressed))
    coefficient = 42424242
    uncompressed = '04aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e21ec53f40efac47ac1c5211b2123527e0e9b57ede790c4da1e72c91fb7da54a3'
    compressed = '03aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e'
    point = coefficient * G
    self.assertEqual(point.sec(compressed=False), bytes.fromhex(uncompressed))
    self.assertEqual(point.sec(compressed=True), bytes.fromhex(compressed))

  def test_address(self):
    secret = 888**3
    mainnet_address = '148dY81A9BmdpMhvYEVznrM45kWN32vSCN'
    testnet_address = 'mieaqB68xDCtbUBYFoUNcmZNwk74xcBfTP'
    point = secret * G
    self.assertEqual(
        point.address(compressed=True, testnet=False), mainnet_address)
    self.assertEqual(
        point.address(compressed=True, testnet=True), testnet_address)
    secret = 321
    mainnet_address = '1S6g2xBJSED7Qr9CYZib5f4PYVhHZiVfj'
    testnet_address = 'mfx3y63A7TfTtXKkv7Y6QzsPFY6QCBCXiP'
    point = secret * G
    self.assertEqual(
        point.address(compressed=False, testnet=False), mainnet_address)
    self.assertEqual(
        point.address(compressed=False, testnet=True), testnet_address)
    secret = 4242424242
    mainnet_address = '1226JSptcStqn4Yq9aAmNXdwdc2ixuH9nb'
    testnet_address = 'mgY3bVusRUL6ZB2Ss999CSrGVbdRwVpM8s'
    point = secret * G
    self.assertEqual(
        point.address(compressed=False, testnet=False), mainnet_address)
    self.assertEqual(
        point.address(compressed=False, testnet=True), testnet_address)

class SignatureTest(unittest.TestCase):

    def test_der(self):
        testcases = (
            (1, 2),
            (randint(0, 2**256), randint(0, 2**255)),
            (randint(0, 2**256), randint(0, 2**255)),
        )
        for r, s in testcases:
            sig = Signature(r, s)
            der = sig.der()
            sig2 = Signature.parse(der)
            self.assertEqual(sig2.r, r)
            self.assertEqual(sig2.s, s)

class PrivateKeyTest(unittest.TestCase):

    def test_sign(self):
        pk = PrivateKey(randint(0, N))
        z = randint(0, 2**256)
        sig = pk.sign(z)
        self.assertTrue(pk.point.verify(z, sig))

    def test_wif(self):
        pk = PrivateKey(2**256 - 2**199)
        expected = 'L5oLkpV3aqBJ4BgssVAsax1iRa77G5CVYnv9adQ6Z87te7TyUdSC'
        self.assertEqual(pk.wif(compressed=True, testnet=False), expected)
        pk = PrivateKey(2**256 - 2**201)
        expected = '93XfLeifX7Jx7n7ELGMAf1SUR6f9kgQs8Xke8WStMwUtrDucMzn'
        self.assertEqual(pk.wif(compressed=False, testnet=True), expected)
        pk = PrivateKey(0x0dba685b4511dbd3d368e5c4358a1277de9486447af7b3604a69b8d9d8b7889d)
        expected = '5HvLFPDVgFZRK9cd4C5jcWki5Skz6fmKqi1GQJf5ZoMofid2Dty'
        self.assertEqual(pk.wif(compressed=False, testnet=False), expected)
        pk = PrivateKey(0x1cca23de92fd1862fb5b76e5f4f50eb082165e5191e116c18ed1a6b24be6a53f)
        expected = 'cNYfWuhDpbNM1JWc3c6JTrtrFVxU4AGhUKgw5f93NP2QaBqmxKkg'
        self.assertEqual(pk.wif(compressed=True, testnet=True), expected)


if __name__ == "__main__":
  unittest.main()