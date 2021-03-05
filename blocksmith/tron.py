import codecs
import ecdsa
from Crypto.Hash import keccak
import base58

class TronWallet:
    # refer to tronpy doc:
    # https://github.com/andelf/tronpy/blob/80354eb8a968898aa271841644975f7a8926fdc2/tronpy/keys/__init__.py#L30
    
    @staticmethod
    def generate_address(private_key):
        public_key = TronWallet.__private_to_public(private_key)
        address = TronWallet.__public_to_address(public_key)
        return address

    @staticmethod
    def checksum_address(address):
        checksum = 'T'
        # Remove '0x' from the address
        address = address[1:]
        address_byte_array = address.encode('utf-8')
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(address_byte_array)
        keccak_digest = keccak_hash.hexdigest()
        for i in range(len(address)):
            address_char = address[i]
            keccak_char = keccak_digest[i]
            if int(keccak_char, 16) >= 10:
                checksum += address_char.upper()
            else:
                checksum += str(address_char)
        return checksum
    
    @staticmethod
    def __private_to_public(private_key):
        private_key_bytes = codecs.decode(private_key, 'hex')
        # Get ECDSA public key
        key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
        key_bytes = key.to_string()
        public_key = codecs.encode(key_bytes, 'hex')
        return public_key

    @staticmethod
    def __public_to_address(public_key):
        public_key_bytes = codecs.decode(public_key, 'hex')
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(public_key_bytes)
        keccak_digest = keccak_hash.digest()  #.digest(), rather than .hexdigest()
        # Take last 20 bytes
        wallet_len = 20
        primative_addr = b"\x41" + keccak_digest[-wallet_len:]
        wallet = base58.b58encode_check(primative_addr).decode()
        return wallet