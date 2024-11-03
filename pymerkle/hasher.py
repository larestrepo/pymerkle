import hashlib
from pymerkle import constants


class MerkleHasher:
    """
    Encapsulates elementary hashing operations.

    :param algorithm: hash algorithm
    :type algorithm: str
    :param security: [optional] resistance against second-preimage attack. Defaults
        to *True*
    :type security: bool
    """

    def __init__(self, algorithm, security=True, **kw):
        normalized = algorithm.lower().replace('-', '_')
        if normalized not in constants.ALGORITHMS:
            msg = f'{algorithm} not supported'
            if normalized in constants.KECCAK_ALGORITHMS:
                msg += ': You need to install pysha3'
            raise ValueError(msg)
        self.algorithm = algorithm

        module = hashlib
        if normalized in constants.KECCAK_ALGORITHMS:
            import sha3
            module = sha3
        self.hashfunc = getattr(module, self.algorithm)

        self.security = security
        self.prefx00 = b'\x00' if self.security else b''
        self.prefx01 = b'\x01' if self.security else b''


    def _consume_bytes(self, buff) -> bytes:
        """
        :param buff:
        :type buff: bytes
        :rtype: bytes
        """
        hasher = self.hashfunc()
        update = hasher.update
        chunksize = 1024
        offset = 0
        chunk = buff[offset: chunksize]
        while chunk:
            update(chunk)
            offset += chunksize
            chunk = buff[offset: offset + chunksize]

        return hasher.digest()


    def hash_empty(self) -> bytes:
        """
        Computes the hash of the empty data without prepending security
        prefixes.

        :param buff:
        :type buff: bytes
        :rtype: bytes
        """
        return self._consume_bytes(b'')
    
    def hash_empty_hex(self) -> str:
        """
        Computes the hash of the empty data without prepending security
        prefixes.

        :param buff:
        :type buff: bytes
        :rtype: str
        """
        return self.hash_empty().hex()


    def hash_raw(self, buff: bytes) -> bytes:
        """
        Computes the hash of the provided data without prepending security
        prefixes.

        :param buff:
        :type buff: bytes
        :rtype: bytes
        """
        return self._consume_bytes(buff)
    
    def hash_raw_hex(self, buff: bytes) -> str:
        """
        Computes the hash of the provided data without prepending security
        prefixes.

        :param buff:
        :type buff: bytes
        :rtype: str
        """
        return self.hash_raw(buff).hex()


    def hash_buff(self, data: bytes) -> bytes:
        """
        Computes the hash of the provided binary data.

        .. note:: Prepends ``\\x00`` if security mode is enabled

        :type data: bytes
        :rtype: bytes
        """
        return self._consume_bytes(self.prefx00 + data)

    def hash_hex(self, data: bytes) -> str:
        """
        Computes the hash of the provided binary data and returns it in hexadecimal
        format.

        :type data: bytes
        :rtype: str
        """
        return self.hash_buff(data).hex()


    def hash_pair(self, buff1, buff2) -> bytes:
        """
        Computes the hash of the concatenation of the provided binary data.

        .. note:: Prepends ``\\x01`` if security mode is enabled

        :param buff1: left value
        :type buff1: bytes
        :param buff2: right value
        :type buff2: bytes
        :rtype: bytes
        """
        return self.hashfunc(self.prefx01 + buff1 + buff2).digest()
    
    
    def hash_pair_hex(self, buff1, buff2) -> str:
        """
        Computes the hash of the concatenation of the provided binary data and
        returns it in hexadecimal format.

        :param buff1: left value
        :type buff1: bytes
        :param buff2: right value
        :type buff2: bytes
        :rtype: str
        """
        return self.hash_pair(buff1, buff2).hex()
