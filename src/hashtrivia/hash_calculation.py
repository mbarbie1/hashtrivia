import os
from enum import Enum
import hashlib

from hashtrivia.util import read_file_as_bytes


class HashCalculation:
    file_path = ""
    HashAlgos = Enum("HashAlgos", ["MD5", "SHA1", "SHA256", "SHA384", "SHA512"])
    computed_hashes = None

    def __init__(self, file_path) -> None:
        self.file_path = file_path
        pass

    def get_HashAlgos(self):
        return self.HashAlgos

    def get_file_path(self):
        return self.file_path

    def get_hash(self, hash_algo):
        """
        Computes the hash for a given file for a specified algorithm.

        Args:
            hash_algo(str): specific hashing algorithm.

        Returns:
            hash(str): the hash value, or empty string when hash_algo is unknown
        """
        file_bytes = read_file_as_bytes(self.file_path)
        hash = ""
        match hash_algo:
            case self.HashAlgos.MD5:
                hash = hashlib.md5(file_bytes).hexdigest()
            case self.HashAlgos.SHA1:
                hash = hashlib.sha1(file_bytes).hexdigest()
            case self.HashAlgos.SHA256:
                hash = hashlib.sha256(file_bytes).hexdigest()
            case self.HashAlgos.SHA384:
                hash = hashlib.sha384(file_bytes).hexdigest()
            case self.HashAlgos.SHA512:
                hash = hashlib.sha512(file_bytes).hexdigest()
            case _:
                print("Unknown hash algorithm.")

        return hash

    def get_hash_all(self):
        """
        Computes the hashes for each algorithm.

        Returns:
            hash_dict(dict): dictionary listing the algorithms with
                corresponding hashes.
        """
        hash_dict = dict()
        for hash_algo in self.HashAlgos:
            self.get_hash(hash_algo)
            hash_dict[hash_algo.name] = self.get_hash(hash_algo)
            self.computed_hashes = hash_dict
        return hash_dict

    def hash_compare(self, input_hash):
        """
        Compares input hash with computed hashes from file.

        The function veryfies whether any of the hashes corresponds to the
        provided input hash. The input hash should be in hexadecimal
        format, but can be lower- or uppercase and contain a prefix and/or
        suffix. When a match is found, the corresponding hash algorithm and hash
        value is returned as a tuple.

        Args:
            input_hash(str): represents a user input hash

        Returns:
            Tuple(str, str) containing hash algorithm and value when the hash
            matches, otherwise None
        """
        for hash_algo, hash_value in self.get_hash_all().items():
            if hash_value.casefold() in input_hash.casefold():
                return (hash_algo, hash_value)
        return None

    def hash_compare_all(self, input_hash, recompute):
        """
        Compares input hash with computed hashes from file (re-compute optional).

        The function veryfies whether any of the hashes corresponds to the
        provided input hash. The input hash should be in hexadecimal
        format, but can be lower- or uppercase and contain a prefix and/or
        suffix. When a match is found, the corresponding hash algorithm and hash
        value is returned as a tuple.

        Args:
            input_hash(str): represents a user input hash
            recompute(bool): If true, always recomputes all hashes

        Returns:
            Tuple(str, str) containing hash algorithm and value when the hash
            matches, otherwise None
        """
        if (self.computed_hashes is None) or recompute:
            self.computed_hashes = self.get_hash_all()
        for hash_algo, hash_value in self.computed_hashes.items():
            if hash_value.casefold() in input_hash.casefold():
                return (hash_algo, hash_value)
        return None
