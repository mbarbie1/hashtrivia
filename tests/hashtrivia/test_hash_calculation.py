import unittest
import os
import sys
import csv
from pathlib import Path

sys.path.append("./src")

from hashtrivia.hash_calculation import HashCalculation
from tests.util import DATA
from tests.util import ground_truth_hash_table
from tests.util import INPUT_HASH_MD5_VALID
from tests.util import INPUT_HASH_MD5_INVALID


class TestHashCalculation(unittest.TestCase):
    def test_get_hash_returns_string_for_sha256(self):
        file_path = os.path.join(DATA, "test_file_1.csv")
        hc = HashCalculation(file_path)
        hash_algo = "SHA256"
        hash = hc.get_hash(hash_algo)
        self.assertIsInstance(hash, str)

    def test_get_hash_returns_string_for_every_hash_algo_if_file_path_exists(self):
        file_path = os.path.join(DATA, "test_file_1.csv")
        hc = HashCalculation(file_path)
        hash_algos = hc.get_HashAlgos()
        for hash_algo in hash_algos:
            hash = hc.get_hash(hash_algo)
            self.assertIsInstance(hash, str)

    def test_get_hash_fails_on_nonexisting_file_path(self):
        hc = HashCalculation("")
        file_path = hc.get_file_path()
        hash_algos = hc.get_HashAlgos()
        hash_algo = hash_algos.SHA256
        self.assertFalse(os.path.exists(file_path))
        self.assertRaises(Exception, hc.get_hash, hash_algo)

    # Note: next test concerns case-insensitive comparison, meaning that it fails less.
    def test_get_hash_return_correct_case_insensitive_hash_for_each_algo(self):
        hashes_ground_truth = ground_truth_hash_table()
        file_path = os.path.join(DATA, "test_file_1.csv")
        hc = HashCalculation(file_path)
        hash_algos = hc.get_HashAlgos()
        for hash_algo in hash_algos:
            hash = hc.get_hash(hash_algo)
            hash_gt = hashes_ground_truth[hash_algo.name]
            self.assertEqual(hash.casefold(), hash_gt.casefold())

    def test_get_hash_all_returns_dict_in_correct_format(self):
        file_path = os.path.join(DATA, "test_file_1.csv")
        hc = HashCalculation(file_path)
        hashes = hc.get_hash_all()
        # Assert it is a dict
        self.assertIsInstance(hashes, dict)
        # Then assert the dict contains each hash algorithm name
        for hash_algo in hc.get_HashAlgos():
            self.assertIn(hash_algo.name, hashes.keys())
        # Assert the dict contains strings as value for each algorithm
        for hash_value in hashes.values():
            self.assertIsInstance(hash_value, str)

    def test_compare_valid_given_hash_with_computed_hashes(self):
        input_hash = INPUT_HASH_MD5_VALID
        file_path = os.path.join(DATA, "test_file_1.csv")
        hc = HashCalculation(file_path)
        hashes = hc.get_hash_all()
        (hash_algo, hash_value) = hc.hash_compare(input_hash)
        self.assertEqual(hash_algo, "MD5")
        self.assertTrue(hash_value.casefold() in input_hash.casefold())

    def test_compare_invalid_given_hash_with_computed_hashes_returns_None(self):
        input_hash = INPUT_HASH_MD5_INVALID
        file_path = os.path.join(DATA, "test_file_1.csv")
        hc = HashCalculation(file_path)
        hashes = hc.get_hash_all()
        self.assertIsNone(hc.hash_compare(input_hash))

    def test_compare_all_without_recompute(self):
        input_hash = INPUT_HASH_MD5_VALID
        file_path = os.path.join(DATA, "test_file_1.csv")
        hc = HashCalculation(file_path)
        # Case: no hashes available, recompute is false --> compute for the first time
        hc.computed_hashes = None
        (hash_algo, hash_value) = hc.hash_compare_all(input_hash, False)
        self.assertTrue(hash_value.casefold() in input_hash.casefold())

    def test_compare_all_without_recompute_with_hashes(self):
        input_hash = INPUT_HASH_MD5_VALID
        file_path = os.path.join(DATA, "test_file_1.csv")
        hc = HashCalculation(file_path)
        # Case: hashes available, recompute is false
        hc.get_hash_all()
        (hash_algo, hash_value) = hc.hash_compare_all(input_hash, False)
        self.assertTrue(hash_value.casefold() in input_hash.casefold())

    def test_compare_all_with_recompute(self):
        input_hash = INPUT_HASH_MD5_VALID
        file_path = os.path.join(DATA, "test_file_1.csv")
        hc = HashCalculation(file_path)
        # Case: hashes available, recompute is True
        hc.get_hash_all()
        (hash_algo, hash_value) = hc.hash_compare_all(input_hash, True)
        self.assertTrue(hash_value.casefold() in input_hash.casefold())
