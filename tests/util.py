import os
import csv
from pathlib import Path

# define the test data path
root_path = Path(os.path.dirname(__file__)).parent.absolute()
DATA = os.path.join(root_path, 'test_data')
INPUT_HASH_MD5_VALID = 'Correct hash with prefix E9DE60E050F6E9AFA860C56281DE4B82'
INPUT_HASH_MD5_INVALID = 'Wrong hash E96281DE4B82'

def reader_hash_table(file_path):
    hash_dict = dict()
    with open(file_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile, skipinitialspace=True)
        for row in reader:
            print(row)
            hash_dict[row['algorithm']] = row['hash'].rstrip()
    return hash_dict

def ground_truth_hash_table():
    return reader_hash_table(os.path.join(DATA, "hash_gt__test_file_1.csv"))
