import os

def read_file_as_bytes(file_path):
    if not os.path.exists(file_path):
        raise OSError
    with open(file_path, "rb") as in_file:
        file_bytes = in_file.read()
    
    return file_bytes

class AlgoMeta:
    algo = None
    label = None
    CB_key = None
    T_key = None
    COPY_key = None

    def __init__(self, algo):
        self.algo = algo
        self.label = algo
        self.CB_key = "CB_" + algo
        self.T_key = "T_" + algo
        self.COPY_key = "COPY_" + algo
