import unittest
import os
import threading
import time
import sys

sys.path.append("./src")

import PySimpleGUI as sg
import pyperclip

from hashtrivia.gui import GUI
from hashtrivia.util import AlgoMeta
from hashtrivia.hash_calculation import HashCalculation
from tests.util import DATA
from tests.util import INPUT_HASH_MD5_VALID
from tests.util import INPUT_HASH_MD5_INVALID


def user_worker(gui, kv_list, wait_time):
    for k, v in kv_list:
        time.sleep(wait_time)
        if v == CLICK_VALUE:
            gui.window.find_element(k).click()
        else:
            gui.window.find_element(k).update(v)


CLICK_VALUE = "CLICK"


class TestGUI(unittest.TestCase):
    def test_window_creation(self):
        gui = GUI()
        self.assertIsInstance(gui.window, sg.Window)

    def test_show_window(self):
        gui = GUI()
        gui.show_window()

    def test_show_all_hashes_by_pressing_compute_then_exit(self):
        gui = GUI()
        gui.file_path = os.path.join(DATA, "test_file_1.csv")
        # start user events thread to for load file and compute events
        kv_list = [
            (gui.CompKey.B_COMPUTE.name, CLICK_VALUE),
            (gui.CompKey.B_EXIT.name, CLICK_VALUE),
        ]
        wait_time = 1
        threading.Thread(target=user_worker, args=(gui, kv_list, wait_time)).start()
        gui.show_window()

    def test_show_help(self):
        gui = GUI()
        gui.file_path = os.path.join(DATA, "test_file_1.csv")
        # start user events thread to for load file and compute events
        kv_list = [
            (gui.CompKey.B_HELP.name, CLICK_VALUE),
            (gui.CompKey.B_EXIT.name, CLICK_VALUE),
        ]
        wait_time = 1
        threading.Thread(target=user_worker, args=(gui, kv_list, wait_time)).start()
        gui.show_window()

    def test_show_all_hashes_and_compare_with_hash_on_clipboard(self):
        gui = GUI()
        gui.file_path = os.path.join(DATA, "test_file_1.csv")
        # put user hash on clipboard
        pyperclip.copy(INPUT_HASH_MD5_VALID)
        # start user events thread to for load file and compute events
        kv_list = [
            (gui.CompKey.B_COMPUTE.name, CLICK_VALUE),
            (gui.CompKey.B_COMPARE.name, CLICK_VALUE),
            (gui.CompKey.B_EXIT.name, CLICK_VALUE),
        ]
        wait_time = 1
        threading.Thread(target=user_worker, args=(gui, kv_list, wait_time)).start()
        gui.show_window()

    def test_show_all_hashes_then_copy_and_valid_compare(self):
        gui = GUI()
        gui.file_path = os.path.join(DATA, "test_file_1.csv")
        # start user events thread to for load file and compute events
        algo_meta = AlgoMeta(algo=HashCalculation.HashAlgos.SHA1.name)
        copy_button_key = algo_meta.COPY_key
        kv_list = [
            (gui.CompKey.B_COMPUTE.name, CLICK_VALUE),
            (copy_button_key, CLICK_VALUE),
            (gui.CompKey.B_COMPARE.name, CLICK_VALUE),
            (gui.CompKey.B_EXIT.name, CLICK_VALUE),
        ]
        wait_time = 1
        threading.Thread(target=user_worker, args=(gui, kv_list, wait_time)).start()
        gui.show_window()

    def test_empty_hash_for_algos_not_checked(self):
        gui = GUI()
        gui.file_path = os.path.join(DATA, "test_file_1.csv")
        # start user events thread to for load file and compute events
        algo_meta = AlgoMeta(algo=HashCalculation.HashAlgos.SHA1.name)
        cb_key = algo_meta.CB_key
        kv_list = [
            (cb_key, False),
            (gui.CompKey.B_COMPUTE.name, CLICK_VALUE),
            (gui.CompKey.B_COMPARE.name, CLICK_VALUE),
            (gui.CompKey.B_EXIT.name, CLICK_VALUE),
        ]
        wait_time = 1
        threading.Thread(target=user_worker, args=(gui, kv_list, wait_time)).start()
        gui.show_window()
