import os
from enum import Enum
import time

# Pylance cannot resolve the import, but it works see: https://github.com/PySimpleGUI/PySimpleGUI/issues/5189
import PySimpleGUI as sg
import pyperclip

from hashtrivia.hash_calculation import HashCalculation
from hashtrivia.util import AlgoMeta


class GUI:
    """
    The graphical user interface for the hash checker.

    The user interface allows the user to either compute (a selection of) hash
    algorithms: MD5, SHA-1, SHA-2 (256, 384, 512) of a user selected file. Next,
    when the user copies a known hash to the clipboard, it can be compared with
    the computed hashes. The actual hash computations are provided by a helper
    class (HashCalculation).

    Typical usage example:
        (starts the app)
        gui = GUI()
        gui.show_window()
    """

    BOX_SIZE = (8, None)
    COPY_SIZE = (8, None)
    LABEL_SIZE = (16, 2)
    HASH_SIZE = (80, 2)
    BUTTON_PAD = (5, 10)
    SEPARATOR_PAD = (10, 10)

    window = None
    layout = None
    file_path = None
    hash_calculation = None
    # Define UI component reference keys
    CompKey = Enum(
        "CompKey",
        [
            "B_LOAD",
            "T_LOAD",
            "B_HELP",
            "B_COMPUTE",
            "T_TIME",
            "B_COMPARE_ALL",
            "B_COMPARE",
            "CB_MD5",
            "T_MD5",
            "COPY_MD5",
            "CB_SHA1",
            "T_SHA1",
            "COPY_SHA1",
            "CB_SHA256",
            "T_SHA256",
            "COPY_SHA256",
            "CB_SHA384",
            "T_SHA384",
            "COPY_SHA384",
            "CB_SHA512",
            "T_SHA512",
            "COPY_SHA512",
            "T_COMPARE",
            "B_EXIT",
        ],
    )

    ALGO_META = dict()
    for hash_algo in HashCalculation.HashAlgos:
        ALGO_META[hash_algo.name] = AlgoMeta(hash_algo.name)

    def __init__(self) -> None:
        self.layout = [
            [
                sg.Button(
                    "Load file",
                    key=self.CompKey.B_LOAD.name,
                    size=self.BOX_SIZE,
                    expand_x=True,
                ),
                sg.Text(
                    "",
                    key=self.CompKey.T_LOAD.name,
                    size=self.HASH_SIZE,
                    background_color="white",
                ),
                sg.Button("Help", key=self.CompKey.B_HELP.name, size=self.COPY_SIZE),
            ],
            [
                sg.Button(
                    "Compute selection",
                    key=self.CompKey.B_COMPUTE.name,
                    expand_x=True,
                    pad=self.BUTTON_PAD,
                ),
                sg.Button(
                    "Compare w/ clipboard",
                    key=self.CompKey.B_COMPARE.name,
                    expand_x=True,
                    pad=self.BUTTON_PAD,
                ),
            ],
            [sg.HorizontalSeparator(pad=self.SEPARATOR_PAD)],
            [
                sg.Checkbox(
                    "MD5", default=True, k=self.CompKey.CB_MD5.name, size=self.BOX_SIZE
                ),
                sg.Text(
                    "",
                    key=self.CompKey.T_MD5.name,
                    size=self.HASH_SIZE,
                    background_color="white",
                ),
                sg.Button("COPY", key=self.CompKey.COPY_MD5.name, size=self.COPY_SIZE),
            ],
            [
                sg.Checkbox(
                    "SHA-1",
                    default=True,
                    k=self.CompKey.CB_SHA1.name,
                    size=self.BOX_SIZE,
                ),
                sg.Text(
                    "",
                    key=self.CompKey.T_SHA1.name,
                    size=self.HASH_SIZE,
                    background_color="white",
                ),
                sg.Button("COPY", key=self.CompKey.COPY_SHA1.name, size=self.COPY_SIZE),
            ],
            [
                sg.Checkbox(
                    "SHA-256",
                    default=True,
                    k=self.CompKey.CB_SHA256.name,
                    size=self.BOX_SIZE,
                ),
                sg.Text(
                    "",
                    key=self.CompKey.T_SHA256.name,
                    size=self.HASH_SIZE,
                    background_color="white",
                ),
                sg.Button(
                    "COPY", key=self.CompKey.COPY_SHA256.name, size=self.COPY_SIZE
                ),
            ],
            [
                sg.Checkbox(
                    "SHA-384",
                    default=True,
                    k=self.CompKey.CB_SHA384.name,
                    size=self.BOX_SIZE,
                ),
                sg.Text(
                    "",
                    key=self.CompKey.T_SHA384.name,
                    size=self.HASH_SIZE,
                    background_color="white",
                ),
                sg.Button(
                    "COPY", key=self.CompKey.COPY_SHA384.name, size=self.COPY_SIZE
                ),
            ],
            [
                sg.Checkbox(
                    "SHA-512",
                    default=True,
                    k=self.CompKey.CB_SHA512.name,
                    size=self.BOX_SIZE,
                ),
                sg.Text(
                    "",
                    key=self.CompKey.T_SHA512.name,
                    size=self.HASH_SIZE,
                    background_color="white",
                ),
                sg.Button(
                    "COPY", key=self.CompKey.COPY_SHA512.name, size=self.COPY_SIZE
                ),
            ],
            [sg.HorizontalSeparator(pad=self.SEPARATOR_PAD)],
            [
                sg.Text("", key=self.CompKey.T_COMPARE.name, expand_x=True),
                sg.Button("Exit", key=self.CompKey.B_EXIT.name, size=self.COPY_SIZE),
            ],
        ]
        # Create the Window
        self.window = sg.Window("Hash Trivia, the trivial hash checker", self.layout)
        pass

    def show_window(self):
        """
        The event loop of the PySimpleGUI window.

        Events include the file browse, compute, compare, copy hash, help, exit,
        etc. buttons and provide the main logic of the user interface.

        Args:
            None

        Returns:
            None
        """
        # Event Loop to process "events" and get the "values" of the inputs
        while True:
            event, values = self.window.read()
            if (
                event == sg.WIN_CLOSED or event == self.CompKey.B_EXIT.name
            ):  # if user closes window or clicks cancel
                break
            elif event == self.CompKey.B_HELP.name:
                print("[LOG] Clicked About")
                sg.popup(
                    "Help for Hash Checker:",
                    "This tool computes various hashes to help verifying file integrity. Follow the steps below to check your file",
                    "  1 - Browse for the file you want to verify",
                    "  2 - Optionally use the checkboxes to compute a subset of hash types",
                    "  3 - Press compute hashes, this will show the hashes",
                    "  4 - Compare an original trusted hash by pressing compare hashes",
                    "When the hash can be matched, it will indicate so.",
                    keep_on_top=True,
                )
            elif event == self.CompKey.B_LOAD.name:
                print("[LOG] Clicked Open File")
                self.file_path = sg.popup_get_file("Choose your file", keep_on_top=True)
                self.window[self.CompKey.T_LOAD.name].update(
                    self.file_path, text_color="black"
                )
            elif event == self.CompKey.B_COMPUTE.name:
                print("[LOG] Clicked Compute")
                self.window[self.CompKey.T_COMPARE.name].update("")
                if not self.file_path == None:
                    if os.path.isfile(self.file_path):
                        self.compute_hashes()
                else:
                    self.window[self.CompKey.T_COMPARE.name].update(
                        "No valid file found to generate hashes."
                    )
            elif event == self.CompKey.B_COMPARE.name:
                print("[LOG] Clicked Compare")
                if not self.file_path == None:
                    if os.path.isfile(self.file_path):
                        init_file = True
                        recompute = True
                        self.compare_user_hash(init_file=init_file, recompute=recompute)
                else:
                    self.window[self.CompKey.T_COMPARE.name].update(
                        "No valid file found to generate hashes."
                    )
            else:
                for hash_algo in HashCalculation.HashAlgos:
                    if event == AlgoMeta(hash_algo.name).COPY_key:
                        pyperclip.copy(
                            self.window[AlgoMeta(hash_algo.name).T_key].get()
                        )

        self.window.close()

    def compute_hashes(self):
        """
        Compute the hashes for the given file and visualize them.

        All hash algorithm are performed on the file of the given file path.
        For each hashing algorithm that is checked, the hash is shown in its
        corresponding textbox. Not computed hashes are grayed out.

        TODO: don't perform the computation for the ones we will not use.

        Args:
            None

        Returns:
            None

        """
        self.hash_calculation = HashCalculation(self.file_path)
        hashes = self.hash_calculation.get_hash_all()
        HA = self.hash_calculation.HashAlgos
        for hash_algo in HashCalculation.HashAlgos:
            algo_meta = AlgoMeta(hash_algo.name)
            if self.window[algo_meta.CB_key].get():
                self.window[algo_meta.T_key].update(
                    hashes[hash_algo.name], text_color="black", background_color="white"
                )
            else:
                self.window[algo_meta.T_key].update(
                    "", text_color="black", background_color="gray"
                )

    def compare_user_hash(self, init_file, recompute) -> bool:
        """
        Compare hash on clipboard with computed hashes from file.

        The function veryfies whether any of the hashes corresponds to the
        provided hash on the clipboard. The user hash should be in hexadecimal
        format, but can be lower- or uppercase and contain a prefix and/or
        suffix. When a match is found, the corresponding hash is highlighted in
        the list.

        Args:
            init_file(bool): If true, always (re-)initializes the file
            recompute(bool): If true, always recomputes all hashes

        Returns:
            True when the user hash matches, otherwise False
        """
        user_hash = pyperclip.paste()
        if (self.hash_calculation is None) or init_file:
            self.hash_calculation = HashCalculation(self.file_path)
        if (self.hash_calculation.computed_hashes is None) or recompute:
            self.compute_hashes()
        res = self.hash_calculation.hash_compare(user_hash)
        self.window[self.CompKey.T_COMPARE.name].update(res)
        if isinstance(res, tuple):
            (hash_algo, hash_value) = res
            self.window[self.CompKey.T_COMPARE.name].update("Matching " + hash_algo)
            algo_meta = AlgoMeta(hash_algo)
            self.window[algo_meta.T_key].update(
                background_color="#88FF88",
            )
            return True
        else:
            self.window[self.CompKey.T_COMPARE.name].update("No match found")
            return False
