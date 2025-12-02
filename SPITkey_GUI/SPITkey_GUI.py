import uuid
import sys
import os
import re

from Crypto.Cipher import AES
from hashlib import sha256

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QComboBox,
    QFileDialog, QTextEdit, QGroupBox, QMessageBox
)
from PyQt6.QtCore import QObject, pyqtSignal

import traceback

# needed for the starfield nonsense
import random
import math
from PyQt6.QtCore import QTimer, Qt, QPointF
from PyQt6.QtGui import QPainter, QColor, QPen, QFont, QBrush, QPainterPath
# for audio playback
from PyQt6.QtMultimedia import QMediaPlayer, QAudioOutput
from PyQt6.QtCore import QUrl

def get_logfile_content(logfile_path):
    """Reads the dislocker log file content."""
    try:
        with open(logfile_path, "r") as f:
            return f.readlines()
    except FileNotFoundError:
        QMessageBox.critical(
             None, "File Error", f"Log file not found at: {logfile_path}"
             )
        return None


# --------------------------------------------------------------------------- #
# Parse upto 17 lines after offset to extract the Nonce, MAC and Payload      #
# stops looking when it reaches end that datum                                #
# --------------------------------------------------------------------------- #
def get_enc_payload(logfile, offset, verbose=False):
    x = offset
    for y in range(1, 18):
        line = logfile[x + y].strip("\n")
        if "Nonce:" in line:
            nonce = logfile[x + y + 1].strip("\n")
            nonce = nonce.split("[DEBUG] ")
            nonce = bytes.fromhex(nonce[1])
        elif "MAC:" in line:
            mac = logfile[x + y + 1].strip("\n")
            mac = mac.split("[DEBUG] ")
            mac = bytes.fromhex(mac[1])
        elif "Payload:" in line:
            payload = ""
            for z in range(1, 10):
                temp = logfile[x + y + z].strip("\n")
                temp = temp.split("[DEBUG] ")
                temp = temp[1]
                if temp[:2] == "0x":    # dislocker puts a - after the 8th byte
                    temp = temp[11:].replace("-", " ")
                    payload = payload + temp
                else:
                    break
            payload = bytes.fromhex(payload)
        elif "Header safe" in line:      # at the end of the datum stop looking
            break

    if verbose is True:
        print("Found encrypted entry")
        print("Nonce:   " + nonce.hex())
        print("MAC:     " + mac.hex())
        print("Payload: " + payload.hex() + "\n")
    return nonce + mac + payload


# --------------------------------------------------------------------------- #
# Search through the dislocker logfile to find an encrypted key of type       #
# key_type and get the Nonce, MAC and Payload to decrypt                      #
# --------------------------------------------------------------------------- #
def get_enc_key(logfile, key_type):
    alg_type = {
        "Recovery": "0x1000",
        "Password": "0x1001",
        "External": "0x2002",
        "PIN": "0x2004"
    }
    alg = alg_type[key_type]
    found = False
    count = 0
    length = len(logfile)
    for x in range(0, length):
        line = logfile[x].strip("\n")
        if "Algo: " + alg in line:                   # find the datum
            found = True
        if found is True and "Datum value type: 5" in line:
            count = count + 1
        if count == 2:                  # find the second encrypted AES-CCM key
            enc_key = get_enc_payload(logfile, x)
            break
    return enc_key


# --------------------------------------------------------------------------- #
# Search through the dislocker logfile to find the reverse encrypted          #
# recovery key and get the Nonce, MAC and Payload to decrypt                  #
# --------------------------------------------------------------------------- #
def get_rev_key(logfile, vmk_type):
    alg_type = {
        "Recovery": "0x1000",
        "PIN": "0x2004"
    }
    alg = alg_type[vmk_type]
    found = False
    length = len(logfile)
    for x in range(0, length):
        line = logfile[x].strip("\n")
        if "Algo: " + alg in line:                   # find the datum
            found = True
        if found is True and "Datum value type: 5" in line:
            # find the first encrypted AES-CCM key
            rev_key = get_enc_payload(logfile, x)
            break
    return rev_key


# --------------------------------------------------------------------------- #
# Search through the dislocker logfile to find the recovery key GUID          #
#                                                                             #
# --------------------------------------------------------------------------- #
def get_rec_GUID(logfile):
    rec_GUID = ""
    length = len(logfile)
    for x in range(0, length):
        line = logfile[x].strip("\n")
        if "Recovery Key GUID:" in line:
            rec_GUID = line.split("GUID: '")[1]
            rec_GUID = rec_GUID[:-1]
        if "Algo: 0x1000" in line:
            # got the correct recovery key GUID
            return rec_GUID


# --------------------------------------------------------------------------- #
# Search through the dislocker logfile to find the clear VMK  (dislocker -c)  #
#                                                                             #
# --------------------------------------------------------------------------- #
def get_vmk_from_log(logfile, verbose=False):
    vmk = ''
    length = len(logfile)
    x = 0
    found = False
    while x < length and not found:
        line = logfile[x].strip("\n")
        if r"==========================[ VMK ]=========================" in line:
            found = True
        x += 1
    if not found:
        return None

    # Key dump should be within the next 20 lines
    boundary = max(x + 20, length)
    found = False

    while x < boundary and not found:
        line = logfile[x].strip("\n")
        if "Key:" in line:
            for o in (1, 2):
                temp = logfile[x+o].strip("\n").split(r"[DEBUG] ")[1]
                print(f"temp: {temp}")
                if temp[:2] == "0x":    # dislocker puts a - after the 8th byte
                    temp = temp[11:].replace("-", " ")
                    vmk += temp
                else:
                    break
            found = True
        x += 1
    if not found:
        return None

    if verbose is True:
        print("Found VMK in log")
    return bytes.fromhex(vmk)


# --------------------------------------------------------------------------- #
# encode the recovery key as the numeric checksummed recovery key             #
# takes recovery key as bytes returns key as numeric string                   #
# --------------------------------------------------------------------------- #
def enc_rec_key(rec_key):
    key_str = ""

    for i in range(8):
        # get key 2 bytes at a time and make it little endian
        offs = i * 2
        block = rec_key[offs:offs+2]
        int_1 = int.from_bytes(block, byteorder='little')
        # multiply by 11 to get text digits
        num_blk = int_1 * 11

        key_str = key_str + str(num_blk).zfill(6) + "-"

    # remove trailing -
    key_str = key_str[:-1]
    return key_str


# --------------------------------------------------------------------------- #
# Save the numeric encoded recovery key                                       #
# Takes the VMK and the gets the GUID from the dislocker log                  #
# and saves the key in a textfile $GUID.recovery                              #
# --------------------------------------------------------------------------- #
def save_recovery(logfile, VMK, path):
    # get the reverse recovery key and decrypt with the VMK
    REV_rec_enc = get_rev_key(logfile, "Recovery")
    REV_dec = decrypt(REV_rec_enc, VMK)
    rec_GUID = get_rec_GUID(logfile)
    print("Recovery key GUID")
    print(rec_GUID)
    print("Decrypted reverse recovery key")
    REV_key = parse_key(REV_dec)
    rec_key = enc_rec_key(REV_key)

    # save the recovery key to a file $GUID.recovery
    filename = os.path.join(path, rec_GUID + ".recovery")

    print(f"Writing the following to recovery key file: {filename}")
    print(rec_key)
    while True:
        if os.path.isfile(filename):             # warn before overwriting file
            qm = QMessageBox()
            qm.setWindowTitle("File Exists!")
            qm.setText(f"File '{filename}' already exists. Overwrite?")
            qm.setStandardButtons(
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
            qm.setIcon(QMessageBox.Icon.Question)
            button = qm.exec()

            if button == QMessageBox.StandardButton.Yes:
                file = open(filename, "w")
                file.write(rec_key)
                file.close()
                return filename
            if button == QMessageBox.StandardButton.No:
                print("key not written")
                return None
        else:
            file = open(filename, "w")
            file.write(rec_key)
            file.close()
            return filename


# --------------------------------------------------------------------------- #
# Search through the dislocker logfile to find the encrypted FVEK             #
# and get the Nonce, MAC and Payload to decrypt                               #
# --------------------------------------------------------------------------- #
def get_enc_fvek(logfile):
    length = len(logfile)
    for x in range(0, length):
        line = logfile[x].strip("\n")
        if "Datum entry type: 3" in line:
            enc_key = get_enc_payload(logfile, x)
            break
    return enc_key


# --------------------------------------------------------------------------- #
# get the salt needed to stretch the PIN, Password or recovery hash from the  #
# logfile salt_type should be "PIN" "Password" or "Recovery"                  #
# --------------------------------------------------------------------------- #
def get_salt(logfile, salt_type):
    salt_alg = {
        "Recovery": "0x1000",
        "Password": "0x1001",
        "PIN": "0x2004"
    }
    alg = salt_alg[salt_type]
    found = False
    length = len(logfile)
    for x in range(0, length):
        line = logfile[x].strip("\n")
        if "Algo: " + alg in line:                   # find the datum
            found = True
        if found is True and "Salt:" in line:
            salt = logfile[x + 1].strip("\n")
            salt = salt.split("[DEBUG] ")
            salt = bytes.fromhex(salt[1])
            break
    return salt


# --------------------------------------------------------------------------- #
# get the computer name from datum type 7 to use when saving the FVEK         #
# --------------------------------------------------------------------------- #
def get_name(logfile):
    length = len(logfile)
    name = ""
    for x in range(0, length):
        line = logfile[x].strip("\n")
        if "Datum entry type: 7" in line:
            for y in range(1, 10):
                temp = logfile[x + y].strip("\n")
                if "UTF-16 string:" in temp:
                    name = temp.split("UTF-16 string: '")
                    name = name[1]
                    name = name.split(" ")
                    name = name[0]
                    return name


# --------------------------------------------------------------------------- #
# The first step in PIN expansion is to change it to utf-16le with no BOM     #
# then hash the PIN with sha256(sha256(pin)) to create the hash key           #
# --------------------------------------------------------------------------- #
def hash_pin(password):
    prepared_pass = password.encode("utf-16le")
    user_hash = sha256(prepared_pass).digest()
    user_hash = sha256(user_hash).digest()
    return user_hash


# --------------------------------------------------------------------------- #
# The second step in PIN expansion is to take the hash key, stretch key salt  #
# and counter and do 0x100000 hashes to generate the actual decryption key    #
# see https://arxiv.org/pdf/1901.01337.pdf                                    #
# https://github.com/Aorimn/dislocker/blob/master/src/accesses/stretch_key.c  #
# --------------------------------------------------------------------------- #
def stretch_key(key, salt):
    last_sha256 = bytes.fromhex("00 00 00 00 00 00 00 00 "
                                "00 00 00 00 00 00 00 00 "
                                "00 00 00 00 00 00 00 00 "
                                "00 00 00 00 00 00 00 00")
    initial_sha256 = key
    count = bytes.fromhex("00 00 00 00 00 00 00 00")

    for i in range(1048576):
        count = i.to_bytes(8, byteorder="little")
        tmp_sha = sha256(last_sha256 + initial_sha256 + salt + count).digest()
        last_sha256 = tmp_sha
    return last_sha256


# --------------------------------------------------------------------------- #
#  XOR two keys together and return the result for protector and StartupKey   #
# --------------------------------------------------------------------------- #
def xor_keys(key1, key2):
    return bytes([a ^ b for a, b in zip(key1, key2)])


# --------------------------------------------------------------------------- #
#  AES-CCM decrypt the data src https://github.com/libyal/libbde/issues/36	  #
# --------------------------------------------------------------------------- #
def decrypt(data, key, verbose=False):
    nonce = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]
    aes = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=16)
    data_dec = aes.decrypt_and_verify(ciphertext, tag)
    if verbose is True:
        print("Key:       " + key.hex())
        print("nonce:     " + nonce.hex())
        print("MAC:       " + tag.hex())
        print("Encrypted: " + ciphertext.hex())
        print("Decrypted: " + data_dec.hex())
        print("")
    return data_dec


# --------------------------------------------------------------------------- #
# Get the TPMandPIN blob from a file. It accepts either just the blob data    #
# the blob data with header or the responseparams Hex Stream from wireshark   #
# which is the blob data with header with an additional 2 byte length header  #
# --------------------------------------------------------------------------- #
def get_blob(filename):
    print("Reading PIN encrypted VMK from file")
    filedata = open(filename, "r")
    blob = filedata.read()
    filedata.close()
    blob = blob.replace("\n", "")      # incase data is split on multiple lines
    blob = blob.replace(" ", "")       # strip spaces too

    # if data is responseparams from wireshark
    if blob[:4] == "0050" and len(blob) == 164:
        print("Found wireshark responseparams, trimming first two bytes")
        blob = blob[4:]             # wireshark includes the param size header

    # if data is the bare blob without header
    if len(blob) == 144:
        print("Found a bare blob without header, adding a placeholder header")
        blob = "5000000005000000" + blob

    # if data is the bare blob with header
    if blob[:4] == "5000" and len(blob) == 160:
        blob = blob[16:]             # tpm2pcap does not include the param size
        blob = bytes.fromhex(blob)
        return blob
    else:
        print("Invalid blob file please check")
        sys.exit()


# ----------------------------------------------------------------------------#
# Search the input file with a regex for the recovery key and parse it into   #
# the hash key, divide each group of digits by 11 convert to hex and swap the #
# bytes then concatenate all the bytes and calculate the sha256(key_bytes) to #
# get the hash key ready for stretching                                       #
# ----------------------------------------------------------------------------#
def get_recovery_key(filename):
    group = [None] * 8
    key = ""
    filedata = open(filename, "r", encoding="utf-16")
    temp = filedata.read()
    temp = temp.replace("\00", "")  # remove nulls if file is utf-16
    filedata.close()
    key_str = re.findall(r'(\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6})',
                         temp)

    if key_str:
        key_str = key_str[0].split("-")  # split into groups of 6
        for i in range(8):
            group[i] = int(key_str[i])
            mod = group[i] % 11
            if mod != 0:
                print("invalid key group: " + key_str[i])
                sys.exit()
            else:
                group[i] = group[i] // 11
                group[i] = format(group[i], "04x")         # convert to hex
                group[i] = group[i][2:4] + group[i][0:2]   # little endian swap
                key = key + group[i]

    else:
        print("could not find recovery key")
        sys.exit()

    print("Stretch  : " + key)
    key = bytes.fromhex(key)
    hashkey = sha256(key).digest()
    return hashkey


# --------------------------------------------------------------------------- #
# Get the VMK from a file. It accepts either just the VMK key                 #
# the VMK key with header or the responseparams Hex Stream from wireshark     #
# which is the VMK key with header with an additional 2 byte length header    #
# --------------------------------------------------------------------------- #
def get_vmk(filename):
    print("Reading VMK from file")
    filedata = open(filename, "r")
    blob = filedata.read()
    filedata.close()
    blob = blob.replace("\n", "")      # incase data is split on multiple lines
    blob = blob.replace(" ", "")       # strip spaces too

    # if data is responseparams from wireshark
    if blob[:4].lower() == "002c" and len(blob) == 92:
        print("Found wireshark responseparams, trimming first two bytes")
        blob = blob[4:]             # wireshark includes the param size header

    # if data is the bare VMK without header
    if len(blob) == 64:
        print("Found a bare VMK without header, adding a placeholder header")
        blob = "2c0000000100000003200000" + blob

    # if data is the bare VMK with header
    if blob[:4].lower() == "2c00" and len(blob) == 88:
        blob = bytes.fromhex(blob)
        tpmkey = parse_key(blob)
        return tpmkey
    else:
        print("Invalid VMK file please check")
        sys.exit()


# --------------------------------------------------------------------------- #
# Get the BEK key from a file.                                                #
# --------------------------------------------------------------------------- #
def get_BEK(filename):
    try:
        with open(filename, 'rb') as filedata:
            BEK_bin = filedata.read()

            uuid_bin = BEK_bin[16:32]
            uuid_str = str(uuid.UUID(bytes_le=uuid_bin))
            print("BEK key " + uuid_str)

            datum = BEK_bin[-44:]
            bek_key = parse_key(datum)

            return bek_key

    except Exception as e:
        return (False, f"Error reading BEK file: {e}")


# --------------------------------------------------------------------------- #
# Parse key datum and print the found key. returns the key.                   #
# Takes a key with header and checks the key type and prints the key and type #
# XTS 128-bit keys return 256 bits as XTS mode uses 2 keys                    #
# XTS 256-bit will return a 512 bit key                                       #
# --------------------------------------------------------------------------- #
def parse_key(datum):
    # size = datum[0:2]
    # role = datum[2:4]    # 0x0005 = AES-CCM VMK??
    # datatype = datum[4:8]
    method = datum[8:10]
    key = datum[12:]
    int_method = int.from_bytes(method, byteorder="little", signed=False)
    encryption_type = {
        0x8000: "AES-CBC 128-bit with Elephant Diffuser",
        0x8001: "AES-CBC 256-bit with Elephant Diffuser",
        0x8002: "AES-CBC 128-bit",
        0x8003: "AES-CBC 256-bit",
        0x8004: "AES-XTS 128-bit",
        0x8005: "AES-XTS 256-bit"
    }
    key_type = {
        0x0000: "Unknown (Not encrypted/External Key)",
        0x1000: "Stretch key (AES-CCM 128-bit)",
        0x1001: "Unknown (Stretch key)",
        0x2000: "TPMandPIN intermediate (AES-CCM 256-bit)",
        0x2001: "Unknown (AES-CCM 256-bit)",
        0x2002: "External key (AES-CCM 256-bit)",
        0x2003: "VMK (AES-CCM 256-bit)",
        0x2004: "PIN? (AES-CCM 256-bit)",
        0x2005: "hash256? (AES-CCM 256-bit)"
    }

    if int_method in encryption_type:
        print("This seems to be an FVEK type: " + encryption_type[int_method])
        print(key.hex())
        print()

    elif int_method in key_type:
        print("This seems to be an AES key type: " + key_type[int_method])
        print(key.hex())
        print()

    return key


# --------------------------------------------------------------------------- #
# Save the decrypted FVEK to a file for use with dislocker                    #
# Takes an FVEK key with header and the computer name from the dislocker log  #
# and saves the key in a format suitable for dislocker to $computer_name.fvek #
# --------------------------------------------------------------------------- #
def save_key(datum, computer_name, path):
    method = datum[8:10]
    key = datum[12:]
    print("Writing the following to key file: " + computer_name + ".fvek")
    keyfile_data = method + key + bytes(66 - len(method + key))
    print(keyfile_data.hex())
    while True:
        filename = os.path.join(path, computer_name + ".fvek")
        if os.path.isfile(filename):             # warn before overwriting file
            qm = QMessageBox()
            qm.setWindowTitle("File Exists!")
            qm.setText(f"File '{filename}' already exists. Overwrite?")
            qm.setStandardButtons(
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
            qm.setIcon(QMessageBox.Icon.Question)
            button = qm.exec()

            if button == QMessageBox.StandardButton.Yes:
                file = open(filename, "wb")
                file.write(keyfile_data)
                file.close()
                return filename
            if button == QMessageBox.StandardButton.No:
                print("key not written")
                return None
        else:
            file = open(filename, "wb")
            file.write(keyfile_data)
            file.close()
            return filename


# -----------------------------------------------------------------------------
# Redirect print to the text box
# -----------------------------------------------------------------------------
class OutputRedirector(QObject):
    """Redirects stdout/stderr to a PyQt6 text widget"""
    output_signal = pyqtSignal(str)

    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget
        self.output_signal.connect(self.append_text)

    def write(self, text):
        """Called when print() or sys.stdout.write() is used"""
        if text.strip():  # Only emit non-empty strings
            self.output_signal.emit(text)

    def flush(self):
        """Required for file-like object compatibility"""
        pass

    def append_text(self, text):
        """Append text to the widget (runs in GUI thread)"""
        self.text_widget.append(text)
        # Auto-scroll to bottom
        self.text_widget.verticalScrollBar().setValue(
            self.text_widget.verticalScrollBar().maximum()
        )


# -----------------------------------------------------------------------------
# DECRYPTION ORCHESTRATOR
# -----------------------------------------------------------------------------
def decrypt_orchestrator(args):
    """
    Main logic flow, replacing the script's original main execution block.
    """

#    for arg in args:
    print(args)

    logfile = get_logfile_content(args['logfile'])
    if logfile is None:
        return (False, "Failed to read log file.")

    mode = args['mode']
    print(f"--- Decryption Attempt Started ---\nMode Selected: {mode}\nLog File: {args['logfile']}\n")

    try:
        # get FVEK using VMK + log [+ BEK] (TPM or TPMandKey)
        if mode == "TPM Only" or mode == "TPM and KEY (BEK)":
            if not args['vmk']:
                print("This mode requires the sniffed VMK file.")
                return (False)
            if mode == "TPM and KEY (BEK)" and not args['bek']:
                print("This mode requires the BEK file.")
                return (False)

            computer_name = get_name(logfile)
            print(f"Computer : {computer_name}\n")

            if mode == "TPM and KEY (BEK)":
                print("Decrypting FVEK using keys from TPM and StartupKey")
                tpmkey = get_vmk(args['vmk'])
                bekkey = get_BEK(args['bek'])
                xorkey = xor_keys(tpmkey, bekkey)
        #        print("TPM key  : " + tpmkey.hex())
        #        print("BEK key  : " + bekkey.hex())
                print("XOR key  : " + xorkey.hex())
                int_key = get_enc_key(logfile, "External")
                print("Decrypted VMK")
                int_key_dec = decrypt(int_key, xorkey)
                VMK = parse_key(int_key_dec)
            else:
                print("Decrypting FVEK using VMK from TPM")
                VMK = get_vmk(args['vmk'])

            print("VMK      : " + VMK.hex())

            FVEK_enc = get_enc_fvek(logfile)
            print("Decrypting FVEK")
            FVEK_dec = decrypt(FVEK_enc, VMK)
            FVEK_bytes = parse_key(FVEK_dec)

            FVEK_output = save_key(FVEK_dec, computer_name, args['output_dir'])

            print("Getting reverse recovery key")
            recovery_output = save_recovery(logfile, VMK, args['output_dir'])

            if FVEK_output is not None and recovery_output is not None:
                print("\n\n*** SUCCESS ***")
                print(f"Decrypted VMK Used: {args['vmk']}")
                print(f"Decrypted FVEK: {FVEK_bytes.hex()}")
                print(f"FVEK saved to: {FVEK_output}")
                print(f"Recovery key saved to: {recovery_output}")
                return (True)
            else:
                print("Error decrypting FVEK")
                return (False)

        # get FVEK using password (Password only)
        elif mode == "PIN/Password Only":
            if not args['pin']:
                return (False, "Password Only mode requires the PIN/Password.")

            # get the computer name for the saved FVEK filename
            computer_name = get_name(logfile)
            print(f"Computer : {computer_name}\n")

            print("Decrypting FVEK using password")
            pass_salt = get_salt(logfile, "Password")
            VMK_enc = get_enc_key(logfile, "Password")
            FVEK_enc = get_enc_fvek(logfile)

            # get hash key and stretched key
            hash_key = hash_pin(args['pin'])
            stretched_key = stretch_key(hash_key, pass_salt)
            print("hashkey  : " + hash_key.hex())
            print("stretched: " + stretched_key.hex())

            print("\nDecrypted VMK")
            VMK_dec = decrypt(VMK_enc, stretched_key)
            VMK = parse_key(VMK_dec)

            # get the key from the decrypted VMK and decrypt the FVEK
            FVEK_dec = decrypt(FVEK_enc, VMK)
            print("\nDecrypted FVEK")
            FVEK_bytes = parse_key(FVEK_dec)

            FVEK_output = save_key(FVEK_dec, computer_name, args['output_dir'])

            print("\nGetting reverse recovery key")
            recovery_output = save_recovery(logfile, VMK, args['output_dir'])

            if FVEK_output is not None and recovery_output is not None:
                print("\n\n*** SUCCESS ***")
                print(f"PIN/Password Used: {args['pin']}")
                print(f"Decrypted VMK: {VMK.hex()}")
                print(f"Decrypted FVEK: {FVEK_bytes.hex()}")
                print(f"FVEK saved to: {FVEK_output}")
                print(f"Recovery key saved to: {recovery_output}")
                return (True)
            else:
                print("Error decrypting FVEK")
                return (False)

        # get FVEK using blob + pin + log [+ BEK] (TPMandPIN or TPMandPINandKEY)
        elif mode == "TPM and PIN" or mode == "TPM and PIN and KEY (BEK)":
            if not args['pin'] or not args['tpm_blob']:
                print("TPM and PIN mode requires both the PIN/Password and the TPM Blob.")
                return (False)
            if mode == "TPM and PIN and KEY (BEK)" and not args['bek']:
                print("TPM and PIN and KEY mode requires the PIN/Password, the TPM Blob and the BEK.")
                return (False)

            computer_name = get_name(logfile)
            print(f"Computer : {computer_name}\n")

            if mode == "TPM and PIN and KEY (BEK)":
                print("Decrypting FVEK using PIN, sniffed TPMandPIN blob and BEK")
                VMK_enc = get_enc_key(logfile, "External")
            else:
                print("Decrypting FVEK using PIN and sniffed TPMandPIN blob")
                VMK_enc = get_enc_key(logfile, "PIN")

            blob_bytes = get_blob(args['tpm_blob'])

            # get keys and salt from log file
            FVEK_enc = get_enc_fvek(logfile)
            pin_salt = get_salt(logfile, "PIN")

            print("TPM blob : " + blob_bytes.hex())
            print("FVEK_enc : " + FVEK_enc.hex())
            print("VMK_enc  : " + VMK_enc.hex())
            print("PIN Salt : " + pin_salt.hex())
            print("PIN      : " + args['pin'])

            # get hash key and stretched key
            hash_key = hash_pin(args['pin'])
            stretched_key = stretch_key(hash_key, pin_salt)
            print("hashkey  : " + hash_key.hex())
            print("stretched: " + stretched_key.hex())

            # decrypt the blob
            blob_dec = decrypt(blob_bytes, stretched_key)
            print("\nDecrypted blob")
            blob_key = parse_key(blob_dec)

            if mode == "TPM and PIN and KEY (BEK)":
                print("XOR'ing StartupKey with blob key before decryption")
                bekkey = get_BEK(args['bek'])
                xorkey = xor_keys(bekkey, blob_key)
                print("XOR key  : " + xorkey.hex())
                blob_key = xorkey

            # get the key from the decrypted blob and decrypt the VMK
            VMK_dec = decrypt(VMK_enc, blob_key)
            print("\nDecrypted VMK")
            VMK = parse_key(VMK_dec)

            # get the key from the decrypted VMK and decrypt the FVEK
            FVEK_dec = decrypt(FVEK_enc, VMK)
            print("\nDecrypted FVEK")
            FVEK_bytes = parse_key(FVEK_dec)

            # save the FVEK to a file $computer_name.fvek
            FVEK_output = save_key(FVEK_dec, computer_name, args['output_dir'])

            # get the reverse recovery key and decrypt with the VMK
            recovery_output = save_recovery(logfile, VMK, args['output_dir'])

            if FVEK_output is not None and recovery_output is not None:
                print("\n*** SUCCESS ***\n")
                print(f"PIN Used: {args['pin']}")
                print(f"TPM Blob Used: {args['tpm_blob']}")
                print(f"Decrypted VMK: {VMK.hex()}")
                print(f"Decrypted FVEK: {FVEK_bytes.hex()}")
                print(f"FVEK saved to: {FVEK_output}")
                print(f"Recovery key saved to: {recovery_output}")
                return (True)
            else:
                print("Error decrypting FVEK")
                return (False)

        # get FVEK using external key (StartupKey or ExternalKey)
        elif mode == "BEK Only":
            if not args['bek']:
                return (False, f"{mode} requires the BEK file path.")

            computer_name = get_name(logfile)
            print(f"Computer : {computer_name}")

            print("Decrypting FVEK using external key")
            bekkey = get_BEK(args['bek'])
            int_key = get_enc_key(logfile, "External")
            FVEK_enc = get_enc_fvek(logfile)

            print("\nDecrypted VMK")
            int_key_dec = decrypt(int_key, bekkey)
            VMK = parse_key(int_key_dec)

            FVEK_dec = decrypt(FVEK_enc, VMK)
            FVEK_bytes = parse_key(FVEK_dec)

            # save the FVEK to a file $computer_name.fvek
            FVEK_output = save_key(FVEK_bytes, computer_name, args['output_dir'])

            # get the reverse recovery key and decrypt with the VMK
            recovery_output = save_recovery(logfile, VMK, args['output_dir'])

            if FVEK_output is not None and recovery_output is not None:
                print("\n*** SUCCESS ***\n")
                print(f"BEK File Used: {args['bek']}")
                print(f"Decrypted VMK (from BEK): {VMK.hex()}")
                print(f"Decrypted FVEK: {FVEK_bytes.hex()}")
                print(f"FVEK saved to: {FVEK_output}")
                print(f"Recovery key saved to: {recovery_output}")
                return (True)
            else:
                print("Error decrypting FVEK")
                return (False)

        # get FVEK using recovery key
        elif mode == "Recovery Key":
            if not args['recovery']:
                print("Recovery Key requires the Recovery file path.")
                return (False)

            # get the computer name for the saved FVEK filename
            computer_name = get_name(logfile)
            print("Computer : " + computer_name)

            print("Decrypting FVEK using Recovery key")
            # get the recovery key, salt, FVEK
            VMK_enc = get_enc_key(logfile, "Recovery")
            FVEK_enc = get_enc_fvek(logfile)
            salt = get_salt(logfile, "Recovery")

            print("FVEK_enc : " + FVEK_enc.hex())
            print("VMK_enc  : " + VMK_enc.hex())
            print("Salt     : " + salt.hex())

            # get the Recovery hash and stretched keys
            hash_key = get_recovery_key(args['recovery'])
            stretched_key = stretch_key(hash_key, salt)
            print("hashkey  : " + hash_key.hex())
            print("stretched: " + stretched_key.hex())

            # get the key from the decrypted blob and decrypt the VMK
            VMK_dec = decrypt(VMK_enc, stretched_key)
            print("\nDecrypted VMK")
            VMK = parse_key(VMK_dec)

            # get the key from the decrypted VMK and decrypt the FVEK
            FVEK_dec = decrypt(FVEK_enc, VMK)
            print("\nDecrypted FVEK")
            FVEK_bytes = parse_key(FVEK_dec)

            # save the FVEK to a file $computer_name.fvek
            FVEK_output = save_key(FVEK_bytes, computer_name, args['output_dir'])

            # get the reverse recovery key and decrypt with the VMK
            recovery_output = save_recovery(logfile, VMK, args['output_dir'])

            if FVEK_output is not None and recovery_output is not None:
                print("\n*** SUCCESS ***\n")
                print(f"Recovery File Used: {args['recovery']}")
                print(f"Decrypted VMK: {VMK.hex()}\n")
                print(f"Decrypted FVEK: {FVEK_bytes.hex()}")
                print(f"FVEK saved to: {FVEK_output}")
                print(f"Recovery key saved to: {recovery_output}")
                return (True)
            else:
                print("Error decrypting FVEK")
                return (False)

        else:
            return (False, f"Unsupported mode: {mode}")

    except Exception as e:
        print(traceback.format_exc())
        return (False, f"Decryption routine failed: {type(e).__name__}: {e}")


# -----------------------------------------------------------------------------
# PYQT GUI APPLICATION
# -----------------------------------------------------------------------------
class SPITkeyGUI(QWidget):
    """
    PyQt6 GUI for the SPITkey BitLocker VMK Decryptor Tool.
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SPITkey BitLocker VMK Decryptor - unregistered")
        self.setGeometry(100, 100, 1200, 900)
        self.setStyleSheet(self.get_style_sheet())
        self.init_ui()

    def get_style_sheet(self):
        """Returns a custom stylesheet for a modern, dark theme."""
        return """
            QWidget {
                background-color: #2c3e50;
                color: #ecf0f1;
                font-family: "Comic Sans MS", "Comic Sans", cursive;
                font-size: 10pt;
            }
            QGroupBox {
                font-size: 11pt;
                font-weight: bold;
                border: 2px solid #3498db;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 20px;
                padding-bottom: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 10px;
                color: #3498db;
            }
            QLineEdit, QComboBox, QTextEdit {
                background-color: #34495e;
                border: 1px solid #7f8c8d;
                border-radius: 5px;
                padding: 6px;
                color: #ecf0f1;
            }
            QPushButton {
                background-color: #3498db;
                color: white;
                font-family: "Comic Sans MS", "Comic Sans", cursive;
                border: none;
                border-radius: 5px;
                padding: 10px 20px;
                font-weight: bold;
                font-size: 10pt;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QLabel {
                font-family: "Comic Sans MS", "Comic Sans", cursive;
                padding-left: 5px;
            }
        """

    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setSpacing(15)

        # ---------------------------------------------------------------------
        # 1. Input Group (Required Log File)
        # ---------------------------------------------------------------------
        input_group = QGroupBox("Required Input")
        input_layout = QVBoxLayout()

        # Log File Selector
        input_layout.addWidget(QLabel("Dislocker Log File (`-vvvv` output):"))
        self.log_file_input = QLineEdit()
        self.log_file_input.setPlaceholderText("Path to log file (e.g., dislocker.log)")
        log_file_browse = QPushButton("Browse...")
        log_file_browse.clicked.connect(lambda: self.browse_file(self.log_file_input, "Select Dislocker Log File", "(*.log);;All Files (*)"))

        h_layout = QHBoxLayout()
        h_layout.addWidget(self.log_file_input)
        h_layout.addWidget(log_file_browse)
        input_layout.addLayout(h_layout)

        # Mode Selection
        input_layout.addWidget(QLabel("Decryption Mode:"))
        self.mode_selector = QComboBox()
        self.mode_selector.addItems([
            "TPM Only",
            "TPM and PIN",
            "PIN/Password Only",
            "BEK Only",
            "Recovery Key",
            "TPM and KEY (BEK)",
            "TPM and PIN and KEY (BEK)"
        ])
        self.mode_selector.currentIndexChanged.connect(self.update_optional_inputs)
        input_layout.addWidget(self.mode_selector)

        input_group.setLayout(input_layout)
        main_layout.addWidget(input_group)

        # ---------------------------------------------------------------------
        # 2. Optional Inputs Group
        # ---------------------------------------------------------------------
        self.optional_group = QGroupBox("Mode-Specific Inputs")
        self.optional_layout = QVBoxLayout()

        # PIN / Password
        self.pin_label = QLabel("PIN or Password:")
        self.pin_input = QLineEdit()
        self.pin_input.setPlaceholderText("BitLocker PIN or User Password (if required by mode)")
        self.optional_layout.addWidget(self.pin_label)
        self.optional_layout.addWidget(self.pin_input)

        # Recovery key
        self.recovery_label = QLabel("Recovery key")
        self.recovery_input = QLineEdit()
        self.recovery_input.setPlaceholderText("Path to recovery key file")
        self.recovery_browse_btn = QPushButton("Browse...")
        self.recovery_browse_btn.clicked.connect(lambda: self.browse_file(self.recovery_input, "Select recovery Key File", "Recovery Files (*.txt);;All Files (*)"))

        # Create a container widget for BEK input row
        self.recovery_container = QWidget()
        recovery_row_layout = QHBoxLayout()
        recovery_row_layout.setContentsMargins(0, 0, 0, 0)
        recovery_row_layout.addWidget(self.recovery_input)
        recovery_row_layout.addWidget(self.recovery_browse_btn)
        self.recovery_container.setLayout(recovery_row_layout)

        self.optional_layout.addWidget(self.recovery_label)
        self.optional_layout.addWidget(self.recovery_container)

        # Recovery pin (just for completeness)
#        self.recovery_pin_label = QLabel("Recovery Pin")
#        self.recovery_pin_input = QLineEdit()
#        self.recovery_pin_input.setPlaceholderText("xxxxxx-xxxxxx-xxxxxx-xxxxxx-xxxxxx-xxxxxx-xxxxxx-xxxxxx")
#        self.optional_layout.addWidget(self.recovery_pin_label)
#        self.optional_layout.addWidget(self.recovery_pin_input)

        # BEK File - Create container widget for proper visibility control
        self.bek_label = QLabel("BEK File (Key File):")
        self.bek_input = QLineEdit()
        self.bek_input.setPlaceholderText("Path to .bek file")
        self.bek_browse_btn = QPushButton("Browse...")
        self.bek_browse_btn.clicked.connect(lambda: self.browse_file(self.bek_input, "Select .BEK Key File", "BEK Files (*.bek);;All Files (*)"))

        # Create a container widget for BEK input row
        self.bek_container = QWidget()
        bek_row_layout = QHBoxLayout()
        bek_row_layout.setContentsMargins(0, 0, 0, 0)
        bek_row_layout.addWidget(self.bek_input)
        bek_row_layout.addWidget(self.bek_browse_btn)
        self.bek_container.setLayout(bek_row_layout)

        self.optional_layout.addWidget(self.bek_label)
        self.optional_layout.addWidget(self.bek_container)

        # VMK File - Create container widget for proper visibility control
        self.tpm_vmk_label = QLabel("VMK/Blob File (Key File):")
        self.tpm_vmk_input = QLineEdit()
        self.tpm_vmk_input.setPlaceholderText("Path to vmk or blob file")
        self.tpm_vmk_browse_btn = QPushButton("Browse...")
        self.tpm_vmk_browse_btn.clicked.connect(lambda: self.browse_file(self.tpm_vmk_input, "Select .VMK/Blob Key File", "VMK Files (*.vmk *.blob);;All Files (*)"))

        # VMK/TPM Blob
        self.tpm_vmk_container = QWidget()
        vmk_row_layout = QHBoxLayout()
        vmk_row_layout.setContentsMargins(0, 0, 0, 0)
        vmk_row_layout.addWidget(self.tpm_vmk_input)
        vmk_row_layout.addWidget(self.tpm_vmk_browse_btn)
        self.tpm_vmk_container.setLayout(vmk_row_layout)

        self.optional_layout.addWidget(self.tpm_vmk_label)
        self.optional_layout.addWidget(self.tpm_vmk_container)

        self.optional_group.setLayout(self.optional_layout)
        main_layout.addWidget(self.optional_group)

        # ---------------------------------------------------------------------
        # 3. Output File Selection
        # ---------------------------------------------------------------------
        output_group = QGroupBox("Output Settings")
        output_layout = QVBoxLayout()

        output_layout.addWidget(QLabel("Output File (where to save VMK/FVEK):"))
        self.output_dir_input = QLineEdit()
        self.output_dir_input.setPlaceholderText("Path to save decrypted keys (e.g., decrypted_keys.txt)")
        output_dir_browse = QPushButton("Browse...")
        output_dir_browse.clicked.connect(lambda: self.browse_save_dir(self.output_dir_input, "Save Output Folder", QFileDialog.Option.ShowDirsOnly))

        h_layout_output = QHBoxLayout()
        h_layout_output.addWidget(self.output_dir_input)
        h_layout_output.addWidget(output_dir_browse)
        output_layout.addLayout(h_layout_output)

        output_group.setLayout(output_layout)
        main_layout.addWidget(output_group)

        # Initial update to set visibility based on default mode
        self.update_optional_inputs()

        # ---------------------------------------------------------------------
        # 4. Decryption Button and Output
        # ---------------------------------------------------------------------
        decrypt_button = QPushButton("Run Decryption and Get FVEK")
        decrypt_button.clicked.connect(self.start_decryption)
        main_layout.addWidget(decrypt_button)

        main_layout.addWidget(QLabel("Output/Results:"))
        self.output_text = AnimatedTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setPlaceholderText("Decryption results will appear here.")
        # Set up output redirection
        self.output_redirector = OutputRedirector(self.output_text)
        sys.stdout = self.output_redirector
        sys.stderr = self.output_redirector  # Also redirect errors

        # Store original stdout/stderr if you need to restore later
        self.original_stdout = sys.__stdout__
        self.original_stderr = sys.__stderr__

        main_layout.addWidget(self.output_text)
        self.setLayout(main_layout)

        # ---------------------------------------------------------------------
        # 5. Setup audio player (requires an audio file)
        # Note: You'll need to provide your own audio file
        self.player = QMediaPlayer()
        self.audio_output = QAudioOutput()
        self.player.setAudioOutput(self.audio_output)
        
        # To use this, place an audio file in the same directory
        # Uncomment and modify the path below:
        self.player.setSource(QUrl.fromLocalFile("zeroplex.mp3"))
        self.audio_output.setVolume(0.5)
        self.player.play()

    def closeEvent(self, event):
        """Restore stdout/stderr when window closes"""
        sys.stdout = self.original_stdout
        sys.stderr = self.original_stderr
        event.accept()

    # Optional: Method to restore normal print behavior
    def restore_stdout(self):
        """Restore original stdout/stderr"""
        sys.stdout = self.original_stdout
        sys.stderr = self.original_stderr

    # Optional: Method to clear the output
    def clear_output(self):
        """Clear the output text widget"""
        self.output_text.clear()

    def browse_file(self, line_edit, title, filter_str):
        """Opens a file dialog and sets the selected file path to the QLineEdit."""
        file_path, _ = QFileDialog.getOpenFileName(self, title, "", filter_str)
        if file_path:
            line_edit.setText(file_path)

    def browse_save_file(self, line_edit, title, filter_str):
        """Opens a save file dialog and sets the selected file path to the QLineEdit."""
        file_path, _ = QFileDialog.getSaveFileName(self, title, "", filter_str)
        if file_path:
            line_edit.setText(file_path)

    def browse_save_dir(self, line_edit, title, filter_str):
        """Opens a save file dialog and sets the selected dir path to the QLineEdit."""
        output_path = QFileDialog.getExistingDirectory(self, title, "", filter_str)
        if output_path:
            line_edit.setText(output_path)

    def update_optional_inputs(self):
        """
        Dynamically shows/hides input fields based on the selected decryption mode.
        """
        mode = self.mode_selector.currentText()

        # Determine which inputs are required based on mode
        is_pin_req = ("PIN" in mode) or (mode == "PIN/Password Only")
        is_bek_req = ("KEY" in mode) or (mode == "BEK Only")
        is_tpm_blob_req = ("TPM and PIN" in mode)
        is_vmk_req = (mode == "TPM Only") or (mode == "TPM and KEY (BEK)")
        is_recovery_req = (mode == "Recovery Key")

        # 1. PIN / Password visibility
        self.pin_label.setVisible(is_pin_req)
        self.pin_input.setVisible(is_pin_req)

        # 2. BEK File visibility - now using container widget
        self.bek_label.setVisible(is_bek_req)
        self.bek_container.setVisible(is_bek_req)

        # 3. VMK / TPM Blob visibility and label update
        if is_vmk_req:
            self.tpm_vmk_label.setText("VMK file from TPM sniff:")
            self.tpm_vmk_input.setPlaceholderText("Path to VMK file from TPM sniff")
        elif is_tpm_blob_req:
            self.tpm_vmk_label.setText("TPM Blob file from TPM sniff:")
            self.tpm_vmk_input.setPlaceholderText("Path to Blob file from TPM sniff")
        else:
            self.tpm_vmk_label.setText("VMK/TPM file:")
            self.tpm_vmk_input.setPlaceholderText("Path to VMK or TPM blob file")

        self.tpm_vmk_label.setVisible(is_tpm_blob_req or is_vmk_req)
        self.tpm_vmk_container.setVisible(is_tpm_blob_req or is_vmk_req)

        # 4 Recovery key
        self.recovery_label.setVisible(is_recovery_req)
        self.recovery_container.setVisible(is_recovery_req)

        # Clean up input fields when switching modes
        if not is_pin_req:
            self.pin_input.clear()
        if not is_bek_req:
            self.bek_input.clear()
        if not (is_tpm_blob_req or is_vmk_req):
            self.tpm_vmk_input.clear()
        if not (is_recovery_req):
            self.recovery_input.clear()

    def start_decryption(self):
        """
        Gathers all input and calls the core decryption logic.
        """
        # TODO use mode rather than strings to determine variables
        # 1. Gather all inputs
        args = {
            'mode': self.mode_selector.currentText(),
            'logfile': self.log_file_input.text().strip(),
            'pin': self.pin_input.text().strip() or None,
            'bek': self.bek_input.text().strip() or None,
            'recovery': self.recovery_input.text().strip() or None,
            # Note: Checking the label text to differentiate TPM blob from VMK sniff
            'tpm_blob': self.tpm_vmk_input.text().strip() if "Blob" in self.tpm_vmk_label.text() else None,
            'vmk': self.tpm_vmk_input.text().strip() if "VMK" in self.tpm_vmk_label.text() else None,
            'output_dir': self.output_dir_input.text().strip() or None,
        }

        # 2. Basic validation
        mode = self.mode_selector.currentText()
        if not args['logfile']:
            QMessageBox.warning(self, "Missing Input", "Please provide the Dislocker Log File path.")
            return
        if ("PIN" in mode) and not args['pin']:
            QMessageBox.warning(self, "Missing Input", "Please provide the PIN/password.")
            return
        if mode == "TPM and PIN" and not args['tpm_blob']:
            QMessageBox.warning(self, "Missing Input", "Please provide the Blob file.")
            return
        if mode == "TPM Only" and not args['vmk']:
            QMessageBox.warning(self, "Missing Input", "Please provide the VMK file.")
            return
        if mode == "TPM and KEY (BEK)" and not args['vmk']:
            QMessageBox.warning(self, "Missing Input", "Please provide the VMK file.")
            return
        if ("BEK" in mode) and not args['bek']:
            QMessageBox.warning(self, "Missing Input", "Please provide the BEK file.")
            return
        if not args['output_dir']:
            QMessageBox.warning(self, "Missing Input", "Please provide the Dislocker save File path.")
            return

        # 3. Run the core logic (using the orchestrator)
        # Use a temporary dictionary for the key names to avoid confusion
        decryption_args = {k: v for k, v in args.items() if v is not None}

        try:
            # Call the implemented orchestrator function
            success = decrypt_orchestrator(decryption_args)

            if success:
                QMessageBox.information(self, "Success", "Decryption completed. Check the output box for VMK/FVEK.")
            else:
                QMessageBox.critical(self, "Failure", "Decryption failed. Please check inputs and log data.")

        except Exception as e:
            error_msg = f"An unhandled error occurred during decryption: {type(e).__name__}: {e}"
            self.output_text.append(error_msg)
            QMessageBox.critical(self, "Critical Error", error_msg)


def handle_exception(exc_type, exc_value, exc_traceback):
    """ handle all exceptions """
    # KeyboardInterrupt is a special case.
    # We don't raise the error dialog when it occurs.
    if issubclass(exc_type, KeyboardInterrupt):
        if app:
            app.quit()
        return

    filename, line, dummy, dummy = traceback.extract_tb(exc_traceback).pop()
    filename = os.path.basename(filename)
    error = "%s: %s" % (exc_type.__name__, exc_value)

    QMessageBox.critical(None, "Error",
        "<html>A critical error has occured.<br/> "
        + "<b>%s</b><br/><br/>" % error
        + "It occurred at <b>line %d</b> of file <b>%s</b>.<br/>" % (line, filename)
        + "</html>")

    print("Closed due to an error. This is the full error report:")
    print()
    print("".join(traceback.format_exception(exc_type, exc_value, exc_traceback)))
    sys.exit(1)


# ============================================================================
# stupid nonsense
# ============================================================================

class Star:
    def __init__(self, width, height):
        self.reset(width, height)
        self.z = random.uniform(0, width)
    
    def reset(self, width, height):
        self.x = random.uniform(-width, width)
        self.y = random.uniform(-height, height)
        self.z = random.uniform(0, width)
    
    def update(self, speed, width, height):
        self.z -= speed
        if self.z <= 0:
            self.reset(width, height)


class AnimatedTextEdit(QTextEdit):
    def __init__(self):
        super().__init__()
        self.stars = [Star(800, 600) for _ in range(200)]
        self.angle = 0
        self.key_rotation_y = 0
        self.key_rotation_x = 0
        
        # Make text edit transparent to show background
        self.setStyleSheet("""
            QTextEdit {
                background-color: transparent;
                color: #00ff00;
                font-family: Courier;
                font-size: 12pt;
                border: none;
            }
        """)
        
        # Set viewport to transparent
        self.viewport().setAutoFillBackground(False)
        
        # Timer for animation
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_animation)
        self.timer.start(16)  # ~60 FPS
    
    def update_animation(self):
        self.angle += 0.02
        self.key_rotation_y += 2
        self.key_rotation_x += 0.5
        self.viewport().update()  # Update the viewport to trigger repaint
    
    def draw_starfield(self, painter, width, height):
        painter.setPen(Qt.PenStyle.NoPen)
        
        for star in self.stars:
            star.update(5, width, height)
            
            # Project 3D to 2D
            k = 128.0 / star.z
            px = star.x * k + width / 2
            py = star.y * k + height / 2
            
            if 0 <= px < width and 0 <= py < height:
                size = (1 - star.z / width) * 3
                brightness = int((1 - star.z / width) * 255)
                color = QColor(brightness, brightness, brightness)
                painter.setBrush(QBrush(color))
                painter.drawEllipse(QPointF(px, py), size, size)
    
    def draw_3d_key(self, painter, cx, cy, scale):
        painter.save()
        painter.translate(cx, cy)
        
        # Simple 3D rotation matrices
        angle_x = math.radians(self.key_rotation_x)
        angle_y = math.radians(self.key_rotation_y)
        
        # Define key vertices (simplified key shape)
        vertices = [
            # Key head (circular part)
            *[(math.cos(a) * 30, math.sin(a) * 30, 0) 
              for a in [i * math.pi / 8 for i in range(16)]],
            # Key shaft
            (0, 30, 0), (0, 80, 0), (5, 80, 0), (5, 30, 0),
            # Key teeth
            (5, 70, 0), (15, 70, 0), (15, 75, 0), (5, 75, 0),
            (5, 80, 0), (15, 80, 0), (15, 85, 0), (5, 85, 0),
        ]
        
        # Apply rotation
        rotated = []
        for x, y, z in vertices:
            # Rotate around Y axis
            x1 = x * math.cos(angle_y) - z * math.sin(angle_y)
            z1 = x * math.sin(angle_y) + z * math.cos(angle_y)
            
            # Rotate around X axis
            y1 = y * math.cos(angle_x) - z1 * math.sin(angle_x)
            z2 = y * math.sin(angle_x) + z1 * math.cos(angle_x)
            
            rotated.append((x1, y1, z2))
        
        # Draw key with depth
        gradient_colors = [
            QColor(255, 215, 0, 128),  # Gold with transparency
            QColor(255, 193, 37, 128),
            QColor(218, 165, 32, 128)
        ]
        
        # Sort by depth for simple painter's algorithm
        avg_z = sum(z for x, y, z in rotated) / len(rotated)
        color_idx = int((avg_z + 50) / 100 * 2) % 3
        
        painter.setPen(QPen(QColor(200, 150, 0, 128), 2))
        painter.setBrush(QBrush(gradient_colors[color_idx]))
        
        # Draw key head circle
        path = QPainterPath()
        for i in range(16):
            x, y, _ = rotated[i]
            if i == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)
        path.closeSubpath()
        painter.drawPath(path)
        
        # Draw key shaft
        shaft = rotated[16:20]
        path = QPainterPath()
        path.moveTo(shaft[0][0], shaft[0][1])
        for x, y, _ in shaft[1:]:
            path.lineTo(x, y)
        path.closeSubpath()
        painter.drawPath(path)
        
        # Draw teeth
        teeth1 = rotated[20:24]
        path = QPainterPath()
        path.moveTo(teeth1[0][0], teeth1[0][1])
        for x, y, _ in teeth1[1:]:
            path.lineTo(x, y)
        path.closeSubpath()
        painter.drawPath(path)
        
        teeth2 = rotated[24:28]
        path = QPainterPath()
        path.moveTo(teeth2[0][0], teeth2[0][1])
        for x, y, _ in teeth2[1:]:
            path.lineTo(x, y)
        path.closeSubpath()
        painter.drawPath(path)
        
        painter.restore()
    
    def paintEvent(self, event):
        # Create painter for the viewport
        painter = QPainter(self.viewport())
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        width = self.viewport().width()
        height = self.viewport().height()
        
        # Fill background
        painter.fillRect(0, 0, width, height, QColor(0, 0, 0))
        
        # Draw starfield
        self.draw_starfield(painter, width, height)
        
        # Draw rotating 3D key in center
        self.draw_3d_key(painter, width // 2, height // 2, 1.0)
        
        painter.end()
        
        # Call parent paintEvent to draw the text on top
        super().paintEvent(event)


if __name__ == '__main__':
    # Initialize the main PyQt application
    app = QApplication(sys.argv)

    # install handler for exceptions
    sys.excepthook = handle_exception

    # Create and show the main window
    ex = SPITkeyGUI()
    ex.show()

    # Start the application event loop
    sys.exit(app.exec())
