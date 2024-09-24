# --------------------------------------------------------------------------- #
#                 ▒█▀▀▀█ ▒█▀▀█ ▀█▀ ▀▀█▀▀ █░█ █▀▀ █░░█                         #
#                 ░▀▀▀▄▄ ▒█▄▄█ ▒█░ ░▒█░░ █▀▄ █▀▀ █▄▄█                         #
#                 ▒█▄▄▄█ ▒█░░░ ▄█▄ ░▒█░░ ▀░▀ ▀▀▀ ▄▄▄█                         #
#                                                                             #
# Decrypt bitlocker FVEK for a drive encrypted in the following modes         #
# All methods require the output of dislocker -vvvv /dev/$bitlockerpartition  #
# As well as this:                                                            #
# KEY only requires:                                                          #
#   The BEK file                                                              #
# TPM only requires:                                                          #
#   The VMK sniffed from the TPM                                              #
# TPMandPIN requires:                                                         #
#   The PIN and the blob of data from the TPM unseal command                  #
# TPMandKEY requires:                                                         #
#   The BEK file and the Key from the TPM unseal command                      #
# TPMandPINandKEY requires:                                                   #
#   The BEK file, The PIN and the blob of data from the TPM unseal command    #
# Recovery requires:                                                          #
#   The Recovery key file                                                     #
#                                                                             #
# Usage:                                                                      #
# spitkey.py -l $LOG [-p $PIN -t $TPMblob] [-k $VMK] [-r $RECOVERY] [-b $BEK] #
#                                                                             #
# If it doesnt work for you send complaints to @en4rab                        #
# --------------------------------------------------------------------------- #
# TODO: *check file path escaping as its behaving oddly with \ and \b in path #
#       *improve mode detection and calling decrypt method                    #
#       *Validate provided credentials against the logfile so make sure the   #
#         creds match what is required to decrypt the protector               #
# --------------------------------------------------------------------------- #

import uuid
import argparse
import os
import re
import sys
from Crypto.Cipher import AES
from hashlib import sha256


# --------------------------------------------------------------------------- #
# Parse upto 17 lines after offset to extract the Nonce, MAC and Payload      #
# stops looking when it reaches end that datum                                #
# --------------------------------------------------------------------------- #
def get_enc_payload(logfile, offset):
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

    if args.verbose is True:
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
        "External": "0x2002",
        "PIN": "0x2004",
        "Recovery": "0x1000"
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
        "PIN": "0x2004",
        "Recovery": "0x1000"
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
def save_recovery(logfile, VMK):
    # get the reverse recovery key and decrypt with the VMK
    REV_rec_enc = get_rev_key(logfile, "Recovery")
    REV_dec = decrypt(REV_rec_enc, VMK)
    rec_GUID = get_rec_GUID(logfile)
    print("\nRecovery key GUID")
    print(rec_GUID)
    print("Decrypted reverse recovery key")
    REV_key = parse_key(REV_dec)
    rec_key = enc_rec_key(REV_key)

    # save the recovery key to a file $GUID.recovery
    path = os.path.dirname(args.logfile)
    path = os.path.join(path, rec_GUID)

    print("Writing the following to recovery key file: " + path + ".recovery")
    print(rec_key)
    while True:
        filename = path + ".recovery"
        if os.path.isfile(filename):             # warn before overwriting file
            overwrite = input(
                "\nFile '"
                + filename
                + "' already exists. Overwrite? Y = yes, N = no\n"
                )
            if overwrite.lower() == "y":
                file = open(filename, "w")
                file.write(rec_key)
                file.close()
                break
            if overwrite.lower() == "n":
                print("recovery key not written")
                break
        else:
            file = open(filename, "w")
            file.write(rec_key)
            file.close()
            break


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
# get the salt needed to stretch the PIN hash or the recovery hash from the   #
# logfile salt_type should be "PIN" or "Recovery"                             #
# --------------------------------------------------------------------------- #
def get_salt(logfile, salt_type):
    salt_alg = {
        "PIN": "0x2004",
        "Recovery": "0x1000"
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
def user_key(password):
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
def decrypt(data, key):
    nonce = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]
    aes = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=16)
    data_dec = aes.decrypt_and_verify(ciphertext, tag)
    if args.verbose is True:
        print("Key:       " + key.hex())
        print("nonce:     " + nonce.hex())
        print("MAC:       " + tag.hex())
        print("Encrypted: " + ciphertext.hex())
        print("Decrypted: " + data_dec.hex())
        print("")
    return data_dec


# --------------------------------------------------------------------------- #
# Get the TPM blob from a file. It accepts either just the blob data          #
# or data with header in the file (responseparams in wireshark)               #
# TODO: add some checks incase someone adds entire TPM packet                 #
# --------------------------------------------------------------------------- #
def get_blob(filename):
    filedata = open(filename, "r")
    blob = filedata.read()
    filedata.close()
    blob = blob.replace("\n", "")      # incase data is split on multiple lines
    blob = blob.replace(" ", "")       # strip spaces too

    if blob[:4] == "0050":           # if data is responseparams from wireshark
        blob = blob[20:]             # wireshark includes the param size header
    if blob[:4] == "5000":           # if data is key from tpm2pcap skip header
        blob = blob[16:]             # tpm2pcap does not include the param size

    blob = bytes.fromhex(blob)
    return blob


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
# or data with header to the file (responseparams in wireshark)               #
# TODO: add some checks incase someone adds entire TPM packet                 #
# --------------------------------------------------------------------------- #
def get_vmk(filename):
    filedata = open(filename, "r")
    blob = filedata.read()
    filedata.close()
    blob = blob.replace("\n", "")      # incase data is split on multiple lines
    blob = blob.replace(" ", "")       # strip spaces too

    if blob[:4].lower() == "002c":   # if data is responseparams from wireshark
        blob = blob[4:]             # wireshark includes the param size header

    if len(blob) == 64:              # support bare VMK without header
        print("Found a bare VMK without header, adding a placeholder header")
        blob = "2c0000000100000003200000" + blob

    blob = bytes.fromhex(blob)
    tpmkey = parse_key(blob)
    return tpmkey


# --------------------------------------------------------------------------- #
# Get the BEK key from a file.                                                #
# --------------------------------------------------------------------------- #
def get_BEK(filename):
    filedata = open(filename, "rb")
    BEK_bin = filedata.read()

    uuid_bin = BEK_bin[16:32]
    uuid_str = uuid.UUID(bytes_le=uuid_bin)
    print("BEK key " + str(uuid_str))

    datum = BEK_bin[-44:]
    bek_key = parse_key(datum)

    return bek_key


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
        0x1000: "Stretch key",
        0x1001: "Unknown (Stretch key)",
        0x2000: "TPM? (AES-CCM 256-bit)",
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
def save_key(datum, computer_name):
    method = datum[8:10]
    key = datum[12:]
    print("Writing the following to key file: " + computer_name + ".fvek")
    keyfile_data = method + key + bytes(66 - len(method + key))
    print(keyfile_data.hex())
    while True:
        filename = computer_name + ".fvek"
        if os.path.isfile(filename):             # warn before overwriting file
            overwrite = input(
                "\nFile '"
                + filename
                + "' already exists. Overwrite? Y = yes, N = no\n"
                )
            if overwrite.lower() == "y":
                file = open(filename, "wb")
                file.write(keyfile_data)
                file.close()
                break
            if overwrite.lower() == "n":
                print("key not written")
                break
        else:
            file = open(filename, "wb")
            file.write(keyfile_data)
            file.close()
            break


# --------------------------------------------------------------------------- #
# Obligatory obnoxious banner SRC: https://fsymbols.com/generators/tarty/     #
# --------------------------------------------------------------------------- #
def print_banner():
    print("""
    ▒█▀▀▀█ ▒█▀▀█ ▀█▀ ▀▀█▀▀ █░█ █▀▀ █░░█
    ░▀▀▀▄▄ ▒█▄▄█ ▒█░ ░▒█░░ █▀▄ █▀▀ █▄▄█
    ▒█▄▄▄█ ▒█░░░ ▄█▄ ░▒█░░ ▀░▀ ▀▀▀ ▄▄▄█
    """)


# ########################################################################### #
# End of functions, execution starts here:                                    #
# ########################################################################### #
parser = argparse.ArgumentParser(
    prog="SPITkey",
    description="Get keys from dislocker verbose log, PIN and TPM blob"
    )
parser.add_argument(
    "-v", "--verbose", action="store_true",
    help="print debug information"
    )
parser.add_argument(
    "-l", "--logfile",
    help="path to logfile created using dislocker -vvvv"
    )
parser.add_argument(
    "-p", "--pin",
    help="the PIN used to decrypt the drive"
    )
parser.add_argument(
    "-t", "--tpmblob",
    help="file containing unsealed TPM data as hex (requires logfile + PIN)"
    )
parser.add_argument(
    "-k", "--key",
    help="file containing the sniffed VMK from the TPM (requires logfile)"
    )
parser.add_argument(
    "-r", "--recovery",
    help="file containing the recovery key (requires logfile)"
    )
parser.add_argument(
    "-b", "--bek",
    help="file containing the external BEK key"
    )
args = parser.parse_args()

print_banner()

# warn if missing logfile, read it in if present
if args.logfile is None:
    print("!! No logfile specified, cannot decrypt data !!")
    parser.print_help()
    sys.exit()
else:
    dislocker_log = open(args.logfile, "r")
    logfile = dislocker_log.readlines()
    dislocker_log.close()

if (args.tpmblob is None and args.key is None
        and args.recovery is None and args.bek is None):
    print("! No TPM data, VMK Recovery or BEK specified, cannot decrypt key !")
    parser.print_help()
    sys.exit()
if args.tpmblob is not None and args.key is not None:
    print("!! Please specify either key or blob !!")
    parser.print_help()
    sys.exit()
if args.tpmblob is not None and args.pin is None:
    print("!! No PIN specified, cannot decrypt data !!")
    parser.print_help()
    sys.exit()

# -----------------------------------------------------------------------------
# get FVEK using blob + pin + log [+ BEK] (TPMandPIN or TPMandPINandKEY)
if args.tpmblob is not None and args.pin is not None:
    if args.bek is not None:
        print("Decrypting FVEK using PIN, sniffed TPMandPIN blob and BEK")
        VMK_enc = get_enc_key(logfile, "External")
    else:
        print("Decrypting FVEK using PIN and sniffed TPMandPIN blob")
        VMK_enc = get_enc_key(logfile, "PIN")
    # get TPM blob data
    blob = get_blob(args.tpmblob)

    # get keys and salt from log file
    FVEK_enc = get_enc_fvek(logfile)
    pin_salt = get_salt(logfile, "PIN")

    if args.verbose is True:
        print("TPM blob : " + blob.hex())
        print("FVEK_enc : " + FVEK_enc.hex())
        print("VMK_enc  : " + VMK_enc.hex())
    print("PIN Salt : " + pin_salt.hex())
    print("PIN      : " + args.pin)

    # get hash key and stretched key
    hash_key = user_key(args.pin)
    stretched_key = stretch_key(hash_key, pin_salt)
    print("hashkey  : " + hash_key.hex())
    print("stretched: " + stretched_key.hex())

    # get the computer name for the saved FVEK filename
    computer_name = get_name(logfile)
    print("Computer : " + computer_name)
    print("")

    # decrypt the blob
    blob_dec = decrypt(blob, stretched_key)
    print("Decrypted blob")
    blob_key = parse_key(blob_dec)

    if args.bek is not None:
        print("XOR'ing StartupKey with blob key before decryption")
        bekkey = get_BEK(args.bek)
        xorkey = xor_keys(bekkey, blob_key)
        print("XOR key  : " + xorkey.hex())
        blob_key = xorkey

    # get the key from the decrypted blob and decrypt the VMK
    VMK_dec = decrypt(VMK_enc, blob_key)
    print("Decrypted VMK")
    VMK = parse_key(VMK_dec)

    # get the key from the decrypted VMK and decrypt the FVEK
    FVEK_dec = decrypt(FVEK_enc, VMK)
    print("Decrypted FVEK")
    parse_key(FVEK_dec)

    # save the FVEK to a file $computer_name.fvek
    path = os.path.dirname(args.tpmblob)
    path = os.path.join(path, computer_name)
    save_key(FVEK_dec, path)

    # get the reverse recovery key and decrypt with the VMK
    save_recovery(logfile, VMK)

    sys.exit()

# -----------------------------------------------------------------------------
# get FVEK using VMK + log [+ BEK] (TPM or TPMandKey)
if args.key is not None:
    if args.bek is not None:
        print("Decrypting FVEK using keys from TPM and StartupKey")
        print("Sniffed TPM key")
        tpmkey = get_vmk(args.key)
        bekkey = get_BEK(args.bek)
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
        # get the VMK and encrypted FVEK
        print("Sniffed TPM key")
        VMK = get_vmk(args.key)
        print("VMK      : " + VMK.hex())

    FVEK_enc = get_enc_fvek(logfile)
    if args.verbose is True:
        print("FVEK_enc : " + FVEK_enc.hex())

    # get the computer name for the saved FVEK filename
    computer_name = get_name(logfile)
    print("Computer : " + computer_name)
    print("")

    # decrypt the encrypted FVEK with the VMK
    FVEK_dec = decrypt(FVEK_enc, VMK)
    print("Decrypted FVEK")
    parse_key(FVEK_dec)

    # save the FVEK to a file $computer_name.fvek
    path = os.path.dirname(args.key)
    path = os.path.join(path, computer_name)
    save_key(FVEK_dec, path)

    # get the reverse recovery key and decrypt with the VMK
    save_recovery(logfile, VMK)

    sys.exit()

# -----------------------------------------------------------------------------
# get FVEK using recovery key
if args.recovery is not None:
    print("Decrypting FVEK using Recovery key")
    # get the recovery key, salt, FVEK
    VMK_enc = get_enc_key(logfile, "Recovery")
    FVEK_enc = get_enc_fvek(logfile)
    salt = get_salt(logfile, "Recovery")
    if args.verbose is True:
        print("FVEK_enc : " + FVEK_enc.hex())
        print("VMK_enc  : " + VMK_enc.hex())
    print("Salt     : " + salt.hex())

    # get the Recovery hash and stretched keys
    hash_key = get_recovery_key(args.recovery)
    stretched_key = stretch_key(hash_key, salt)
    print("hashkey  : " + hash_key.hex())
    print("stretched: " + stretched_key.hex())

    # get the computer name for the saved FVEK filename
    computer_name = get_name(logfile)
    print("Computer : " + computer_name)
    print("")

    # get the key from the decrypted blob and decrypt the VMK
    VMK_dec = decrypt(VMK_enc, stretched_key)
    print("Decrypted VMK")
    VMK = parse_key(VMK_dec)

    # get the key from the decrypted VMK and decrypt the FVEK
    FVEK_dec = decrypt(FVEK_enc, VMK)
    print("Decrypted FVEK")
    parse_key(FVEK_dec)

    # save the FVEK to a file $computer_name.fvek
    path = os.path.dirname(args.recovery)
    path = os.path.join(path, computer_name)
    save_key(FVEK_dec, path)

    sys.exit()

# -----------------------------------------------------------------------------
# get FVEK using external key (StartupKey or ExternalKey)
if args.bek is not None and args.key is None and args.pin is None:
    bekkey = get_BEK(args.bek)
    int_key = get_enc_key(logfile, "External")
    FVEK_enc = get_enc_fvek(logfile)

    # get the computer name for the saved FVEK filename
    computer_name = get_name(logfile)
    print("Computer : " + computer_name)
    print("")

    print("Decrypted VMK")
    int_key_dec = decrypt(int_key, bekkey)
    VMK = parse_key(int_key_dec)

    # get the key from the decrypted VMK and decrypt the FVEK
    FVEK_dec = decrypt(FVEK_enc, VMK)
    print("Decrypted FVEK")
    parse_key(FVEK_dec)

    # save the FVEK to a file $computer_name.fvek
    path = os.path.dirname(args.logfile)
    path = os.path.join(path, computer_name)
    save_key(FVEK_dec, path)

    # get the reverse recovery key and decrypt with the VMK
    save_recovery(logfile, VMK)

    sys.exit()

# if we made it here there was a very wrong set of flags
parser.print_help()
sys.exit()
