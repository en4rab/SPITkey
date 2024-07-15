# --------------------------------------------------------------------------- #
#               █▀▀▄ █░░ █▀▀█ █▀▀▄ █▀█ ░░▀ █▀▀█ █░░█ █▀▀▄                     #
#               █▀▀▄ █░░ █░░█ █▀▀▄ ░▄▀ ░░█ █░░█ █▀▀█ █░░█                     #
#               ▀▀▀░ ▀▀▀ ▀▀▀▀ ▀▀▀░ █▄▄ █▄█ ▀▀▀▀ ▀░░▀ ▀░░▀                     #
#                                                                             #
# Extract data from a sniffed TPM blob and a dislocker log and output a hash  #
# file in a format suitable for trying to crack the PIN with Hashcat,         #
# John the ripper or bitcracker                                               #
# Requires:                                                                   #
#   The blob of data from the TPM unseal command and                          #
#   The output of dislocker -vvvv /dev/$bitlockerpartition                    #
#                                                                             #
# Usage: blob2john.py -l $dislocker-log -t $TPMblob                           #
# --------------------------------------------------------------------------- #

import os
import sys
import argparse


# --------------------------------------------------------------------------- #
# get the salt needed to stretch the PIN hash from the logfile                #
# --------------------------------------------------------------------------- #
def get_salt(logfile):
    tpmandpin = False
    length = len(logfile)
    for x in range(0, length):
        line = logfile[x].strip("\n")
        if "Algo: 0x2004" in line:                   # find the TPMandPin datum
            tpmandpin = True
        if tpmandpin is True and "Salt:" in line:
            salt = logfile[x + 1].strip("\n")
            salt = salt.split("[DEBUG] ")
            salt = bytes.fromhex(salt[1])
            break
    return salt


# --------------------------------------------------------------------------- #
# get the computer name from datum type 7 to use when saving the hash         #
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


# --------------------------------------------------------------------------- #
# Save the hash to a file for use with hashcat, john the ripper or bitcracker #
# Takes a hash string and the computer name from the dislocker log            #
# and saves the hash in a format suitable for cracking to $computer_name.hash #
# --------------------------------------------------------------------------- #
def save_key(data, filename):
    print("Writing the following to hash file: " + filename)
    keyfile_data = data
    print(keyfile_data)
    while True:
        if os.path.isfile(filename):             # warn before overwriting file
            overwrite = input(
                "\nFile '"
                + filename
                + "' already exists. Overwrite? Y = yes, N = no\n"
                )
            if overwrite.lower() == "y":
                file = open(filename, "w")
                file.write(keyfile_data)
                file.close()
                break
            if overwrite.lower() == "n":
                print("key not written")
                break
        else:
            file = open(filename, "w")
            file.write(keyfile_data)
            file.close()
            break


# ########################################################################### #
# End of functions, execution starts here:                                    #
# ########################################################################### #
parser = argparse.ArgumentParser(
    prog="blob2john",
    description="Get hash from dislocker verbose log and TPM blob"
    )
parser.add_argument(
    "-l", "--logfile",
    help="path to logfile created using dislocker -vvvv"
    )
parser.add_argument(
    "-t", "--tpmblob",
    help="file containing unsealed TPM data as hex (requires logfile + PIN)"
    )
args = parser.parse_args()

# warn if missing logfile, read it in if present
if args.logfile is None:
    print("!! No logfile specified, cannot extract hash !!\n")
    parser.print_help()
    sys.exit()
else:
    dislocker_log = open(args.logfile, "r")
    logfile = dislocker_log.readlines()
    dislocker_log.close()

if args.tpmblob is None:
    print("!! No TPM data specified, cannot extract hash !!\n")
    parser.print_help()
    sys.exit()

# get the computer name for the saved FVEK filename
computer_name = get_name(logfile)
print("Computer : " + computer_name)

# get the salt from the logfile
salt = get_salt(logfile)
print("Salt     : " + salt.hex())

# get TPM blob data
blob = get_blob(args.tpmblob)
nonce = blob[:12]
mac = blob[12:28]
enc_key = blob[28:]
print("nonce    : " + nonce.hex())
print("mac      : " + mac.hex())
print("enc_key  : " + enc_key.hex())
print("")

#  Hash type: User Password with MAC verification
# (slower solution, no false positives)
# $bitlocker$1$16${salt}$1048576$12${nonce}$60${mac}{enc_key}
bl_hash = ("$bitlocker$1$16$" + salt.hex() + "$1048576$12$"
           + nonce.hex() + "$60$" + mac.hex() + enc_key.hex())

# save the hash to a file $path\$computer_name.hash
path = os.path.dirname(args.tpmblob)
save_key(bl_hash, path + "\\" + computer_name + ".hash")
sys.exit()
