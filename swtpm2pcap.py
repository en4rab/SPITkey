# --------------------------------------------------------------------------- #
# swtpm2pcap.py input_file output_file                                        #
#                                                                             #
# convert swtpm verbose logfile to pcap so it can be parsed in wireshark      #
# https://github.com/stefanberger/swtpm                                       #
# This can also be parsed with tpmstream which reads pcaps                    #
# "tpmstream convert output_file.pcap"                                        #
# --------------------------------------------------------------------------- #

import argparse
import os
import re
import sys


def get_bytes(x, Lines):
    parts = Lines[x].split("length ")
    count = int(parts[1])
    hexdata = ""
    inc = 1
    while count > 0:
        data = Lines[x+inc].strip(" \n")
        hexdata = hexdata + " " + data
        inc += 1
        count -= 16
    return hexdata


# ----------------------------------------------------------------------------#
# Write data $output to file $filename                                        #
# if the file already exists prompt for confirmation before overwriting       #
# ----------------------------------------------------------------------------#
def writeOutputToFile(output, filename):
    while True:
        if os.path.isfile(filename):
            overwrite = input(
                "\nFile "
                + filename
                + " already exists. Overwrite? Y = yes, N = no\n"
                )
            if overwrite.lower() == "y":
                file = open(filename, "w")
                file.write(output)
                file.close()
                break
            if overwrite.lower() == "n":
                print("data not written")
                break
        else:
            print("saving to file " + filename)
            file = open(filename, "w")
            file.write(output)
            file.close()
            break


# ----------------------------------------------------------------------------#
# Write parsed data out to a txt file in a format suitable for conversion     #
# with text2pcap.exe if this is present on the system call it after writing   #
# the file to convert the text file automatically                             #
# ----------------------------------------------------------------------------#
def writePcap(output, filename):
    outfile = filename
    tempdata = output.splitlines()
    length = len(tempdata)
    output = ""
    for count in range(length):
        line = tempdata[count]
        line = line.replace("Write ", "O\n")
        line = line.replace("Read ", "I\n")
        line = line.replace("TPM_DATA_FIFO_0", "000000")

        output = output + line + "\n"

    tmpfile = filename + ".tmp"
    writeOutputToFile(output, tmpfile)

    win_exe = "C:\\Program Files\\Wireshark\\text2pcap.exe"
    linux_exe = "/usr/bin/text2pcap"
    if os.path.isfile(win_exe) is True:
        program = win_exe
    elif os.path.isfile(linux_exe) is True:
        program = linux_exe
    else:
        program = None
    
    if program is not None:
        pcapout = outfile + ".pcap"
        os.system(
            '"' + program + '"' + " -D -T 2321,49172 "
            + tmpfile + " " + pcapout
            )
    else:
        print("Data written to " + outfile + ".tmp convert to pcap using")
        print("\"text2pcap -D -T 2321,49172 " + outfile + ".tmp out.pcap\"")


# ----------------------------------------------------------------------------#
# Search the parsed data with regex's for the VMK and TPMandPIN blob          #
# Prints the data if it is found to save time looking in wireshark            #
# VMK regex from Withsecure's toolkit                                         #
# https://github.com/WithSecureLabs/bitlocker-spi-toolkit                     #
# While there shouldn't be multiple matches this will output more than one    #
# key file in the event there are                                             #
# ----------------------------------------------------------------------------#
def findKeys(output, filename):
    tempdata = output.replace(" ", "")  # strip spaces too lazy to change regex
    tempdata = tempdata.lower()
    vmk_match = re.findall(
        r'(2c000[0-6]000[1-9]000[0-1]000[0-5]200000)(\w{64})',
        tempdata
        )
    if vmk_match:
        length = len(vmk_match)
        for i in range(length):
            print("Possible VMK match:")
            print("Header : " + vmk_match[i][0])
            print("Key    : " + vmk_match[i][1])
            cnt = str(i)
            if cnt == "0":
                cnt = ""
            file = filename + cnt + ".vmk"
            # write header + key
            writeOutputToFile(vmk_match[i][0] + vmk_match[i][1], file)
    TPM_blob = re.findall(r'(5000000005000000)(\w{144})', tempdata)
    if TPM_blob:
        length = len(TPM_blob)
        for i in range(length):
            print("Possible TPM blob match:")
            print("Header : " + TPM_blob[i][0])
            print("Blob   : " + TPM_blob[i][1])
            cnt = str(i)
            if cnt == "0":
                cnt = ""
            file = filename + cnt + ".blob"
            # write header + blob
            writeOutputToFile(TPM_blob[i][0] + TPM_blob[i][1], file)
    if not vmk_match and not TPM_blob:
        print("Could not find any keys, if you were expecting a result check")
        print("in wireshark for the response to the first TPM2_CC_Unseal ")
        print("packet and also check pulseview to see if the trace is noisy")


# ----------------------------------------------------------------------------#
# Take swtmp verbose log and parse it into TPM packets                        #
# returns the data in the form                                                #
# "O \n000000 80 01 00 00 00 0A 00 00 01 81"                                  #
# This can then be searched or written out and converted with minimal effort  #
# ----------------------------------------------------------------------------#
def convert(Lines):
    output = ""
    length = len(Lines)
    for x in range(0, length):
        line = Lines[x].strip("\n")
        if line.startswith(" SWTPM_IO_Write:") is True:
            packet = get_bytes(x, Lines)
            if packet == " 80 01 00 00 00 0A 00 00 00 84":  # invalid packet
                continue
            else:
                output = output + "I\n000000" + packet + "\n"
        elif line.startswith(" SWTPM_IO_Read:") is True:
            packet = get_bytes(x, Lines)
            if packet == " 00 C1 00 00 00 0A 00 00 00 F1":  # invalid packet
                continue
            else:
                output = output + "O\n000000" + packet + "\n"
        else:
            continue
    return output


# ########################################################################### #
# End of functions, execution starts here:                                    #
# ########################################################################### #

parser = argparse.ArgumentParser(
    prog="swtpm2pcap",
    description="Parse trace verbose log from swtpm"
    " and convert to pcap or search for keys"
    )
parser.add_argument(
    "filename",
    help="path to exported trace file"
    )
parser.add_argument(
    "-p", "--pcap", action="store_true",
    help="convert input to pcap"
    )
parser.add_argument(
    "-k", "--key", action="store_true",
    help="search for and save keys"
    )

args = parser.parse_args()
input_list = open(args.filename, "r")
Lines = input_list.readlines()
# parse the trace data into packets
output = convert(Lines)
# get the input file name to uses when saving data
infilename = args.filename
savename = infilename.split(".")[0]

if args.pcap is True:
    print("\nWriting packets to file and "
          "converting to pcap if wireshark is present")
    writePcap(output, savename)
if args.key is True:
    print("\nSearching for potential keys:")
    findKeys(output, savename)
if args.key is False and args.pcap is False:
    print("Please specify either or both:")
    print("-k to search for and save keys")
    print("-p to convert input to pcap")
    sys.exit()
