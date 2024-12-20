# --------------------------------------------------------------------------- #
#                                                                             #
#           █▀▀▄ █▀▀ █░░ █▀▀█ █▀▀▀ ░▀░ █▀▀ █▀█ █▀▀█ █▀▀ █▀▀█ █▀▀█             #
#           █░░█ ▀▀█ █░░ █░░█ █░▀█ ▀█▀ █░░ ░▄▀ █░░█ █░░ █▄▄█ █░░█             #
#           ▀▀▀░ ▀▀▀ ▀▀▀ ▀▀▀▀ ▀▀▀▀ ▀▀▀ ▀▀▀ █▄▄ █▀▀▀ ▀▀▀ ▀░░▀ █▀▀▀             #
#                                                                             #
# convert output from dslogic to a text file suitable for use with wiresharks #
# text2pcap.exe. If this is present it will be called to convert the file     #
# automatically                                                               #
# https://github.com/ghecko/libsigrokdecoder_spi-tpm                          #
#                                                                             #
# Usage: dslogic2pcap.py input_file -p (write pcap) -k (write keys)           #
# --------------------------------------------------------------------------- #

import os
import sys
import argparse
import re


def getAction(line):
    parts = line.split(",")
    action = parts[2]
    return action
    # TODO grab time and mangle it to something appropriate for wireshark?


def getRegister(line):
    parts = line.split(",Register: ")
    register = parts[1]
    return register


def getData(line):
    parts = line.split(",")
    data = parts[2]
    data = data[:2]  # data occasionally had an extra null appended no idea why
    return data


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
# Take exported pulseview trace and parse it into TPM packets                 #
# returns the data in the form                                                #
# Read TPM_DATA_FIFO_0 80 01 00 00 00 0a 00 00 01 00\n                        #
# This can then be searched or written out and converted with minimal effort  #
# ----------------------------------------------------------------------------#
def convert(Lines):
    # check first line is valid action eg READ or WRITE
    start_idx = 0
    for x in range(5):
        line = Lines[x].strip("\n")
        action = getAction(line)
        if action == "Read" or action == "Write":
            start_idx = x
            break

    prev_action = ""
    length = len(Lines)
    for x in range(start_idx, length, 4):
        left = length - x               # stop if input file has been truncated
        if left < 4:
            break
        line1 = Lines[x].strip("\n")
        line2 = Lines[x+1].strip("\n")
        line3 = Lines[x+2].strip("\n")
        line4 = Lines[x+3].strip("\n")

        if line1 == "":           # dont explode if there are trailing newlines
            break

        action = getAction(line1)
        register = getRegister(line2)
        if "Wait" in line3:
            data = getData(line4)
        else:
            data = getData(line3)

        if register == "TPM_DATA_FIFO_0":
            if prev_action == "":    # stops first line of the file being blank
                output = action + " " + register + " " + data + " "
                prev_action = action
            elif action == prev_action:
                output = output + data + " "
            else:
                output = (
                    output + "\n" + action
                    + " " + register + " " + data + " "
                    )
                prev_action = action
        else:
            continue
    return output


# ########################################################################### #
# End of functions, execution starts here:                                    #
# ########################################################################### #
parser = argparse.ArgumentParser(
    prog="sigrok2pcap",
    description="Parse trace exported from libsigrokdecoder_spi-tpm"
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

# read the data in from the file
input_list = open(args.filename, "r")
Lines = input_list.readlines()
input_list.close()
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
