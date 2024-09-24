# function test call spitkey with various test files to check they are
# decrypted correctly and make sure I havent broken anything by making changes

import os


def get_line(filename):
    file = open(filename)
    first_line = file.readline()
    return first_line


def get_fvek(filename):
    file = open(filename, "rb")
    fvek_hex = file.read().hex()
    return fvek_hex


def cleanup(filename):
    if os.path.isfile(filename):
        print("removing " + filename)
        os.remove(filename)


result_list = ""

# -----------------------------------------------------------------------------
# Test  logic2-TPMandKEY
result = "passed"
fvek_file = os.path.join("testdata", "logic2-TPMandKEY", "DESKTOP-LBLPGHL.fvek")
recovery_file = os.path.join("testdata", "logic2-TPMandKEY", "38F91648-280E-4F3A-9772-640DCB48F4CE.recovery")

cleanup(fvek_file)
cleanup(recovery_file)

log = os.path.join("testdata", "logic2-TPMandKEY", "dislocker-TPMandKEY.log")
key = os.path.join("testdata", "logic2-TPMandKEY", "TPMandKEY.vmk")
bek = os.path.join("testdata", "logic2-TPMandKEY", "E5EFFF28-7AA3-4000-9E70-BB1A3DAD6203.BEK")

os.system("python SPITkey.py -l " + log + " -k " + key + " -b " + bek)

recovery_key = "712349-506968-088748-356565-266090-003839-598565-010538"
fvek = "0480c9fa9f7c8457890542b80d80b26abac96503f05d84ddca4fa8af2d9fe993dfd30000000000000000000000000000000000000000000000000000000000000000"

dec_fvek = get_fvek(fvek_file)
if dec_fvek != fvek:
    print("TPM only FVEK did not decrypt correctly")
    result = "failed"

dec_recovery = get_line(recovery_file)
if dec_recovery != recovery_key:
    print("TPM only Recovery key did not decrypt correctly")
    result = "failed"

cleanup(fvek_file)
cleanup(recovery_file)

result_list = result_list + "TPMandKEY test " + result + "\n"


# Test  logic2-TPM
result = "passed"
fvek_file = os.path.join("testdata", "logic2-TPM", "DESKTOP-LBLPGHL.fvek")
recovery_file = os.path.join("testdata", "logic2-TPM", "38F91648-280E-4F3A-9772-640DCB48F4CE.recovery")

cleanup(fvek_file)
cleanup(recovery_file)

log = os.path.join("testdata", "logic2-TPM", "dislocker-TPM.log")
key = os.path.join("testdata", "logic2-TPM", "TPM-only.vmk")
os.system("python SPITkey.py -l " + log + " -k " + key)

recovery_key = "712349-506968-088748-356565-266090-003839-598565-010538"
fvek = "0480c9fa9f7c8457890542b80d80b26abac96503f05d84ddca4fa8af2d9fe993dfd30000000000000000000000000000000000000000000000000000000000000000"

dec_fvek = get_fvek(fvek_file)
if dec_fvek != fvek:
    print("TPM only FVEK did not decrypt correctly")
    result = "failed"

dec_recovery = get_line(recovery_file)
if dec_recovery != recovery_key:
    print("TPM only Recovery key did not decrypt correctly")
    result = "failed"

cleanup(fvek_file)
cleanup(recovery_file)

result_list = result_list + "TPM only test " + result + "\n"

# -----------------------------------------------------------------------------
# Test  logic2-TPMandPIN
result = "passed"
fvek_file = os.path.join("testdata", "logic2-TPMandPIN", "DESKTOP-LBLPGHL.fvek")
recovery_file = os.path.join("testdata", "logic2-TPMandPIN", "38F91648-280E-4F3A-9772-640DCB48F4CE.recovery")

cleanup(fvek_file)
cleanup(recovery_file)

log = os.path.join("testdata", "logic2-TPMandPIN", "dislocker-TPMandPIN.log")
blob = os.path.join("testdata", "logic2-TPMandPIN", "TPMandPIN.blob")
os.system("python SPITkey.py -l " + log + " -t " + blob + " -p 87654321")

recovery_key = "712349-506968-088748-356565-266090-003839-598565-010538"
fvek = "0480c9fa9f7c8457890542b80d80b26abac96503f05d84ddca4fa8af2d9fe993dfd30000000000000000000000000000000000000000000000000000000000000000"

dec_fvek = get_fvek(fvek_file)
if dec_fvek != fvek:
    print("TPMandPIN FVEK did not decrypt correctly")
    result = "failed"

dec_recovery = get_line(recovery_file)
if dec_recovery != recovery_key:
    print("TPMandPIN Recovery key did not decrypt correctly")
    result = "failed"

cleanup(fvek_file)
cleanup(recovery_file)

result_list = result_list + "TPMandPIN test " + result + "\n"

# -----------------------------------------------------------------------------
# Test  logic2-TPMandPINandKEY
result = "passed"
fvek_file = os.path.join("testdata", "logic2-TPMandPINandKEY", "DESKTOP-LBLPGHL.fvek")
recovery_file = os.path.join("testdata", "logic2-TPMandPINandKEY", "3CBE5E70-96FF-45BC-A609-1D38323006F0.recovery")

cleanup(fvek_file)
cleanup(recovery_file)

log = os.path.join("testdata", "logic2-TPMandPINandKEY", "dislocker-TPMandPINandKEY.log")
blob = os.path.join("testdata", "logic2-TPMandPINandKEY", "TPMandPINandKEY.blob")
bek = os.path.join("testdata", "logic2-TPMandPINandKEY", "CA933F67-F8AA-4FB7-B526-F0D4EE6AB0AB.BEK")
os.system("python SPITkey.py -l " + log + " -t " + blob + " -p 87654321 -b " + bek)

recovery_key = "203907-116314-114389-096954-364463-544236-500236-393580"
fvek = "0480c9fa9f7c8457890542b80d80b26abac96503f05d84ddca4fa8af2d9fe993dfd30000000000000000000000000000000000000000000000000000000000000000"

dec_fvek = get_fvek(fvek_file)
if dec_fvek != fvek:
    print("TPMandPINandKEY FVEK did not decrypt correctly")
    result = "failed"

dec_recovery = get_line(recovery_file)
if dec_recovery != recovery_key:
    print("TPMandPINandKEY Recovery key did not decrypt correctly")
    result = "failed"

cleanup(fvek_file)
cleanup(recovery_file)

result_list = result_list + "TPMandPINandKEY test " + result + "\n"

# -----------------------------------------------------------------------------
# Test  swtpm-TPM
result = "passed"
fvek_file = os.path.join("testdata", "swtpm-TPM", "DESKTOP-GUUFK3H.fvek")
recovery_file = os.path.join("testdata", "swtpm-TPM", "39C2AA90-0CFA-4B77-9622-11A99EDCE513.recovery")

cleanup(fvek_file)
cleanup(recovery_file)

log = os.path.join("testdata", "swtpm-TPM", "dislocker-TPM.log")
vmk = os.path.join("testdata", "swtpm-TPM", "TPM-only.vmk")
os.system("python SPITkey.py -l " + log + " -k " + vmk)

recovery_key = "586784-333322-635690-264165-396374-216447-422653-402589"
fvek = "04801c8b7b0a3dd295948742aaf6c61920e25d7cbd7eb97471e54b2fd0819d0a2d010000000000000000000000000000000000000000000000000000000000000000"

dec_fvek = get_fvek(fvek_file)
if dec_fvek != fvek:
    print("swtpm-TPM only FVEK did not decrypt correctly")
    result = "failed"

dec_recovery = get_line(recovery_file)
if dec_recovery != recovery_key:
    print("swtpm-TPM only Recovery key did not decrypt correctly")
    result = "failed"

cleanup(fvek_file)
cleanup(recovery_file)

result_list = result_list + "swtpm-TPM only test " + result + "\n"


# -----------------------------------------------------------------------------
# Test  swtpm-TPMandPIN
result = "passed"
fvek_file = os.path.join("testdata", "swtpm-TPMandPIN", "DESKTOP-GUUFK3H.fvek")
recovery_file = os.path.join("testdata", "swtpm-TPMandPIN", "39C2AA90-0CFA-4B77-9622-11A99EDCE513.recovery")

cleanup(fvek_file)
cleanup(recovery_file)

log = os.path.join("testdata", "swtpm-TPMandPIN", "dislocker-TPMandPIN.log")
blob = os.path.join("testdata", "swtpm-TPMandPIN", "TPMandPIN.blob")
os.system("python SPITkey.py -l " + log + " -t " + blob + " -p 87654321")

recovery_key = "586784-333322-635690-264165-396374-216447-422653-402589"
fvek = "04801c8b7b0a3dd295948742aaf6c61920e25d7cbd7eb97471e54b2fd0819d0a2d010000000000000000000000000000000000000000000000000000000000000000"

dec_fvek = get_fvek(fvek_file)
if dec_fvek != fvek:
    print("swtpm-TPMandPIN FVEK did not decrypt correctly")
    result = "failed"

dec_recovery = get_line(recovery_file)
if dec_recovery != recovery_key:
    print("swtpm-TPMandPIN Recovery key did not decrypt correctly")
    result = "failed"

cleanup(fvek_file)
cleanup(recovery_file)

result_list = result_list + "swtpm-TPMandPIN test " + result + "\n"


# -----------------------------------------------------------------------------
# Test  USB-KEY
result = "passed"
fvek_file = os.path.join("testdata", "USB-KEY", "DESKTOP-LBLPGHL.fvek")
recovery_file = os.path.join("testdata", "USB-KEY", "3CBE5E70-96FF-45BC-A609-1D38323006F0.recovery")

cleanup(fvek_file)
cleanup(recovery_file)

log = os.path.join("testdata", "USB-KEY", "dislocker-key.log")
bek = os.path.join("testdata", "USB-KEY", "108D1C23-D614-4DA1-910D-3D87C488833A.BEK")
os.system("python SPITkey.py -l " + log + " -b " + bek)

recovery_key = "203907-116314-114389-096954-364463-544236-500236-393580"
fvek = "0480c9fa9f7c8457890542b80d80b26abac96503f05d84ddca4fa8af2d9fe993dfd30000000000000000000000000000000000000000000000000000000000000000"

dec_fvek = get_fvek(fvek_file)
if dec_fvek != fvek:
    print("USB-KEY FVEK did not decrypt correctly")
    result = "failed"

dec_recovery = get_line(recovery_file)
if dec_recovery != recovery_key:
    print("USB-KEY Recovery key did not decrypt correctly")
    result = "failed"

cleanup(fvek_file)
cleanup(recovery_file)

result_list = result_list + "USB-KEY test " + result + "\n"

# -----------------------------------------------------------------------------
# Test  RECOVERY
result = "passed"
fvek_file = os.path.join("testdata", "logic2-TPM", "DESKTOP-LBLPGHL.fvek")

cleanup(fvek_file)

log = os.path.join("testdata", "logic2-TPM", "dislocker-TPM.log")
recovery_key = os.path.join("testdata", "logic2-TPM", "BitLocker_Recovery_Key_38F91648-280E-4F3A-9772-640DCB48F4CE.TXT")
os.system("python SPITkey.py -l " + log + " -r " + recovery_key)

fvek = "0480c9fa9f7c8457890542b80d80b26abac96503f05d84ddca4fa8af2d9fe993dfd30000000000000000000000000000000000000000000000000000000000000000"

dec_fvek = get_fvek(fvek_file)
if dec_fvek != fvek:
    print("RECOVERY FVEK did not decrypt correctly")
    result = "failed"

cleanup(fvek_file)

result_list = result_list + "RECOVERY test " + result + "\n"

print("\n\n")
print(result_list)
