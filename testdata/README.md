Testdata
========

This directory contains test data for the various protector modes, if it requires a pin it is 87654321
To test these examples run the following command from the main directory:

- KEY only

```
SPITkey.py -l testdata\USB-KEY\dislocker-key.log -b testdata\USB-KEY\108D1C23-D614-4DA1-910D-3D87C488833A.BEK
```

- TPM only

```
SPITkey.py -l testdata\logic2-TPM\dislocker-TPM.log -k testdata\logic2-TPM\TPM-only.vmk
```

- TPMandPIN

```
SPITkey.py -l testdata\logic2-TPMandPIN\dislocker-TPMandPIN.log -t testdata\logic2-TPMandPIN\TPMandPIN.blob -p 87654321
```

- TPMandKEY

```
SPITkey.py -l testdata\logic2-TPMandKEY\dislocker-TPMandKEY.log -k testdata\logic2-TPMandKEY\TPMandKEY.vmk -b testdata\logic2-TPMandKEY\E5EFFF28-7AA3-4000-9E70-BB1A3DAD6203.BEK
```

- TPMandPINandKEY

```
SPITkey.py -l testdata\logic2-TPMandPINandKEY\dislocker-TPMandPINandKEY.log -t testdata\logic2-TPMandPINandKEY\TPMandPINandKEY.blob -p 87654321 -b testdata\logic2-TPMandPINandKEY\CA933F67-F8AA-4FB7-B526-F0D4EE6AB0AB.BEK
```

- RECOVERY

```
SPITkey.py -l testdata\logic2-TPM\dislocker-TPM.log -r "testdata\logic2-TPM\BitLocker Recovery Key 38F91648-280E-4F3A-9772-640DCB48F4CE.TXT"
```



