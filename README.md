```
▒█▀▀▀█ ▒█▀▀█ ▀█▀ ▀▀█▀▀ █░█ █▀▀ █░░█ 
░▀▀▀▄▄ ▒█▄▄█ ▒█░ ░▒█░░ █▀▄ █▀▀ █▄▄█ 
▒█▄▄▄█ ▒█░░░ ▄█▄ ░▒█░░ ▀░▀ ▀▀▀ ▄▄▄█
```

# Requirements
These scripts require:
  python3: [https://www.python.org/downloads/](https://www.python.org/downloads/)  
  pycryptodome: "pip install pycryptodome" 

optionally:
  wireshark: [https://www.wireshark.org/download.html](https://www.wireshark.org/download.html)

# SPITkey
**Usage:  spitkey.py -l $LOG [-p $PIN -t $TPMblob] [-k $VMK] [-r $RECOVERY] [-b $BEK]**

Decrypt the bitlocker FVEK for a bitlocker encrypted drive.
All methods require the output of the command ```dislocker -vvvv /dev/$bitlockerpartition``` as this contains important metadata and the encrypted keys.

In addition:

- KEY only requires
  - The BEK file
- TPM only requires
  - The VMK sniffed from the TPM
- TPMandPIN requires
  -   The PIN
  -   The blob of data returned from the TPM by the unseal command
- TPMandKEY requires
  -   The BEK file
  -   The VMK sniffed from the TPM
- TPMandPINandKEY requires
  -   The BEK file
  -   The PIN
  -   The blob of data returned from the TPM by the unseal command
- Recovery requires
  -   The recovery key
- Password requires
  -   The password (use the -p arg to supply the password)

If you provide no other option than the logfile, it is expected to contain the VMK in clear, meaning it has been generated with a disk where protection was temporary disabled, and dislocker could find a clear key.  

> [!NOTE]
> Please note the sniffed data from the TPM is handled differently depending on the mode  
> If bitlocker is in TPM or TPMandKEY the data you sniff is a key and use -k $key  
> If bitlocker is in TPMandPIN or TPMandPINandKEY the data is an encrypted blob and use -t $blob  


# sigrok2pcap
**Usage: sigrok2pcap.py input_file -p (write pcap) -k (write keys)**

Convert exported csv data from libsigrokdecoder_spi-tpm.

- -p will output a text file suitable for use with wiresharks text2pcap.exe If this is present it will be called to convert the file automatically.
- -k will extract the VMK or Blob and save it.

# dslogic2pcap

**Usage: dslogic2pcap.py input_file -p (write pcap) -k (write keys)**

Convert exported csv data from DSView's SPI TPM protocol decoder.

- -p will output a text file suitable for use with wiresharks text2pcap.exe If this is present it will be called to convert the file automatically.
- -k will extract the VMK or Blob and save it.
> [!IMPORTANT]
> When exporting data from DSView to a csv with the save button in the "Decoding Results" panel select only the "SPI TPM: TPM transactions" checkbox

# logic2pcap
**Usage: logic2pcap.py input.csv -p (write pcap) -k (write keys)**

Convert exported csv data from locic2 using Withsecure's "TPM SPI" analyser

- -p will output a text file suitable for use with Wireshark's text2pcap.exe If wireshark is installed it will be called to convert the file automatically
- -k will extract the VMK or Blob and save it.

> [!IMPORTANT]
> When exporting data from logic2 to a csv ensure the "TPM SPI" analyser's "operation selector" is set to export both read and write data 


# swtpm2pcap
**Usage: swtpm2pcap.py input_file -p (write pcap) -k (write keys)**

Convert the verbose log of an emulated tpm in QEMU using the swtpm package 

- -p will output a text file suitable for use with wiresharks text2pcap.exe If wireshark is installed it will be called to convert the file automatically
- -k will extract the VMK or Blob and save it.

This was writen when testing and is only left in incase it of use to someone. To output tpm traffic in the logfile swtpm needs to be called with the option ```--log level=20```


# blob2john
**Usage: blob2john.py -l $dislocker-log -t $TPMblob**

Extract data from a sniffed TPM blob and a dislocker log and output a hash file 
in a format suitable for trying to crack the PIN with Hashcat,
John the ripper or bitcracker
Requires:

- The blob of data from the TPM unseal command

- The output of dislocker -vvvv /dev/$bitlockerpartition


# Sniffing the SPI bus
Sniffing the data from the TPM will require a suitably fast logic analyser that
is supported by pulseview or Logic2.

SPI TPM's have a minimum bus speed of 10 - 24 MHz however the Trusted Computing
Group encourage support for frequencies between 33MHz and 66MHz.
As a rule of thumb you ideally need a sample rate at least 4 times faster than the bus speed for 
example a 43MHz Infineon 9670 would need an analyser than can sample 4 channels
(MISO MOSI SCLK CS#) at a minimum of 172 MHz and if possible faster.

# Software setup
The required software is dictated by the logic analyser hardware being used
Either Pulseview and libsigrokdecoder_spi-tpm or Logic2 and WithSecures "TPM SPI" analyser for Saleae devices

### Pulseview

Install Pulseview 
[https://sigrok.org/wiki/Downloads](https://sigrok.org/wiki/Downloads)

Install the libsigrokdecoder_spi-tpm stacked decoder.
[https://github.com/ghecko/libsigrokdecoder_spi-tpm](https://github.com/ghecko/libsigrokdecoder_spi-tpm)

To install this click on code then download zip to download the plugin.
Unzip the libsigrokdecoder_spi-tpm-main.zip and it should unzip to a folder 
called libsigrokdecoder_spi-tpm-main rename this to "spi_tpm" and then copy 
this folder and its contents to 
"C:\Program Files\sigrok\PulseView\share\libsigrokdecode\decoders\"
It is important you name the folder spi_tpm as pulseview expects the folder 
name and the plugin id to match eg. "id = 'spi_tpm'"

### Logic2

Install Logic2
[https://www.saleae.com/downloads/](https://www.saleae.com/downloads/)

Install WithSecures "TPM SPI" analyzer from their bitlocker spi toolkit
[https://github.com/WithSecureLabs/bitlocker-spi-toolkit](https://github.com/WithSecureLabs/bitlocker-spi-toolkit)

This repo also contains some slightly edited versions of these plugins which
will find both keys and the encrypted blob and display the key/blob in a full width bubble
on the main trace display as well as in the terminal.
They are in the "logic2-plugins" folder

### Both

On a machine running Linux or a linux VM Install dislocker
[https://github.com/Aorimn/dislocker](https://github.com/Aorimn/dislocker)  

The output of `dislocker -vvvv /dev/encryptedpartition` is required to decrypt 
the TPMandPIN blob and recover the FVEK.  Connect the bitlocker encrypted drive to a machine running linux or a linux VM
and find the bitlocker partition with `sudo fdisk -l`  

The partition will show as "Microsoft basic data" on a device that isn't usb in 
this example /dev/nvme0n1p3  
(note lowercase v for verbosity and uppercase V for volume)  
   `sudo dislocker -vvvv -V /dev/nvme0n1p3 > dislocker.log`  
or  
   `sudo dislocker -vvvv -l dislocker.log -V /dev/nvme0n1p3`  
This will create a file "dislocker.log" with the information you need.

If you wish to convert and view the recorded TPM data as pcaps.
Install wireshark
[https://www.wireshark.org/](https://www.wireshark.org/)


# Exporting trace data - Pulseview
Once you have setup pulseview and connected the logic analyser to the TPM you 
can record the spi bus then add first the SPI protocol decoder then once that 
is configured select stack decoder and add the "SPI TPM" stackable decoder and
select the tpm type 1.2 or 2.0.

At this point it should have (slowly) decoded the TPM traffic and you should 
see some decoded data below the traces.
If the target PC had bitlocker configured for TPM only there should be a trace 
labled "SPI TPM: BitLocker Volume Master Key" if this is the case that key can 
either be used directly with dislocker to unlock the drive or you can use 
SPITkey with the key and a dislocker logfile to recover the FVEK.

If the PC is using TPMandPIN or you wish to export a PIN only trace to a pcap
the data needed for conversion to pcap is the trace labeled 
"SPI TPM: TPM transactions" to save this right click on the trace and select 
"Export all annotations for this row" and save the annotations as a text file.
This text file can then be converted to a pcap or the key/blob extracted using sigrok2pcap.


# Exporting trace data - Logic2
Launch Logic2 and select the SPI analyser and setup your channels.  
In the the Extension tab click on the 3 dots and select "load existing extension"
and add both of the WithSecure plugins "Bitlocker Key Extractor" and "TPM SPI Transaction"  
On the analysers tab deselect "Stream to Terminal" and "Show in data table"
for the SPI analyser as we don't need that data but the extensions require that.  

For the TPM SPI extension select edit and change "operation selector" to both 
so when you export the data it will have both read and write data.

Now capture the spi data. The "Bitlocker Key Extractor" decoder should have logged the key
or the blob to the terminal to let you know you were successful.

To extract the key/blob or to export the data to a pcap the "TPI SPM" decoders output first
needs to be exported to a csv file.  
On the Analyzers tab with the data table selected click on the three dots to the right of the search box.  Click on export table and select all columns, all data, CSV format and then save the data as a CSV. This can then be converted to a pcap or the key/blob extracted using logic2pcap. 

# Extracting the key from a trace
With the trace exported to a csv from logic2 or sigrock run the appropriate 
x2pcap.py script using the -k argument will export the VMK or blob to a file and
the -p flag will export the data to a pcap if you wish to view it in wireshark.

# Decrypting the blob and or FVEK
With the key or blob extracted from the csv run SPITKey.py with the appropriate 
inputs for the protector in use:  
TPM needs the VMK and the metadata  
TPMandStartupKey needs the VMK, the BEK and the metadata  
TPMandPIN needs the blob, the pin and the metadata  
TPMandPINandStartupKey needs the blob, the pin, the BEK and the metadata  
StartupKey needs the BEK and the metadata  
Recovery needs the recovery key and the metadata  
Password needs the password and the metadata  
This will then decrypt the FVEK and save it out to a file so you can use it with dislocker.
If the drive is using TPM only you can skip this step and just use the VMK extracted from the CSV with dislocker.

# Using other TPM sniffers

The output of the extractor scripts x2pcap.py save the VMK or blob including the header. SPITkey should accept a vmk or blob with or without the header or with the header and the additional 2 byte length if copied from wireshark. If you have used a tool such as Stacksmashing's Pico TPMSniffer you can use the bare vmk.

If your capture is from a PC using TPMandPIN and you have built an implant and somehow managed
to get the blob when the owner logged in but don't know the PIN, well done!  
You can use blob2john and the dislocker log to extract the hash needed to attempt
to brute force the PIN with John the ripper, hashcat or bitcracker.

# Additional info

There is a blog post about SPITkey with some screenshots here [https://en4rab.github.io/posts/Sniffing-Bitlocker-Keys/](https://en4rab.github.io/posts/Sniffing-Bitlocker-Keys/)
