# SPITkey GUI: BitLocker VMK Decryptor

## 🔑 Overview

**SPITkey GUI** is a graphical front-end for a BitLocker Volume Master Key (VMK) decryptor and Full Volume Encryption Key (FVEK) extraction tool.

This application simplifies the process of using different BitLocker decryption methods—such as those based on TPM-sniffed keys, user PIN/Password, or Recovery Keys—to decrypt the VMK and subsequently extract the FVEK. The resulting FVEK and a numeric BitLocker Recovery Key are saved to files, which can then be used with tools like **Dislocker** to mount and access the encrypted volume.

The GUI aims to make the decryption workflow more accessible by handling file path inputs, mode selection, and coordinating the core cryptographic operations.

## ✨ Features

* **Multiple Decryption Modes:** Supports various BitLocker protector configurations:
    * **TPM Only** (Requires sniffed VMK file)
    * **TPM and PIN** (Requires sniffed TPM Blob and user PIN/Password)
    * **PIN/Password Only**
    * **BEK Only** (Requires an external `StartupKey` or `.bek` file)
    * **Recovery Key** (Requires a plain-text recovery key file)
    * **TPM and KEY (BEK)** (Combines TPM-sniffed VMK and a BEK file)
    * **TPM and PIN and KEY (BEK)** (Combines PIN, TPM Blob, and a BEK file)
* **Key Extraction:** Extracts and saves the decrypted **FVEK** (Full Volume Encryption Key) and the **numeric Recovery Key**.
* **Intuitive Interface:** Built with PyQt6 for a desktop-friendly user experience.
* **Output Redirection:** All process output and decryption results are streamed directly to the application's text window.
* **Custom Aesthetics:** Features a dark, stylized theme and an animated output window (complete with starfield and a 3D key visualization).

## ⚠️ Important Warning: Early Stage Code

**THIS IS AN EARLY VERSION OF THE GUI.**

While the core cryptographic logic is derived from a proven command-line tool, the graphical interface, input handling, and orchestration logic are newly implemented.

* **Expect Messy Code:** The code is in its initial stage of development and is currently quite messy. It has not been fully refactored for clarity or complete robustness.
* **Potential Bugs:** You may encounter unexpected bugs or crashes.
* **Troubleshooting:** If you experience any issues (e.g., failed decryption, unexpected behavior, file handling errors), please try the **command-line version** of the decryptor to rule out a bug specific to this GUI application.

Please report any issues you find, but understand that this version is provided for early testing and functionality demonstration.

## 🛠️ Prerequisites

To use this tool, you will need the following dependencies and files:

1.  **Python 3.x**
2.  **PyQt6:** For the graphical interface.
3.  **pycryptodome:** For the AES-CCM decryption and SHA256 hashing.
4.  **BitLocker Volume Data:**
    * A **Dislocker Log File** (`dislocker -v -V /dev/sdaX -- -vvvv > logfile.log` or similar). This log contains the encrypted key blobs, salt, and other metadata required for decryption.
    * The relevant **protector file** (`.vmk`, `.blob`, `.bek`, or plain-text recovery key) corresponding to the chosen decryption mode.

### Installation

```bash
# Clone the repository
git clone [YOUR_REPO_URL]
cd SPITkey_GUI

# Install Python dependencies
pip install pyqt6 pycryptodome
# Note: You may also need python-is-python3 or similar on some systems.