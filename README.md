# Retro Hunter 🕵🏾‍♀️
**Security Scanner & Threat Audit Tool** for Veeam Backup & Replication Restore Points using the Data Integration API.

## 🛡️Find Threats in Your Backups – With Retro Hunter
Imagine you’re responsible for your company’s security. You have backups. You trust them. But what if malware or suspicious files are hiding right now or were silently active weeks ago? Wouldn’t it be great to look inside your backups, like a time machine, and search for threats?

That’s exactly what Retro Hunter does!
It connects directly to your Veeam backups and scans files from past restore points for signs of malware, hacked binaries, and other suspicious behavior. And the best part: it comes with a beautiful, easy-to-use dashboard that shows you everything.

![alt text](https://github.com/yetanothermightytool/retro-hunter/blob/main/Images/retro-hunter.png)

Retro Hunter is a lightweight Python-based toolkit that scans Veeam Backup & Replication restore points for malware, suspicious binaries, and unusual patterns. It allows you to investigate historical restore points and perform regular scans over time. By integrating with threat intelligence sources like MalwareBazaar, it continuously checks known file hashes and monitors the scanning results.

## ✅ Key Features
- Search for Veeam backups from a specific host or Veeam Backup Repository
- Mounts the manually selected backup via the Veeam Data Integration API
- Mounts the latest restore point from all supported platforms from a Veeam Backup Repository
- Scans mounted Veeam restore points
- Saves useful metadata from the presented files
- Parallelized scanning using Python’s multiprocessing for fast performance
- Tracks file changes across restore points (hash or size drift)
- Detects known malware using hash lookups from MalwareBazaar
- Identifies out-of-place LOLBAS (Living Off the Land Binaries and Scripts)
- Optionally applies YARA rules to selected file types during scan
- Displays findings in a Streamlit dashboard
- (Currently) Uses SQLite for persistent storage (file index and scan results)

## ⚙️ Setup Process
The setup process is simplified with the setup.sh script. You only need to download the malwarebazaar.csv file (See more in the [Technical Details of the Scripts](#-technical-details-of-the-scripts) and run the script with your target folder. During setup, you will be asked for the VBR Server, REST API user, and a password. The password will be securely encrypted and stored using Fernet.

```bash
./setup.sh /path/to/malwarebazaar.csv retro-hunter
```

## 🐳 Docker Support
A minimal Docker setup is provided to run the Streamlit dashboard in isolated environments.

## 🛠️ Technical Details of the Scripts
## Version Information
~~~~
Version: 1.0 (June 2025)
Requires: Veeam Backup & Replication v12.3.1 & Linux & Python 3.1+
Author: Stephan "Steve" Herzig
~~~~

## Prerequisites
Some preparations are required for this script to run. 

### Veeam Backup & Replication
You must add the Linux server on which this script is executed to the [backup infrastructure](https://helpcenter.veeam.com/docs/backup/vsphere/add_linux_server.html).

### Python Modules
The following Python modules are not part of the standard library and must be installed separately using pip.
- requests
- cryptography (for cryptography.fernet.Fernet)
- colorama
- yara (usually installed via yara-python)

## YARA Rules
Save additional YARA rule files in the script folder directory yara_rules. (File extensions .yar and .yara). A sample rule is stored in the yara_rules directory.

## Database
The script loads the contents of the databases into memory during runtime. Currently, there are two central databases involved: One stores known LOLBAS tools and malware hashes (badfiles.db), while the other (file_index.db) is used to keep track of scanned or stored files and their metadata.

The malwarebazaar table in badfiles.db contains the SHA256 values of the malware files. Download the complete [data dump](https://bazaar.abuse.ch/export/#csv) and unzip the CSV file as malwarebazaar.csv to the script folder. The script import_malwarebazaar_data.py imports the values into the database.

## Possible improvements
- Bloom filter support to improve memory efficiency when handling large hash sets.
- Mark the scanned restore point as infected in Veeam Backup & Replication.
- And a few other nice things that I'm currently researching.

- 1.0 (June 2025)
  - Initial version

## Considerations and Limitations
- The scripts have been created and tested on Ubuntu 22.04.
- Only filesystems with the NTFS, ext4, and XFS filesystems can be scanned when presenting the restore points using iSCSI
- When mounting NTFS disks, it’s important to know that Ubuntu (from version 22.04 and newer) uses the built-in ntfs3 kernel driver, which provides better performance and more stable access. In contrast, Rocky Linux and other RHEL-based systems usually rely on the older ntfs-3g driver through FUSE, which is slower because it runs in user space. This means that the way NTFS is handled can vary depending on the system.

    
## Disclaimer
**This script is not officially supported by Veeam Software. Use it at your own risk.**

Made with ❤️, fueled by 🍺, and powered by the **Veeam Data Integration API**.
Inspired by real-world needs, supported by a bit of AI.
