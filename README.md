![tor-browser-ui](https://github.com/user-attachments/assets/0ffc9155-8ada-4757-83e5-8de0728617ef)

# Threat Hunt Report: Unauthorized TOR Usage (S0183)
- [Scenario Creation](https://github.com/churd-git/Threat-Hunting-Scenario-Tor/blob/main/Threat-Hunting-Scenario-Tor-Event-Creation)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "interncr" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-01-06T20:16:59.480414Z`. These events began at `2025-01-06T20:05:30.4441741Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName contains "windowsvm-mde"
| where FileName contains "tor"
| where InitiatingProcessAccountName == "interncr"
| where Timestamp >= datetime(2025-01-06T20:05:30.4441741Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![Screenshot 2025-01-07 at 12 11 10 PM](https://github.com/user-attachments/assets/a86114aa-7ae7-4f6b-8de6-d2f67d759ba3)

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.3.exe". Based on the logs returned, at `2025-01-06T20:07:56.4147182Z`, an employee on the "windowsvm-mde-c" device ran the file `tor-browser-windows-x86_64-portable-14.0.3.exe` from their Desktop folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName contains "windowsvm-mde"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.3.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![Screenshot 2025-01-07 at 12 15 37 PM](https://github.com/user-attachments/assets/f631cce3-ba3a-421b-b3ff-fb65706f4604)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "interncr" actually opened the TOR browser. There was evidence that they did open it at `2025-01-06T20:08:54.2456469Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName contains "windowsvm-mde"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
![Screenshot 2025-01-07 at 12 19 19 PM](https://github.com/user-attachments/assets/65ed1cb9-d6d3-4516-80b4-9df16c9d00c1)

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-01-06T20:09:32.1224911Z`, an employee on the "windowsvm-mde-c" device successfully established a connection to the remote IP address `51.222.136.218` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\interncr\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName contains "windowsvm-mde"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe","firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150","443","80")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
```
![Screenshot 2025-01-07 at 12 23 42 PM](https://github.com/user-attachments/assets/a37c6afd-72c7-45a6-afef-be4588552da1)

---

## Chronological Timeline Report: Tor Browser Usage Incident

---

### 1. Tor Browser Download Initiated
- **Timestamp:** 2025-01-06T20:05:30.4441741Z  
- **Device:** `windowsvm-mde-c`  
- **User:** `interncr`  
- **Action:** File Created  
- **File:** `tor-browser-windows-x86_64-portable-14.0.3.exe`  
- **Folder Path:** `C:\Users\InternCR\Desktop`  

**Event:**  
The user downloaded the Tor browser installer, `tor-browser-windows-x86_64-portable-14.0.3.exe`, from an unknown source to their desktop. This file is the main executable used to set up a portable version of the Tor browser, suggesting that the user intentionally initiated this activity to use Tor.

---

### 2. Silent Installation Executed
- **Timestamp:** 2025-01-06T20:07:56.0000000Z  
- **Device:** `windowsvm-mde-c`  
- **User:** `interncr`  
- **Action:** Process Created  
- **Process Command Line:** `"tor-browser-windows-x86_64-portable-14.0.3.exe" /S`  
- **Folder Path:** `C:\Users\InternCR\Desktop\tor-browser-windows-x86_64-portable-14.0.3.exe`  

**Event:**  
The user executed the downloaded Tor browser installer in silent mode, as indicated by the `/S` flag in the process command line. This mode bypasses standard installation prompts, allowing the program to install or configure itself without user interaction. This behavior is typical for users aiming to install software quickly or avoid drawing attention.

---

### 3. Tor Browser Launched
- **Timestamp:** 2025-01-06T20:08:54.2456469Z  
- **Device:** `windowsvm-mde-c`  
- **User:** `interncr`  
- **Action:** Process Created  
- **Process Command Line:** `"firefox.exe" -contentproc --channel=XYZ`  
- **Folder Path:** `C:\Users\InternCR\Desktop\Tor Browser\Browser\firefox.exe`  

**Event:**  
The user launched the Tor browser shortly after installation. The Tor browser uses a modified version of Firefox to facilitate anonymous browsing through the Tor network. This event marks the beginning of Tor usage on the device, indicating the user’s intent to browse anonymously or access restricted content.

---

### 4. Tor Network Connection Established
- **Timestamp:** 2025-01-06T20:09:32.0000000Z  
- **Device:** `windowsvm-mde-c`  
- **User:** `interncr`  
- **Action:** Network Connection Success  
- **Initiating Process:** `tor.exe`  
- **Folder Path:** `C:\Users\InternCR\Desktop\Tor Browser\Browser\TorBrowser\Tor`  
- **Remote IP:** `51.222.136.218`  
- **Remote Port:** `9001`  

**Event:**  
The Tor browser successfully established a connection to the Tor network via a remote Tor node. This connection to the IP address `51.222.136.218` over port `9001` demonstrates that the browser is functioning correctly and actively routing traffic through the Tor network. This is a critical step for anonymizing online activities.

---

### 5. Tor-Related Files Created
- **Timestamp:** 2025-01-06T20:16:59.480414Z  
- **Device:** `windowsvm-mde-c`  
- **User:** `interncr`  
- **Action:** File Created  
- **File:** `tor-shopping-list.txt`  
- **Folder Path:** `C:\Users\InternCR\Desktop\Tor-Shopping-List.txt`  

**Event:**  
A file named `tor-shopping-list.txt` was created on the user’s desktop. While the exact contents of the file are not available, its name and location suggest it may have been created intentionally by the user or automatically by the Tor browser. This file could potentially include notes or other information related to activities conducted using the Tor browser.

---

## Summary

On January 6, 2025, the user interncr on device windowsvm-mde-c downloaded and installed the Tor browser. The installer was executed in silent mode, likely to expedite the process or avoid user prompts. Shortly after installation, the Tor browser was launched, and a successful connection to the Tor network was established via a known Tor node. Tor-related files were created, including a potentially user-generated file named tor-shopping-list.txt. These actions indicate deliberate use of the Tor browser for anonymous browsing or other potentially sensitive activities. Further review of logs and the file contents is recommended to determine the purpose and impact of these actions.

---

## Response Taken

TOR usage was confirmed on the endpoint `windowsvm-mde-c` by the user `interncr`. The device was isolated, and the user's direct manager was notified.

---

## Created By:
- **Author Name**: Carlton Hurd
- **Author Contact**: https://www.linkedin.com/in/carlton-hurd-6069a5120/
- **Date**: January 29th, 2025

## Validated By:
- **Reviewer Name**: Carlton Hurd
- **Reviewer Contact**: 
- **Validation Date**: January 29th, 2025 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `January  29th, 2025`  | `Carlton Hurd`   
