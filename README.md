<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage (S0183)
- [Scenario Creation](https://github.com/usman-affan23/tor-usage/blob/main/tor-usage-scenario-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
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

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it, and discovered what looks like the user “labuser” downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called “tor-shopping-list.txt”. These events began at: `2025-12-06T19:49:18.5275428Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName == "labuser"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-12-06T19:49:18.5275428Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1920" height="646" alt="tor-1" src="https://github.com/user-attachments/assets/82fab13e-eec2-4592-bedf-0ac267bf09b9" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the `DeviceProcessEvents` table for any `ProcessCommandLine` that contained the string “tor-browser-windows-x86_64-portable-15.0.2.exe”. Based on the logs returned, at `2025-12-06T19:49:40.0345453Z`, an employee on the “threat-hunt-lab” device ran the file `tor-browser-windows-x86_64-portable-15.0.2.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName contains "threat-hunt-lab"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.2.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
<img width="1920" height="200" alt="tor-2" src="https://github.com/user-attachments/assets/1edd156a-06b5-4094-871a-67b93e14b521" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user “labuser” actually opened the TOR browser. There was evidence that they did open it at `2025-12-06T19:53:04.6387398Z`. There were several other instances of `firefox.exe` (TOR), as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName contains "threat-hunt-lab"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1460" height="798" alt="tor-3" src="https://github.com/user-attachments/assets/d25af5cb-d037-40d5-9c65-f108b90e579a" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-12-06T19:54:10.767636Z`, an employee on the “threat-hunt-lab” device successfully established a connection to the remote IP address `37.218.242.26` on port `9001`. The connection was initiated by the process tor.exe, located in the folder `c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over the same port.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName contains "threat-hunt-lab"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1624" height="279" alt="tor-4" src="https://github.com/user-attachments/assets/72cf1098-92b1-426f-99b8-ede758a5a440" />


---

## Chronological Timeline Report: Tor Browser Usage Incident

---

1. Initial TOR File Activity Detected – 19:49:18 UTC

At 19:49:18.5275428 UTC, file events on threat-hunt-lab indicate that the user labuser interacted with multiple files containing the string “tor”. Logs show a TOR installer was downloaded, followed by rapid creation and copying of TOR-related files to the user’s desktop.

During this same window, a text file named “tor-shopping-list.txt” was created, suggesting the user may have saved notes or intentions related to TOR usage.

This marks the beginning of observable TOR-related activity on the device.

2. TOR Installer Executed Silently – 19:49:40 UTC

Approximately 22 seconds later, at 19:49:40.0345453 UTC, logs from DeviceProcessEvents confirm that labuser executed the installer tor-browser-windows-x86_64-portable-15.0.2.exe from their Downloads folder.

The command line used indicates a silent installation, meaning the installer ran without requiring user interaction or showing visible prompts.

This suggests deliberate execution, possibly with the intent to quickly deploy the TOR Browser without drawing attention.

3. TOR Browser Launched – 19:53:04 UTC

Roughly three minutes later, at 19:53:04.6387398 UTC, the user launched the TOR browser.

Process logs show firefox.exe (the TOR Browser frontend) and tor.exe (the TOR networking daemon) starting up, with additional instances appearing shortly afterward.

This confirms that the user not only installed TOR but also actively opened and used it.

4. TOR Network Connection Established – 19:54:10 UTC

At 19:54:10.767636 UTC, network telemetry captured the TOR client establishing a successful outbound connection to:

Remote IP: 37.218.242.26

Port: 9001 (a known TOR relay or bridge port)

The connection originated from the TOR executable located at:

c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe


Additional connections to other external systems over TOR-related ports were also observed soon afterward, indicating continued communication within the TOR network.

---

## MITRE ATT&CK Framework

| Observed Behavior                                       | MITRE Technique             | ID         |
|---------------------------------------------------------|------------------------------|------------|
| Downloading TOR portable installer                      | Ingress Tool Transfer        | T1105      |
| Executing TOR installer with silent parameters          | Command/Scripting Interpreter | T1059      |
| User running the TOR installer                          | User Execution               | T1204.002  |
| Launching tor.exe and firefox.exe                       | Native Binary Execution      | T1106      |
| TOR establishing outbound connection to 37.218.242.26:9001 | Proxy / Multi-hop Proxy      | T1090.003  |
| Encrypted TOR communications                            | Encrypted Channel            | T1573      |


---

---

## Summary

On December 6, 2025, the user labuser on the device threat-hunt-lab downloaded a TOR Browser installer and, within seconds, executed it using a silent installation command. Almost immediately after installation, TOR-related files appeared on the user’s desktop, including a text file named tor-shopping-list.txt, suggesting the user was preparing or organizing TOR usage. A few minutes later, the user launched the TOR Browser, triggering both firefox.exe and tor.exe processes. Shortly afterward, at 19:54 UTC, the TOR client successfully connected to an external TOR relay server at 37.218.242.26 over port 9001, confirming that TOR was fully operational and being used to establish anonymized, encrypted outbound communication.

---

## Response Taken

TOR usage was confirmed on endpoint “threat-hunt-lab” by the user “labuser”. The device was isolated through MDE, and the user’s direct manager was notified.

---

## Created By:
- **Author Name**: Usman Affan
- **Author Contact**: https://www.linkedin.com/in/muhammad-affan20/
- **Date**: December 6th, 2024

## Validated By:
- **Reviewer Name**: Usman Affan
- **Reviewer Contact**: 
- **Validation Date**: December 6th, 2025

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `December 6th, 2025`  | `Usman Affan`   
