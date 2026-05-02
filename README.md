# threat-hunting

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/TheSunnyDev/adversary-emulation-telemetry/blob/main/emulate-tor-traffic-telemetry.md)
- [Tor Threat Hunt Timeline Report](https://github.com/TheSunnyDev/adversary-emulation-telemetry/blob/main/Tor%20Threat%20Hunt%20Timeline%20Report.pdf)
- [Tor Threat Hunt Timeline Report (PDF)](https://github.com/user-attachments/files/27294750/Tor.Threat.Hunt.Timeline.Report.pdf) 

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

Searched for any file that had the string "tor" in it and discovered what looks like the user "thesunnydev" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor.txt` on the desktop. These events began at `2026-04-13T12:39:42.4871519Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "thesunnydev"
| where InitiatingProcessAccountName == "thesunnydev"
| where FileName contains "tor"
| order by Timestamp desc
| where Timestamp >= datetime(2026-04-13T12:39:42.4871519Z)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

<img width="1094" height="487" alt="Screenshot 2026-05-01 at 6 27 54 PM" src="https://github.com/user-attachments/assets/9adfa9c0-61b4-4880-ad65-ebadd54685c6" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2026-04-13T12:41:39.0300353Z`, an employee on the "thesunnydev" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "thesunnydev"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.9.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

<img width="1094" height="487" alt="Screenshot 2026-05-01 at 6 29 36 PM" src="https://github.com/user-attachments/assets/901b767b-0b0b-4be4-acd0-a86cbfbd0a85" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "thesunnydev" actually opened the TOR browser. There was evidence that they did open it at `2026-04-13T12:42:09.7307538Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "thesunnydev"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1158" height="474" alt="Screenshot 2026-05-01 at 6 31 43 PM" src="https://github.com/user-attachments/assets/1b453a43-14c4-475b-a346-bbf2ce1bcdf0" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-04-13T12:42:17.6318709Z`, an employee on the "thesunnydev" device successfully established a connection to the remote IP address `37.114.50.124` on port `9001`. The connection was initiated by the process `tor.exe`. Port 9001 is commonly associated with Tor relay (ORPort) communication, which is used for routing encrypted traffic between nodes within the Tor anonymity network. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "thesunnydev"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9050", "9150", "9051", "9151", "9001", "9030", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```

<img width="1567" height="375" alt="Screenshot 2026-05-01 at 6 24 19 PM" src="https://github.com/user-attachments/assets/9681f317-da2b-4065-a7e9-e75b3be94399" />




---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-04-13T12:39:42.4871519Z`
- **Event:** The user "thesunnydev" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\thesunnydev\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-04-13T12:41:39.0300353Z`
- **Event:** The user "thesunnydev" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\thesunnydev\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-04-13T12:42:09.7307538Z`
- **Event:** User "thesunnydev" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\thesunnydev\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-04-13T12:42:17.6318709Z`
- **Event:** A network connection to IP `37.114.50.124` on port `9001` by user "thesunnydev" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\thesunnydev\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-04-13T12:43:21.0179937Z` - Connected to `192.42.116.32` on port `443`.
  - `2026-04-13T12:42:41.2559547Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "thesunnydev" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-04-17T17:46:50.1340954Z`
- **Event:** The user "thesunnydev" created a text file named `tor.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\thesunnydev\Desktop\tor.txt`

---

## Summary

The user "thesunnydev" on the "thesunnydev" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes.

---

## Response Taken

TOR usage was confirmed on the endpoint `thesunnydev` by the user `thesunnydev`. The device was isolated, and the user's direct manager was notified.

---













