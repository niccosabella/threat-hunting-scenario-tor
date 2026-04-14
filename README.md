# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/niccosabella/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

Searched the DeviceFileEvent table for ANY file that had the string “tor” in it and discovered what looks like the user “niccosab” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor shopping.txt. On the desktop. These events began at: 2026-04-14T16:21:18.8969656Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where InitiatingProcessAccountName == "niccosab"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-04-14T16:21:18.8969656Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1436" height="755" alt="image" src="https://github.com/user-attachments/assets/94937f11-f11a-4fe9-80a9-ff2267395c97" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-15.0.9.exe”. Based on the logs returned, at 12:21:41 PM on April 14, 2026. User “niccosab” on the “nicco-threat-hu” device ran the file tor-browser-windows-x86_64-portable-15.0.9.exe from their Downloads folders, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName contains "nicco"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.9.exe"
| project Timestamp, DeviceName,AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1616" height="179" alt="image" src="https://github.com/user-attachments/assets/9d072cf8-5c1a-4267-ad96-8da614df3605" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “niccosab” actually opened the tor browser. There was evidence they did open it at 2026-04-14T16:22:11.4988217Z. There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName contains "nicco"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName,AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1592" height="684" alt="image" src="https://github.com/user-attachments/assets/88bb6a17-fa9a-482a-8577-7187030f86ed" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using of the known tor ports. At 2026-04-14T17:40:57.9895011Z, someone using the “nicco-threat-hu” device successfully established a connection to the remote IP address 5.255.127.222 on port 9001. The connection was initiated by the process tor.exe, located in the folder c:\users\niccosab\desktop\tor browser\browser\torbrowser\tor\tor.exe. There were a few other events.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName contains "nicco"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp
```
<img width="1622" height="365" alt="image" src="https://github.com/user-attachments/assets/33f7e772-6c09-4e7c-9adc-25b9581a7e47" />

---

## Chronological Event Timeline 

### 12:21:41 PM  
**User niccosab executed the Tor installer**

- File: `tor-browser-windows-x86_64-portable-15.0.9.exe`  
- Location: Downloads folder  
- Behavior: Command line indicates silent installation  
- Source: DeviceProcessEvents  

**What this means**

- The user intentionally launched the installer with minimal prompts or visibility.  

---

### 12:21:18 PM onward  
**Initial Tor-related file activity begins**

- Multiple files containing "tor" created or copied  
- Files placed on Desktop  
- Notable artifact: `tor shopping.txt` created  
- Source: DeviceFileEvents  

**What this means**

- Installation extracted files or user manually moved them.  
- The text file suggests user interaction after install.  

---

### 12:22:11 PM  
**Tor browser execution confirmed**

- Processes observed:  
  - `tor-browser.exe`  
  - `firefox.exe` (Tor-based browser)  
  - `tor.exe`  
- Source: DeviceProcessEvents  

**What this means**

- User successfully launched Tor Browser.  
- Tor runtime components started correctly.  

---

### 12:22 PM – 5:40 PM  
**Ongoing Tor process activity**

- Repeated spawning of:  
  - `tor.exe`  
  - `firefox.exe`  
- Indicates continued or repeated usage sessions  

**What this means**

- Tor remained active or was reopened multiple times.  

---

### 5:40:57 PM  
**Outbound Tor network connection established**

- Remote IP: `5.255.127.222`  
- Port: `9001` (Tor relay port)  
- Process: `tor.exe`  
- Path:  
  `C:\Users\niccosab\Desktop\tor browser\Browser\TorBrowser\Tor\tor.exe`  
- Source: DeviceNetworkEvents  

**What this means**

- Device connected to the Tor network through a relay node.  
- Port 9001 confirms standard Tor routing behavior.  

---

### Additional Network Activity  
**Other Tor-related connections observed**

- Ports:  
  - `9001`, `9030` (relay and directory)  
  - `9050`, `9150` (SOCKS proxy)  
  - `80`, `443` (web traffic through Tor)  

**What this means**

- Traffic routed through the Tor network successfully.  
- Activity matches normal Tor browsing behavior.  

---

## Summary

The user **niccosab** downloaded and executed a portable Tor browser installer on April 14, 2026. The installer ran using a command that indicates a silent installation, which reduced user prompts and visibility during setup. After execution, Tor-related files were created and copied to the user’s Desktop instead of a standard installation directory.

Shortly after installation, the user manually interacted with the files. Evidence shows the creation of a text file named `tor shopping.txt` on the Desktop. Within about 30 seconds of running the installer, the Tor browser launched successfully. Process activity confirms that core components such as `tor.exe` and the Tor-based `firefox.exe` browser started and continued running, which shows active usage.

Network logs show that the device established outbound connections to known Tor relay infrastructure. A confirmed connection was made to a remote IP address over port `9001`, which is commonly used for Tor relay communication. Additional connections over standard Tor-related ports further confirm that traffic routed through the Tor network.

---

## Response Taken

TOR usage was confirmed on the endpoint nicco-threat-hu by the user niccosab. The device was isolated and the user's direct manager was notified.

---
