<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/juliobread/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md) 

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

Searched the DeviceFileEvents for any file that had the string "tor” in it and discovered what looks like, the user “labuser” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop In the creation of a file called “tor-shopping-list” on the desktop. These events began at: '2025-02-28T04:18:26.9033631Z'

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName contains "tor"
| where DeviceName == "threathunting"
| where Timestamp >= datetime(2025-02-28T04:18:26.9033631Z)
| where InitiatingProcessAccountName == "labuser"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![image](https://github.com/user-attachments/assets/98a826f9-b1ad-4a8f-99ba-75de8dcfd740)

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string “tor-browser-windows”. Based on logs returned on 2025-02-28T04:18:26.9033631Z, the Tor Browser installer was silently installed on the 'threathunting' computer. This indicates a potential automated or hidden software installation, as the silent switch prevents typical user interaction during the installation process.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where ProcessCommandLine startswith "tor-browser-windows"
| where DeviceName == "threathunting"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/4e6b1957-a71f-4099-8551-747176cc2b03)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched DeviceProcessEvents table for any indication that user  “labuser” actually opened the Tor browser. There was evidence that they did open it at 2025-02-28T04:21:02.9603459Z. There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards.
**Query used to locate events:**

```kql
DeviceProcessEvents
| where FileName has_any("tor.exe","firefox.exe","tor-browser.exe")
| where DeviceName == "threathunting"
| project  Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine
|order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/2e14a2ab-a6a4-4a76-aafc-b93eda64bc40)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. At 2025-02-28T04:21:21.8465905Z a user named "labuser" on the computer called "threathunting" used the Firefox web browser to connect to the computer's own local address (127.0.0.1) on network port 9150. There were a couple other connections to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/8d309cf1-029b-4f7d-b305-0343a3ad8aa6)

---

## Chronological Event Timeline 

Here's a breakdown of the chronological events related to Tor Browser usage, observed on 2025-02-28:

1.  **Automated Tor Browser Installation and File Creation:**
    * The user "labuser" initiated the download and silent installation of the Tor Browser.
    * The installer was executed with the `/S` switch, suppressing the user interface.
    * Multiple Tor-related files were copied to the user's desktop.
    * A new file, "tor-shopping-list," was created.
    * This suggests an automated setup and preparation for Tor Browser use.
    * *Timestamp:* `2025-02-28 04:18:26.9033631Z` - Event: File Creation/Copy - Action: Tor Browser installer downloaded and executed, Tor-related files copied to the desktop, and “tor-shopping-list” file created.

2.  **Tor Browser Launch and Process Spawning:**
    * Shortly after installation, "labuser" launched the Tor Browser application (firefox.exe).
    * Multiple instances of "firefox.exe" and "tor.exe" were spawned, indicating active use.
    * *Timestamp:* `2025-02-28 04:21:02.9603459Z` - Event: Process Creation - Action: Tor Browser (firefox.exe) launched
    * Following this timestamp, multiple process creation events occurred.

3.  **Tor Network Connection and Web Traffic:**
    * "labuser" established a network connection to the local loopback address (127.0.0.1) on port 9150.
    * This is the standard port for Tor Browser's local proxy communication.
    * Connections were also made to remote web servers over port 443 (HTTPS).
    * These connections confirm active routing of web traffic through the Tor network.
    * *Timestamp:* `2025-02-28 04:21:21.8465905Z` - Event: Network Connection - Action: Firefox (Tor Browser) connected to 127.0.0.1:9150
    * Following this timestamp, multiple network connections to remote sites over port 443 occurred.
    
---

## Summary

The user "labuser" on the "threathunting" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threathunting` by the user `labuser`. The device was isolated, and the user's direct manager was notified.

---
