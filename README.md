# Microsoft 365 Security Posture Scorer
 
A PowerShell script that pulls every security control from Microsoft Secure Score via the Graph API, runs them through a custom weighted scoring engine mapped to NIST CSF and CIS Benchmarks, and outputs an executive-ready posture report with a prioritized remediation backlog.
 
Microsoft's raw Secure Score treats all points equally. This doesn't. A 1-point MFA control is not the same risk as a 3-point SharePoint sharing setting. This script re-ranks everything by category risk weight so you know what to actually fix first.
 
Completely read-only. Nothing in your tenant gets touched.
 
---
 
## What makes this different from just looking at Secure Score
 
| Microsoft Secure Score | This Script |
|------------------------|-------------|
| Raw points, all weighted equally | Risk-weighted score by category |
| No compliance framework mapping | Mapped to NIST CSF and CIS Benchmarks |
| No prioritization logic | Top 10 highest-impact quick wins ranked |
| Portal only | Exportable HTML report and CSV backlog |
| No posture grade | Letter grade A through F |
 
---
 
## How the weighted scoring works
 
Instead of treating every point equally, the script applies category weights based on real-world attack surface priority:
 
| Category | Weight | Why |
|----------|--------|-----|
| Identity | 35% | Number one attack vector — credential theft and account takeover |
| Device | 25% | Endpoint compromise leads directly to lateral movement |
| Data | 20% | Compliance exposure and data exfiltration risk |
| Apps | 12% | OAuth abuse and shadow IT |
| Infrastructure | 8% | Azure resource exposure |
 
Your weighted score out of 100 is a more honest picture of your actual risk posture than the raw Microsoft number.
 
---
 
## NIST CSF Mapping
 
Every control is mapped to one of the five NIST Cybersecurity Framework functions so you can see where you're strong and where you have gaps:
 
| NIST Function | What it means |
|---------------|---------------|
| Identify | Know what assets and risks you have |
| Protect | Controls that prevent attacks |
| Detect | Visibility into threats and anomalies |
| Respond | Incident response capability |
| Recover | Resilience and business continuity |
 
---
 
## CIS Benchmark Mapping
 
Controls are also mapped to CIS Critical Security Controls by category:
 
| Category | CIS Mapping |
|----------|------------|
| Identity | CIS Control 6 - Access Control Management |
| Device | CIS Control 4 - Secure Configuration / Control 10 - Malware Defense |
| Data | CIS Control 3 - Data Protection |
| Apps | CIS Control 16 - Application Software Security |
| Infrastructure | CIS Control 1 - Inventory and Control of Enterprise Assets |
 
---
 
## Output
 
- `M365-Posture-Report.html` — full dashboard with posture grade, weighted score, category breakdown with progress bars, NIST coverage, top 10 priority fixes, and all controls. Opens automatically in your browser.
- `M365-Posture-Report.csv` — complete remediation backlog sorted by priority score, ready to drop into a ticket system or share with a team.
---
 
## Posture Grades
 
| Weighted Score | Grade |
|----------------|-------|
| 85 and above | A - Strong |
| 70 to 84 | B - Good |
| 55 to 69 | C - Moderate |
| 40 to 54 | D - Weak |
| Below 40 | F - Critical |
 
---
 
## Requirements
 
- Windows PowerShell 5.1 or PowerShell 7+
- Microsoft Graph PowerShell SDK
- Entra ID account with Security Reader or Global Reader role
---
 
## Setup
 
### Step 1 — Install the NuGet package provider
 
Required before installing anything from PowerShell Gallery.
 
```powershell
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
```
 
### Step 2 — Trust PowerShell Gallery
 
One-time setting so you don't get the untrusted repository prompt.
 
```powershell
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
```
 
### Step 3 — Install the Microsoft Graph PowerShell SDK
 
Installs to your user profile only. No admin rights needed on the machine.
 
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```
 
Takes a few minutes. Let it run.
 
### Step 4 — Import the authentication module
 
```powershell
Import-Module Microsoft.Graph.Authentication
```
 
### Step 5 — Set execution policy
 
Allows local scripts to run without requiring a digital signature.
 
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```
 
---
 
## Connecting to the Graph API
 
The script uses these read-only permission scopes:
 
| Scope | What it reads |
|-------|--------------|
| `SecurityEvents.Read.All` | Secure Score data and control scores |
| `SecurityActions.Read.All` | Security improvement actions |
| `Policy.Read.All` | Tenant policy configurations |
| `Directory.Read.All` | Users, roles, and group memberships |
 
To connect manually before running:
 
```powershell
Connect-MgGraph -Scopes "SecurityEvents.Read.All", "SecurityActions.Read.All", "Policy.Read.All", "Directory.Read.All"
```
 
A browser window will open. Sign in with your work account and accept the permissions consent screen — all four scopes are read-only. PowerShell will confirm the connection once you close the tab.
 
> **Note:** If your organisation requires admin consent for Graph API permissions, a Global Admin needs to grant consent once. After that, any user with Security Reader can run the script without needing admin approval again.
 
---
 
## Running the script
 
Navigate to the folder where you saved `M365-Posture-Scorer.ps1`:
 
```powershell
cd C:\Users\YourName\Documents
```
 
Then run it:
 
```powershell
.\M365-Posture-Scorer.ps1
```
 
The script will:
1. Connect to Microsoft Graph (browser login if not already connected)
2. Pull your latest Secure Score and all control profiles
3. Cross-reference current scores against all controls
4. Apply category weights and calculate your weighted score
5. Map every control to NIST CSF and CIS Benchmarks
6. Rank controls by priority score to build your top 10 quick wins list
7. Print a summary in the terminal
8. Save the HTML report and CSV backlog to the current folder
9. Open the HTML report automatically in your browser
---
 
## What to expect in the terminal
 
```
[*] Connecting to Microsoft Graph (read-only scopes)...
[*] Pulling Microsoft Secure Score...
    Current Score: 142.45 / 228 (62.5%)
[*] Pulling all Secure Score control profiles...
    Found 97 control profiles.
[*] Pulling current control scores...
[*] Processing and scoring controls...
 
========================================
  MICROSOFT 365 SECURITY POSTURE REPORT
========================================
  Raw Microsoft Score : 142.45 / 228 (62.5%)
  Weighted Score      : 58.3 / 100
  Posture Grade       : C - Moderate
  Controls Evaluated  : 97
 
  TOP 10 PRIORITY FIXES:
  ...
 
[+] CSV saved: .\M365-Posture-Report.csv
[+] HTML report saved and opening: .\M365-Posture-Report.html
 
[DONE] Posture scoring complete.
```
 
---
 
## Troubleshooting
 
**"Cannot be loaded, not digitally signed"**
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass
```
 
**"Module could not be loaded"**
```powershell
Import-Module Microsoft.Graph.Authentication
```
Then retry the connect command.
 
**"Insufficient privileges" on Graph connect**
Your account needs at least the Security Reader role in Entra ID. Check under Identity > Roles and administrators in the Entra portal.
 
**Secure Score comes back empty**
Confirm your tenant has Microsoft Defender for Office 365 or Microsoft 365 E3/E5 licensing — Secure Score requires one of these to be active.
 
**Score looks lower than what the portal shows**
The weighted score will almost always differ from the raw Microsoft score — that's intentional. The weighted score reflects risk priority, not raw points.
 
---
 
## Is this safe to run in production?
 
Yes. All four Graph API scopes used are read-only. The script cannot create, modify, enable, disable, or delete any policy, user, setting, or configuration in your tenant. The only files it writes are the two report files saved locally on your machine.
 
Graph API read activity will appear in your Entra sign-in logs under your account as a normal read operation.
 
---
 
## Badges
 
![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue)
![Graph API](https://img.shields.io/badge/Microsoft%20Graph-v1.0-0078d4)
![NIST CSF](https://img.shields.io/badge/NIST-CSF%20Mapped-green)
![CIS](https://img.shields.io/badge/CIS-Benchmark%20Mapped-orange)
![Read Only](https://img.shields.io/badge/Tenant%20Impact-Read%20Only-brightgreen)
 
---
 
## Author
 
Roshan Tamang
www.linkedin.com/in/roshan-tamangg
