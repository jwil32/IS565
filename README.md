# WINDOWS FORENSICS V1
## Solution Overview:
The purpose of this script is to extract Windows forensic data from a potentially compromised Endpoint. The data extracted will give security personel insight into any malicious activities taking place on the host or hosts in question. Time is of the essense when it comes to potential compromises, this provides one with the ability to get quality information quickly.

## Usage and Deployment: 
Minimal preparation is required in order to run this script, however there are a few conditions that should be met:
1. The target machine should allow for the execution of scripts. In a corporate environment the powershell execution policy should be set to only allow scripts to run if they are signed by your organization. 
2. Powershell should be installed on the target machine (Installed by default)
3. Powershell should be run as an admin user for best results

Once these conditions are met, the script should have the permissions needed to function. 