# WINDOWS FORENSICS V1
## Solution Overview:
The purpose of this script is to extract Windows forensic data from a potentially compromised Endpoint. The data extracted will give security personel insight into any malicious activities taking place on the host or hosts in question. Time is of the essense when it comes to potential compromises, this provides one with the ability to get quality information quickly.

### Usage and Deployment: 
Minimal preparation is required in order to run this script, however there are a few conditions that should be met:
1. The target machine should allow for the execution of scripts. In a corporate environment the powershell execution policy should be set to only allow scripts to run if they are signed by your organization. 
2. Powershell should be installed on the target machine (Installed by default)
3. Powershell should be run as an admin user for best results

Once these conditions are met, the script should have the permissions needed to function. 

In an ideal setting, this script would have the capability to be run remotely from SIEM/SOAR like solution. Some of these tools allow for custom scripts to be executed on a target host upon the appearance of specific alerts that are deemed suspicious enough to merit investigation.

### Functionality:
The script works as follows:
1. The script first defines a few key Input/Output directories for later use. Namely, the results destination directory, the registry folder, and instantiates an empty hashmap of 'Users'
2. The script checks for the existance of the base and registry folders. If they exist the execution continues, otherwise they are created.
3. Next the users in the C:\Users folder are enumerated and written to the terminal as output and to a Windows log file in the base directory.
4. Next the script attempts to push all NTUSER.DAT files to the base directory. NTUSER.DAT files hold the personal configuration settings of each user. Every user has their own NTUSER.DAT file and is valuable information to have in the event of a compromise.
5. Next the system registries are copied to the base directory. These registries are arguably the most important pieces of information to have in the event of a breach. Often times malware will overwrite or modify registry values in windows. Windows registry is the hierarchical database that holds the low-level settings for the Windows operating system.
6. Next the windows event logs are copied to the base directory. These inculde records of events that have taken place on the host and will likely include valuable evidence in the case of a legitimate breach.
7. The script then checks for common browsers installed on the system for each user. Where these browsers exist for each user, the browsing data, profile settings, tabs, etc. are gathered and aggregated in the base directory.

# WINDOWS FORENSICS V2 (Additions to V1)
### Added Functionality:
1. *** Functionality Added *** This script now extracts powershell event logs to the base directory for analysis. Powershell is a powerful tool that integrates into windows. It is useful for system administration and other legitimate purposes, but also doubles as a powerful hacking tool. Seeing these logs is valuable in the case of a compromised host. Often times malicious activity will show up here.
2. *** Functionality Added *** This script now pulls a lot of relevant system information at the beginning of the script including hardware information, Windows version, and Timezone.
3. *** Functionality Added *** This script now pulls `Established` and `Listen` network connections on the device
4. *** Functionality Added *** This script now copies the Amcache database and the System Resource Usage database

### Proof of Concept (Iteration #1):
Terminal output from script...
![Terminal Output](/POC.png)
Populated directory after execution...
![Base Directory](/BaseDirectory.png)

### Proof of Concept (Iteration #2):
Terminal output showing the extraction of Powershell log events...
![Terminal Output](/POC2.png)

Termial output of system information...

![System Information](/POC2-sysinfo.png)

Terminal output of network connections...

![Network Information](/POC2-netinfo.png)

Base Directory with added logging ad zip file for easy and fast extraction...
![Base Directory with added logging ad zip file for extraction](/BaseDirectoryIteration2.png)

### Proof of Concept (Iteration #3):

