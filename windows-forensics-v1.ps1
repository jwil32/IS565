# Gather Windows Forensics Artifacts v1

$BaseDir = "C:\Windows\Temp\investigate"
$RegistryFolder = "$BaseDir\registries"
$LogFile = "$BaseDir\log.txt"
$Users = @{}
$Spacer = "---------------------------------------------------------------"

# Create the main folders if they do not already exist
if (!(Test-Path $BaseDir)){
    New-Item -ItemType Directory -Path $BaseDir | Out-Null
}

if (!(Test-Path $RegistryFolder)){
    New-Item -ItemType Directory -Path $RegistryFolder | Out-Null
}

# Create the logfile
Out-File -FilePath $LogFile -NoNewline

# Get usernames of users on this computer
Get-ChildItem 'C:\Users\' | ForEach-Object {
    # Write-Output $_.FullName
    if ($_.Name -ne "Public"){
        $Users.$($_.Name) = $_.FullName
    }
}
Write-Output $Users

# Writes to the console and the logfile simultaneously
Tee-Object -InputObject "`nBase Directory: $($BaseDir)" -FilePath $LogFile -Append

# Check what users are logged in
Tee-Object -InputObject "The following users are currently logged in:" -FilePath $LogFile -Append
quser | Tee-Object -FilePath $LogFile -Append

# TODO: Make sure to gather up the bits of the registry that need to be rolled into the main registry files
# Does this apply to users that are signed out? Is everything autmatically rolled into the main registry file when they log out?

# Handle Dirty hives: https://cybermeisam.medium.com/blue-team-system-live-analysis-part-11-windows-user-account-forensics-ntuser-dat-495ab41393db

# Get NTUSER.dats for each real user
# You can't copy files in that are currently in use by the system or a 
# logged in user so the built-in tool 'reg' has to be used to export the registries

Tee-Object -InputObject "`nAttempting to copy NTUSER.DAT files...`n$($Spacer)" -FilePath $LogFile -Append

foreach ($User in $Users.Keys) {
    # Get each user's SID to export that user's NTUSER.DAT file using 'reg'.
    $SID = (Get-LocalUser -Name $User).SID.Value
    
    if (!(Test-Path "$RegistryFolder\$User")){
        New-Item -ItemType Directory -Path "$RegistryFolder\$User" | Out-Null
    }
    
    try {
        reg save "HKU\$SID" "$RegistryFolder\$User\NTUSER.DAT" /y | Out-Null
        Tee-Object -InputObject "[+] Copied HKU\$($SID) ($User) to $RegistryFolder\$User\NTUSER.DAT" -FilePath $LogFile -Append
    }
    catch {
        Tee-Object -InputObject "[-] Could not save a copy of HKU\$($SID)" -FilePath $LogFile -Append
    }
}

# Get the system registries
$systemRegistries = @("sam","system", "security", "software")

Tee-Object -InputObject "`nAttempting to copy System Registry files...`n$($Spacer)" -FilePath $LogFile -Append

$systemRegistries | ForEach-Object {
    try {
        reg save "HKLM\$($_)" "$RegistryFolder\$($_).hiv" /y | Out-Null
        Tee-Object -InputObject "[+] Copied $($_) log to $($RegistryFolder)\$($_).hiv" -FilePath $LogFile -Append
    } catch {
        Tee-Object -InputObject "[-] Could not save $($_)" -FilePath $LogFile -Append
    }
}

# # Get the event logs
Tee-Object -InputObject "`nGathering Event Logs...`n$($Spacer)" -FilePath $LogFile -Append

$logs = @("Security", "System", "Application")

$logs | ForEach-Object {
    try {
        wevtutil.exe export-log $_ "$($BaseDir)\$($_).evtx" /ow
        Tee-Object -InputObject "[+] Copied $($_) log to $($BaseDir)\$($_).evtx" -FilePath $LogFile -Append
    } catch{
        Tee-Object -InputObject "[-] Error retrieving the $($_) log" -FilePath $LogFile -Append
    }
}

# Discover installed browsers by checking if registry keys exist for common browsers
Tee-Object -InputObject "`nChecking for browsers...`n$($Spacer)" -FilePath $LogFile -Append

$Browsers = @{
    'Google Chrome' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe';
    'Microsoft Edge' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe';
    'Mozilla Firefox' = 'HKLM:\SOFTWARE\Mozilla\Mozilla Firefox'
}

foreach($Browser in $Browsers.Keys){
    # Get the value of the registry key listed for the browser
    $BrowserPath = Get-ItemPropertyValue $Browsers.$Browser '(default)' 2>$null

    # If this value is null, then the registry key does not exist and the browser is not installed
    if ($null -eq $BrowserPath){
        Tee-Object -InputObject "[-] $($Browser) was not found" -FilePath $LogFile -Append
    } else {
        $BrowserVersion = $BrowserPath
        # Firefox stores the version number as the default key value, so no need to do fancy stuff to get it.
        if ($Browser -ne 'Mozilla Firefox'){
            $BrowserVersion = (Get-Item($BrowserPath)).VersionInfo.ProductVersion
        }
        Tee-Object -InputObject "[+] $($Browser) $($BrowserVersion) was found" -FilePath $LogFile -Append
    }
}

# Gather the data files from each of the browsers
Tee-Object -InputObject "`nGathering browser data files...`n$($Spacer)" -FilePath $LogFile -Append

# List of important files created by each browser
$BrowsersInfo = @{
    "Google Chrome" = @{
        "Destination" = "$BaseDir\chrome"
        "DefaultPath" = "C:\Users\<USERNAME>\AppData\Local\Google\Chrome\User Data"
        "Files" = @("History", "Web Data", "Login Data", "Shortcuts", "Visited Links")
    };
    "Microsoft Edge" = @{
        "Destination" = "$BaseDir\edge"
        "DefaultPath" = "C:\Users\<USERNAME>\AppData\Local\Microsoft\Edge\User Data"
        "Files" = @("History", "Web Data", "Login Data", "Shortcuts", "Visited Links")
    };
    "Mozilla Firefox" = @{
        "Destination" = "$BaseDir\firefox"
        "DefaultPath" = "C:\Users\<USERNAME>\AppData\Roaming\Mozilla\Firefox\Profiles"
        "Files" = @("places.sqlite", "cookies.sqlite", "formhistory.sqlite", "key4.db", "logins.json")
    };
}

# Get the data from all the browsers
# Yes, this is a quadruple nested for-loop... not great, I know

foreach ($User in $Users.Keys) {
    # Set the file path with the right username. Use a local array to store the temp info for each user
    $CustomBrowserInfo = @{}
    
    # Replace the <USERNAME> placeholder in the local array with the username
    foreach ($Browser in $BrowsersInfo.Keys){
        Tee-Object -InputObject "[+] $($Browser) (Username: $($User))" -FilePath $LogFile -Append
        # Clone the sub array from the browser info array to create a seperate copy and not change the original
        # Copying the whole $browersinfo array only makes references to the sub arrays, so any data changed locally will reflect in the master array
        $CustomBrowserInfo.$Browser = $BrowsersInfo.$Browser.Clone()
        $CustomBrowserInfo.$Browser.DefaultPath = $BrowsersInfo.$Browser.DefaultPath.replace('<USERNAME>', $User)

        if(!(Test-Path "$($CustomBrowserInfo.$Browser.DefaultPath)")){
            continue
        }

        # Add the username to the destination
        $CustomBrowserInfo.$Browser.Destination = "$($BrowsersInfo.$Browser.Destination)\$User"

        # Check to see if the user actually has the directory where the browser data is stored
        # It's possible the user hasn't used this browser yet and no files exist for it
        foreach ($Folder in (Get-ChildItem $CustomBrowserInfo.$Browser.DefaultPath)){
            $CurrentPath = "$($CustomBrowserInfo.$Browser.DefaultPath)\$Folder"
            $FinalPath = "$($CustomBrowserInfo.$Browser.Destination)\$Folder"

            if(Test-Path $CurrentPath){
                # Copy all the files over to the destination
                foreach ($File in $CustomBrowserInfo.$Browser.Files){
                    if(Test-Path "$($CurrentPath)\$File"){
                        # Create the proper file paths: firefox/username
                        if (!(Test-Path $FinalPath)){
                            New-Item -ItemType Directory -Path $FinalPath | Out-Null
                        }
                        try {
                            Copy-Item "$CurrentPath\$File" $FinalPath
                            Tee-Object -InputObject "`t[+] Copied $($File) to $($FinalPath)" -FilePath $LogFile -Append
                        } catch {
                            Tee-Object -InputObject "`t[-] Could not retrieve $($File)" -FilePath $LogFile -Append
                        }
                    }
                }
            }
        }
    }
}

# Put all the files in $BaseDir into a zip file for easy extraction
Compress-Archive -Path "$BaseDir\*" -DestinationPath "$BaseDir\extractme.zip"

# Delete all the other files except the zip file?? Probably should clean up.
