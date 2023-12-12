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

# Create the registry folder if it does not already exist
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

$computerName = $env:COMPUTERNAME
$operatingSystem = (Get-CimInstance Win32_OperatingSystem).Caption
$architecture = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
$systemDrive = (Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $env:SystemDrive }).Size / 1GB
$memory = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB
$cpuInfo = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name

Tee-Object -InputObject "`nSystem Information`n$Spacer" -FilePath $LogFile -Append
Tee-Object -InputObject "Hostname: $computerName" -FilePath $LogFile -Append
Tee-Object -InputObject "Operating System: $operatingSystem" -FilePath $LogFile -Append
Tee-Object -InputObject "System Architecture: $architecture" -FilePath $LogFile -Append
Tee-Object -InputObject "Main System Drive Size: $systemDrive GB" -FilePath $LogFile -Append
Tee-Object -InputObject "Total Physical Memory: $memory GB" -FilePath $LogFile -Append
Tee-Object -InputObject "CPU Information: $cpuInfo" -FilePath $LogFile -Append
Tee-Object -InputObject "System Date and Time: $(Get-Date)" -FilePath $LogFile -Append
Tee-Object -InputObject "System Timezone: $($(Get-TimeZone).DisplayName)" -FilePath $LogFile -Append

# TODO: Make sure to gather up the bits of the registry that need to be rolled into the main registry files
# Does this apply to users that are signed out? Is everything autmatically rolled into the main registry file when they log out?

# Handle Dirty hives: https://cybermeisam.medium.com/blue-team-system-live-analysis-part-11-windows-user-account-forensics-ntuser-dat-495ab41393db

# Get NTUSER.dats for each real user
# You can't copy files in that are currently in use by the system or a 
# logged in user so the built-in tool 'reg' has to be used to export the registries

Tee-Object -InputObject "`nData Collection Logs:" -FilePath $LogFile -Append

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

# Get the Recently Accessed Items
foreach ($User in $Users.Keys) {
    Tee-Object -InputObject "`nGathering Recent Files for all users...`n$($Spacer)" -FilePath $LogFile -Append
    try {
        Copy-Item -Path "C:\Users\$User\AppData\Roaming\Microsoft\Windows\Recent\*" -Destination "$BaseDir\recent files\$User" -Recurse -Force | Out-Null
        Tee-Object -InputObject "[+] $($User)" -FilePath $LogFile -Append
    }
    catch {
        Tee-Object -InputObject "[-] Could not retrieve Recent Files for $($User)" -FilePath $LogFile -Append
    }
}

# Get the System Resource Usage Monitor
Tee-Object -InputObject "`nGathering System Resource Usage Monitor...`n$($Spacer)" -FilePath $LogFile -Append
try {
    Copy-Item -Path "C:\Windows\System32\sru\SRUDB.dat" -Destination "$BaseDir\SRUDB.dat" -Force | Out-Null
    Tee-Object -InputObject "[+] SRUDB.dat" -FilePath $LogFile -Append
}
catch {
    Tee-Object -InputObject "[-] Could not retrieve SRUDB.dat" -FilePath $LogFile -Append
}

# Get the Amcache.hve file
Tee-Object -InputObject "`nGathering Amcache.hve...`n$($Spacer)" -FilePath $LogFile -Append
try {
    Copy-Item -Path "C:\Windows\AppCompat\Programs\Amcache.hve" -Destination "$BaseDir\Amcache.hve" -Force | Out-Null
    Tee-Object -InputObject "[+] Amcache.hve" -FilePath $LogFile -Append
}
catch {
    Tee-Object -InputObject "[-] Could not retrieve Amcache.hve" -FilePath $LogFile -Append
}

# Active web connections
Tee-Object -InputObject "`nGetting Established Web Connections...`n$($Spacer)" -FilePath $LogFile -Append
Tee-Object -InputObject "$(Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' } | Format-Table -AutoSize | Out-String)" -FilePath $LogFile -Append

Tee-Object -InputObject "`nGetting Local Listening Connections...`n$($Spacer)" -FilePath $LogFile -Append
Tee-Object -InputObject "$(Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' } | Format-Table -AutoSize | Out-String)" -FilePath $LogFile -Append

# Function to create html document
function ConvertToHTML {
    param (
        [string]$inputFilePath = "log.txt",
        [string]$outputFilePath = "output.html"
    )

    # Read contents of the input file
    $content = Get-Content -Path $inputFilePath -Raw

    # Define the CSS for styling the HTML
    $style = @"
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 40px;
        }
        h1 {
            color: #333;
        }
        pre {
            background-color: #f4f4f4;
            padding: 20px;
            overflow: auto;
        }
        .section {
            margin-top: 20px;
            margin-bottom: 20px;
        }
        .subsection {
            margin-top: 10px;
            margin-bottom: 10px;
        }
        .success {
            color: green;
            font-weight: bold;
        }
        .failure {
            color: red;
            font-weight: bold;
        }
        table {
            border-collapse: collapse;
            width: 100%;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
    </style>
"@

    # Create the HTML structure
    $sysinfo = $($($content -split '---------------------------------------------------------------')[1] -split 'Data')[0]
    $datalogs = $($content -split 'Data Collection Logs:')[1]
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Log File</title>
    $style
</head>
<body>
    <h1>Investigation Log</h1>
    <div class="section">
        <h2>Base Directory</h2>
        <p>C:\Windows\Temp\investigate</p>
    </div>
    <div class="section">
        <h2>System Information</h2>
        <p>$($sysinfo -replace '\n', '</br>')</p>
    </div>
    <div class="section">
        <h2>Data Extraction Logs</h2>
        <pre>$datalogs</pre>
    <!-- Add more sections for different parts of the log as needed -->
</body>
</html>
"@

    # Write HTML content to a new file
    $html | Out-File -FilePath $outputFilePath -Encoding UTF8

    Write-Host "HTML file '$outputFilePath' created successfully!"
}

# Create the report
ConvertToHTML -inputFilePath "C:\Windows\Temp\investigate\log.txt" -outputFilePath "C:\Windows\Temp\investigate\Report.html"

# Put all the files in $BaseDir into a zip file for easy extraction
Compress-Archive -Path "$BaseDir\*" -DestinationPath "$BaseDir\extractme.zip" -Force

# Delete all the other files except the zip file
Tee-Object -InputObject "`nCleaning up...`n$($Spacer)" -FilePath $LogFile -Append
Get-ChildItem $BaseDir | Where-Object {$_.Name -ne "extractme.zip"} | Remove-Item -Recurse -Force
