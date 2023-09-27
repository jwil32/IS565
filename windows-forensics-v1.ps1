$baseDir = "C:\Windows\Temp"
$outFile = "$baseDir\hiveInfo.txt" 

# Make the file
# ni $outFile -ItemType "file"
out-file -filepath $outFile

# Copy the NTUSER.DAT from each user into $baseDir
# * This command will not copy the NTUSER.DAT of any user that is currently logged in
#   because the NTUSER.DAT is currently being used by Windows
#
# .DAT files are hidden files by default. See them by listing the directory with dir -Force


Get-ChildItem 'C:\Users\*\NTUSER.DAT' -Attributes Hidden | ForEach-Object{
	write-output $_
    $fname = $_.Directory.Name + "." + $_.Name
    try
    {
    	copy $_.FullName C:\Windows\Temp\$fname
    }
    catch
    {
    	write-output "Exception"
        write-output $_
    }
}


# Get all autostarted system programs
add-content $outFile "##############################################################"
add-content $outFile "################# System Autostart Programs ##################"
add-content $outFile "##############################################################"
add-content $outFile ""

Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\*' | ForEach-Object{
    if($_.Start -eq 2){
        Add-Content $outFile "Registry Key: $($_.PSPath)"
        Add-Content $outFile "Executable Path: $($_.ImagePath)"
        Add-Content $outFile "Start Type: $($_.Start) (Autostarted at boot)"
        Add-Content $outFile ""
    }
}

Add-Content $outFile "##############################################################"
Add-Content $outFile "############## User Logon Autostart Programs #################"
Add-Content $outFile "##############################################################"
Add-Content $outFile ""

# Find keys that run commands at every user logon
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' | ForEach-Object {
    Add-Content $outfile "* Command is executed every time the user logs in"
    $_ | get-member -type properties | foreach {
        $array = "$_".Split(" ", 2)
        Add-Content $outFile $array[1]
    }
    Add-Content $outFile ""
}

# Find keys that run commands once at the next user logon
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' | ForEach-Object {
    Add-Content $outfile "* Command will be executed at the next user logon, then deleted"
    $_ | get-member -type properties | foreach {
        $array = "$_".Split(" ", 2)
        Add-Content $outFile $array[1]
    }
    Add-Content $outFile ""
}
