Function intro {
    <#
            .SYNOPSIS
                Remediation script for WaveBrowser Software previously known as WebNavigator.
    
            .DESCRIPTION
                The script will first scan and log WaveBrowser artifacts.
                Prompt user to then stop browser session, remove files, scheduled tasks and registry keys associated with WebBrowser.
            .EXAMPLE
                Run the script to scan and choose to remove the artifacts.
    
                Description
                -----------
                Scans for WaveBrowser artifacts.
                Prompts user to remove items found in scan.
                Kills any browser sessions.
                Removes registry keys associated with Wave Browser Hijacking Software.
                Removes files associated with Wave Browser Hijacking Software.
                Removes the scheduled tasks associated with Wave Browser.
                Orginally sourced from https://github.com/xephora/Threat-Remediation-Scripts/blob/main/WaveBrowser/WaveBrowser-Remediation-Script.ps1
        #>

    }
Function CheckBrowserProcesses {
    "Checking Browser Sessions"

    Get-Process chrome -ErrorAction SilentlyContinue | Out-File -filePath $filePath -Append
    Get-Process firefox -ErrorAction SilentlyContinue | Out-File -filePath $filePath -Append
    Get-Process iexplore -ErrorAction SilentlyContinue | Out-File -filePath $filePath -Append
    Get-Process msedge -ErrorAction SilentlyContinue | Out-File -filePath $filePath -Append
    Get-Process SWUpdater -ErrorAction SilentlyContinue | Out-File -filePath $filePath -Append
    Get-Process wavebrowser -ErrorAction SilentlyContinue | Out-File -filePath $filePath -Append
}

Function CheckWavesorFS {
	"Checking WaveBrowser Files"
	$dir = "$env:USERPROFILE\Wavesor Software",
	"$env:USERPROFILE\WebNavigatorBrowser",
	"$env:USERPROFILE\appdata\local\WaveBrowser",
	"$env:USERPROFILE\appdata\local\WebNavigatorBrowser",
	"$env:USERPROFILE\downloads\Wave Browser*.exe",
	"$env:USERPROFILE\appdata\Roaming\Microsoft\Internet Explorer\Quick Launch\WaveBrowser.lnk",
	"$env:USERPROFILE\appdata\Roaming\Microsoft\Windows\Start Menu\Programs\WaveBrowser.lnk",
	"C:\ProgramData\Intel\ShaderCache\wavebrowser*",
	"C:\Users\All Users\Intel\ShaderCache\wavebrowser*",
	"C:\Windows\Prefetch\WAVEBROWSER*.*"
	
	foreach ($path in $dir)
	{    
    if(($item = Get-Item -Path $path -ErrorAction SilentlyContinue)) {
    $item,$path,"Path exists" | Out-File -filePath $filePath -Append
} else {
    $item,$path,"Path does not exist`n" | Out-File -filePath $filePath -Append
	   }
	}
}

Function CheckScheduledTasks {
    "Checking Scheduled Tasks"
    
    $tasks = Get-ScheduledTask -TaskName *Wave* | Select-Object -ExpandProperty TaskName
    foreach ($i in $tasks) {
       $i,"Scheduled Task Exists`n" | Out-File -filePath $filePath -Append
    }
}

Function CheckRegistryKey {
    "Checking Registry Keys.."
    
		$dir = "HKCU:\Software\WaveBrowser",
		"HKCU:\Software\Wavesor",
		"HKCU:\Software\WebNavigatorBrowser",
		"HKCU\Software\Microsoft\Windows\CurrentVersion\Run.Wavesor SWUpdater"
		
	foreach ($path in $dir)
	{    
    if(($item = Get-Item -Path $path -ErrorAction SilentlyContinue)) {
    $item,$path,"Path exists" | Out-File -filePath $filePath -Append
} else {
    $item,$path,"Path does not exist`n" | Out-File -filePath $filePath -Append
	   }
	}
}
	
Function BrowserProcesses {
	"Stopping Browser Sessions"

	Get-Process chrome -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
	Get-Process firefox -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
	Get-Process iexplore -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
	Get-Process msedge -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
	Get-Process SWUpdater -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
	Get-Process wavebrowser -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

Function RemoveWavesorFS {
	"Cleaning WaveBrowser Files"
	
	
	$dir = "$env:USERPROFILE\Wavesor Software",
	"$env:USERPROFILE\WebNavigatorBrowser",
	"$env:USERPROFILE\appdata\local\WaveBrowser",
	"$env:USERPROFILE\appdata\local\WebNavigatorBrowser",
	"$env:USERPROFILE\downloads\Wave Browser*.exe",
	"$env:USERPROFILE\appdata\Roaming\Microsoft\Internet Explorer\Quick Launch\WaveBrowser.lnk",
	"$env:USERPROFILE\appdata\Roaming\Microsoft\Windows\Start Menu\Programs\WaveBrowser.lnk",
	"C:\ProgramData\Intel\ShaderCache\wavebrowser*",
	"C:\Users\All Users\Intel\ShaderCache\wavebrowser*",
	"C:\Windows\Prefetch\WAVEBROWSER*.*"
		
	foreach ($path in $dir)
	{    
    if(($item = Get-Item -Path $path -ErrorAction SilentlyContinue)) {
    $item,$path,"Attempting removal" | Out-File -filePath $filePath -Append
	rm $path -Force -Recurse -ErrorAction SilentlyContinue -ErrorVariable DirectoryError
} else {
    $item,$path,"Path does not exist`n" | Out-File -filePath $filePath -Append
	   }
	}
}

Function RemoveScheduledTasks {
	"Cleaning Scheduled Tasks"
	
	$tasks = Get-ScheduledTask -TaskName *Wave* | Select-Object -ExpandProperty TaskName
	foreach ($i in $tasks) {
		Unregister-ScheduledTask -TaskName $i -Confirm:$false -ErrorAction SilentlyContinue -ErrorVariable DirectoryError
	}
}

Function RemoveRegistryKey {
	"Cleaning Registry Keys.."
	
		$dir = "HKCU:\Software\WaveBrowser",
		"HKCU:\Software\Wavesor",
		"HKCU:\Software\WebNavigatorBrowser",
		"HKCU\Software\Microsoft\Windows\CurrentVersion\Run.Wavesor SWUpdater"
		
	foreach ($path in $dir)
	{    
    if(($item = Get-Item -Path $path -ErrorAction SilentlyContinue)) {
    $item,$path,"Attempting removal" | Out-File -filePath $filePath -Append
	Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
} else {
    $item,$path,"Path does not exist`n" | Out-File -filePath $filePath -Append
	   }
	}
}	


$filePath = "C:\temp\waveScan.txt"
$titleScan = 'Would you like to scan for the Wave Browser on this host'
$waveScan = '(y/n)?'
$choicesScan = '&Yes', '&No'

$decision = $Host.UI.PromptForChoice($titleScan, $waveScan, $choicesScan, 1)
if ($decision -eq 0) {
    Write-Host 'confirmed'
CheckBrowserProcesses
CheckWavesorFS
CheckScheduledTasks
CheckRegistryKey
Write-Output "`nPrinting log file to:",$filePath

$titleClean    = 'Would you like to remediate the Wave Browser on this host'
$waveClean = '(y/n)?'
$choicesClean  = '&Yes', '&No'

$decision = $Host.UI.PromptForChoice($titleClean, $waveClean, $choicesClean, 1)
	if ($decision -eq 0) {
		Write-Host 'confirmed'
		BrowserProcesses
		RemoveWavesorFS
		RemoveScheduledTasks
		RemoveRegistryKey
		} else {
		Write-Host 'cancelled'
	}
} else {
    Write-Host 'cancelled'
}
