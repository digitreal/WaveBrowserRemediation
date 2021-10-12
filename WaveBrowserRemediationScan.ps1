Function intro {
    <#
            .SYNOPSIS
                Remediation script for WaveBrowser Software previously known as WebNavigator.
    
            .DESCRIPTION
                The script will first scan and log WaveBrowser artifacts.

            .EXAMPLE
                Run the script to scan for artifacts.
    
                Description
                -----------
                Scans for WaveBrowser artifacts.
                Orginally sourced from https://github.com/xephora/Threat-Remediation-Scripts/blob/main/WaveBrowser/WaveBrowser-Remediation-Script.ps1

        #>

    }
Function CheckBrowserProcesses {
<#--- Checks and PRINTS OUT all running browser processes ---#>

    Get-Process chrome -ErrorAction SilentlyContinue | Out-File -filePath $filePath -Append
    Get-Process firefox -ErrorAction SilentlyContinue | Out-File -filePath $filePath -Append
    Get-Process iexplore -ErrorAction SilentlyContinue | Out-File -filePath $filePath -Append
    Get-Process msedge -ErrorAction SilentlyContinue | Out-File -filePath $filePath -Append
    Get-Process SWUpdater -ErrorAction SilentlyContinue | Out-File -filePath $filePath -Append
	Get-Process wavebrowser -ErrorAction SilentlyContinue | Out-File -filePath $filePath -Append
}

Function CheckWavesorFS {
<#--- Checks and PRINTS OUT all files assigned to $dir ---#>

	$dir = "C:\users\*\Wavesor Software",
	"C:\users\*\WebNavigatorBrowser",
	"C:\users\*\appdata\local\WaveBrowser",
	"C:\users\*\appdata\local\WebNavigatorBrowser",
	"C:\users\*\downloads\Wave Browser*.exe",
	"C:\users\*\appdata\Roaming\Microsoft\Internet Explorer\Quick Launch\WaveBrowser.lnk",
	"C:\users\*\appdata\Roaming\Microsoft\Windows\Start Menu\Programs\WaveBrowser.lnk",
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
<#--- Checks and PRINTS OUT all scheduled tasks with the name of *wave* ---#>
    
    $tasks = Get-ScheduledTask -TaskName *Wave* | Select-Object -ExpandProperty TaskName
    foreach ($i in $tasks) {
       $i,"Scheduled Task Exists`n" | Out-File -filePath $filePath -Append
    }
}

Function CheckRegistryKey {
<#--- Checks and PRINTS OUT all registry keys assigned to $dir under the current user account ---#>
    
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
	"`n**************Scan Complete**************`n" | Out-File -filePath $filePath -Append
	Write-Output "`n**************Scan Complete**************`n"
}
	


<#------------------------------------------------------------------------#>

$filePath = "C:\waveScan.txt"

CheckBrowserProcesses
CheckWavesorFS
CheckScheduledTasks
CheckRegistryKey
