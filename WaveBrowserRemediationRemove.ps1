Function intro {
    <#
            .SYNOPSIS
                Remediation script for WaveBrowser Software previously known as WebNavigator.
    
            .DESCRIPTION
                The script will first scan and log WaveBrowser artifacts.
                Stops browser session, remove files, scheduled tasks and registry keys associated with WebBrowser.
            .EXAMPLE
                Run the script to scan and remove the artifacts.
    
                Description
                -----------
                Scans for WaveBrowser artifacts.
                Kills any browser sessions.
                Removes registry keys associated with Wave Browser Hijacking Software.
                Removes files associated with Wave Browser Hijacking Software.
                Removes the scheduled tasks associated with Wave Browser.
                Orginally sourced from https://github.com/xephora/Threat-Remediation-Scripts/blob/main/WaveBrowser/WaveBrowser-Remediation-Script.ps1
        #>

    }

Function BrowserProcesses {
<#--- Checks and STOPS all running browser processes ---#>

	Get-Process chrome -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
	Get-Process firefox -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
	Get-Process iexplore -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
	Get-Process msedge -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
	Get-Process SWUpdater -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
	Get-Process wavebrowser -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

Function RemoveWavesorFS {
<#--- Checks and DELETES all files assigned to $dir ---#>
	
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
    $item,$path,"Attempting removal" | Out-File -filePath $filePath -Append
	rm $path -Force -Recurse -ErrorAction SilentlyContinue -ErrorVariable DirectoryError
} else {
    $item,$path,"Path does not exist`n" | Out-File -filePath $filePath -Append
	   }
	}
}

Function RemoveScheduledTasks {
<#--- Checks and DELETES all scheduled tasks with the name of *wave* ---#>
	
	$tasks = Get-ScheduledTask -TaskName *Wave* | Select-Object -ExpandProperty TaskName
	foreach ($i in $tasks) {
		Unregister-ScheduledTask -TaskName $i -Confirm:$false -ErrorAction SilentlyContinue -ErrorVariable DirectoryError
	}
}

Function RemoveRegistryKey {
<#--- Checks and DELETES all registry keys assigned to $dir under the current user account ---#>
	
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
	"`n**************Removal Complete**************`n" | Out-File -filePath $filePath -Append
}	


<#------------------------------------------------------------------------#>

$filePath = "C:\waveScan.txt"


BrowserProcesses
RemoveWavesorFS
RemoveScheduledTasks
RemoveRegistryKey
