@echo off
set "KOKA_PROJECT_DIR=%~dp0"
powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Windows.Forms; $dialog=New-Object System.Windows.Forms.FolderBrowserDialog; $dialog.Description='Select the output folder for koka.exe'; $dialog.ShowNewFolderButton=$true; if($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK){ & (Join-Path $env:KOKA_PROJECT_DIR 'build.ps1') -OutputDirectory $dialog.SelectedPath; if($LASTEXITCODE -ne 0){ exit $LASTEXITCODE }; Write-Host 'Build completed.' }"
pause
