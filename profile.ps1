#region Initialization of states
# * Admin Check
# Find out if the current user identity is elevated (has admin rights)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# * Check for Internet Connection to provide all terminal utils 
$internetConnectionEstablished = Test-Connection -ComputerName google.com -Count 1 -Quiet
if ($internetConnectionEstablished) {
    Write-Host "Internet connection established!" -ForegroundColor Green
} else {
    Write-Host "No internet connection. Commands and terminal output may be limited." -ForegroundColor Red -BackgroundColor Black
}
# Utility Functions
function Test-CommandExists {
    param($command)
    $exists = $null -ne (Get-Command $command -ErrorAction SilentlyContinue)
    return $exists
}

#region Profile Utilities
# - Reload Profile
function rld {
    Write-Host ""
    Write-Host "Profile will be reloaded in 5 seconds..." -ForegroundColor Yellow
    Write-Host "Press Ctrl + C to cancel!" -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    . $PROFILE.CurrentUserAllHosts
}
# If this is $false until the end, then no profile reload will be triggered
$reloadpending = $false

#region Terminal Package Managers
# Check if Scoop is installed. If not, install it.
# If it is installed, run the scoop-search hook to install
# missing packages.
if (Get-Command scoop -ErrorAction SilentlyContinue) {
    # Run the hook
    Write-Host "Running scoop-search hook..."
    Invoke-Expression (&scoop-search --hook)
} else {
    Write-Host "Scoop is not installed. " -ForegroundColor Yellow
    Write-Host -NoNewline "Checking internet connectivity..." -ForegroundColor Gray
    # Check internet connection to provide output
    if ($internetConnectionEstablished) {
        Write-Host "Installing Scoop..." -ForegroundColor White
        # Install Scoop using the official install script.
        # This script is used to install Scoop on a machine without
        # requiring admin rights.
        Invoke-RestMethod -Uri https://get.scoop.sh | Invoke-Expression
        Write-Host "Scoop installed successfully." -ForegroundColor Green
        # Install git is necessary to add buckets
        Write-Host "Installing git..." -ForegroundColor White
        scoop install git
        # Add the extras bucket
        Write-Host "Adding extras bucket..." -ForegroundColor White 
        scoop bucket add extras
        # Install scoop-search
        Write-Host "Installing scoop-search..." -ForegroundColor White
        scoop install scoop-search
        # Run the hook
        Write-Host "Running scoop-search hook..." -ForegroundColor White
        Invoke-Expression (&scoop-search --hook)
    } else {
        Write-Host "No internet connection. Commands and terminal output may be limited." -ForegroundColor Red
    }
}

# ? Install Chocolatey if it is not already installed.
# This code is run when Chocolatey is not installed or
# if it is installed but not in the user's PATH.
# If the user is an admin, the user will be prompted to
# install Chocolatey.
# If the user is not an admin, the user will be prompted
# to run the command with admin rights.
if (-not (Get-Command choco -ErrorAction SilentlyContinue) -and -not (Get-Command chocolatey -ErrorAction SilentlyContinue)) {
    if ($isAdmin) {
        $choice = Read-Host "Chocolatey is not installed. Do you want to install it now? [Y/n]"
        if ($choice -eq "Y" -or $choice -eq "y" -or $choice -eq "") {
            Write-Host "Installing Chocolatey..." -ForegroundColor Green
            # Install Chocolatey using the official install script.
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
            Write-Host "Chocolatey installed successfully." -ForegroundColor Green
            $reloadpending = $true
        } else {
            Write-Host "Skipping Chocolatey install." -ForegroundColor Yellow
        }
    } else {
        $choice = Read-Host "Chocolatey is not installed. Do you want to install it now? You will be prompted for admin rights. [Y/n]"
        if ($choice -eq "Y" -or $choice -eq "y" -or $choice -eq "") {
            # Prompt for administrator privileges and install Chocolatey
            Start-Process powershell.exe -ArgumentList "-noprofile -noexit", "-Command", "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))" -Verb RunAs -Wait
            Write-Host "Chocolatey installed successfully." -ForegroundColor Green
            $reloadpending = $true
        } else {
            Write-Host "Skipping Chocolatey install. Admin rights is denied." -ForegroundColor Yellow
        }
    }
} else {
    # Import the Chocolatey profile if it is installed.
    $ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
    if (Test-Path($ChocolateyProfile)) {
        Import-Module "$ChocolateyProfile"
    }
}

# Modules and External Profiles
# - Update all installed PowerShell modules to the latest version
if ($internetConnectionEstablished) {
  $outdatedModules = Get-InstalledModule | Where-Object {
    $latestVersion = (Find-Module -Name $_.Name -Repository PSGallery).Version
    $_.Version -ne $latestVersion
  }
  if ($outdatedModules) {
    Write-Host "Updating outdated modules..." -ForegroundColor Green
    $outdatedModules | ForEach-Object {
      $latestVersion = (Find-Module -Name $_.Name -Repository PSGallery).Version
      Write-Host "Updating Module $($_.Name) from version $($_.Version) to version $($latestVersion)" -ForegroundColor Yellow
      Update-Module -Name $_.Name -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }
    Write-Host "Module updates complete." -ForegroundColor Green
  } else {
    Write-Host "All modules are up to date." -ForegroundColor Cyan
  }
} else {
  Write-Host "No internet connection established. Skipping module updates." -ForegroundColor Red
}
# * - Set up PSReadLine
# Validate if PSReadLine module is installed
if (Get-Module -ListAvailable -Name PSReadLine) {
    # If PSReadLine module is installed, import it
    Import-Module "PSReadline"
} else {
    # If PSReadLine module is not installed, install it
    try {
        # Attempt to install PSReadLine module from PSGallery
        Install-Module -Name PSReadLine -Force -Repository PSGallery
    } catch {
        # If installation fails, handle the error
        Write-Error "Failed to install PSReadLine module. Error: $_"
        return
    }
    # Import PSReadLine module after successful installation
    Import-Module "PSReadline"
}
# Set the PredictionSource to HistoryAndPlugin
Set-PSReadLineOption -PredictionSource HistoryAndPlugin
Set-PSReadLineOption -PredictionViewStyle ListView
Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete

# ? - Ensure Terminal-Icons module is installed before importing
if (-not (Get-Module -ListAvailable -Name Terminal-Icons)) {
    Install-Module -Name Terminal-Icons -Scope CurrentUser -Force -SkipPublisherCheck
} 
Import-Module -Name Terminal-Icons

# ? - Imports the Gsudo Module
if (Get-Command gsudo -ErrorAction SilentlyContinue) {
    # Write-Host "gsudo is installed. Loading..." -ForegroundColor Cyan
    Import-Module 'gsudoModule'
    Write-Host "gsudo is installed." -ForegroundColor Cyan
    Set-Alias -Name su -Value gsudo
    Set-Alias -Name sudo -Value gsudo
} else {
    Write-Host "gsudo not found!" -ForegroundColor Red
    if ($internetConnectionEstablished) {
        Write-Host "Internet connection established. " -ForegroundColor Green 
        Write-Host "Installing gsudo via scoop..." -ForegroundColor Gray
        try {
            scoop install gsudo
            Write-Host "gsudo installed successfully." -ForegroundColor Green
            $reloadpending = $true
        } catch {
            Write-Host "Installation failed. Please check the error above." -ForegroundColor Red
        }
    } else {
        Write-Host "No internet connection available. Running gsudo will not work." -ForegroundColor Red
    }
}
# ? - Catppuccin Colorscheme
if (!(Get-Module -ListAvailable -Name Catppuccin)) {
    Write-Host "Catppuccin Module not found!" -ForegroundColor Red
    
    if ($internetConnectionEstablished) {
        $catppuccinTargetClone = Join-Path -Path (($env:PSModulePath -split ';')[0]) -ChildPath 'Catppuccin'
        
        try {
            if (!(Test-Path $catppuccinTargetClone)) {
                Write-Host "Cloning Catppuccin module..." -ForegroundColor Cyan
                git clone https://github.com/catppuccin/powershell.git $catppuccinTargetClone    
            } else {
                Write-Host "Updating Catppuccin module..." -ForegroundColor Cyan
                git -C $catppuccinTargetClone pull
            }
        } catch {
            Write-Host "Git operation failed: $_" -ForegroundColor Red
        }

        # Try importing the module after cloning/updating
        Import-Module Catppuccin -ErrorAction SilentlyContinue

        if (Get-Module -ListAvailable -Name Catppuccin) {
            Write-Host "Catppuccin module is ready to use." -ForegroundColor Green
        } else {
            Write-Host "Failed to load Catppuccin module." -ForegroundColor Red
        }
    } else {
        Write-Host "No internet connection. Cannot clone or update Catppuccin module." -ForegroundColor Yellow
    }
}

#region Editor Configuration
# - Editor Aliases
# If your favorite editor is not here, add an elseif and ensure that the directory it is installed in exists in your $env:Path
# Terminal editors
$terminalEditor = if (Test-CommandExists nvim) { 'nvim' }
                  elseif (Test-CommandExists vim) { 'vim' }
                  else { $null }

# App-based editors
$appEditor = if (Test-CommandExists code) { 'code' }
              elseif (Test-CommandExists codium) { 'codium' }
              elseif (Test-CommandExists notepad++) { 'notepad++' }
              elseif (Test-CommandExists sublime_text) { 'sublime_text' }
              else { 'notepad' }

# Default editor (prefer terminal editor if available)
$editor = if ($terminalEditor) { $terminalEditor } else { $appEditor }
# - Edit Profile
function Edit-Profile {
    $editor = $args[0]
    if ([string]::IsNullOrEmpty($editor)) {
        $editor = $editor
    }
    & $editor $PROFILE.CurrentUserAllHosts
}

# Useful shortcuts for traversing directories
function cd... { Set-Location ..\.. }
function cd.... { Set-Location ..\..\.. }

# Compute file hashes - useful for checking successful downloads 
function md5 { Get-FileHash -Algorithm MD5 $args }
function sha1 { Get-FileHash -Algorithm SHA1 $args }
function sha256 { Get-FileHash -Algorithm SHA256 $args }

# Quick shortcut to start an editor to be based on
# app or terminal
function aedit { if ($appEditor) { & $appEditor $args } else { Write-Error "No app-based editor found" } }
function tedit { if ($terminalEditor) { & $terminalEditor $args } else { Write-Error "No terminal editor found" } }

# Drive shortcuts
function HKLM: { Set-Location HKLM: }
function HKCU: { Set-Location HKCU: }
function Env: { Set-Location Env: }

# Set the window title to include the version of PowerShell and whether or not
# the user is running with admin rights. This is done by concatenating the version
# string onto the base title and adding "[ADMIN]" if the user is running with admin rights.
$Host.UI.RawUI.WindowTitle = "PowerShell {0}" -f $PSVersionTable.PSVersion.ToString()
if ($isAdmin) {
    $Host.UI.RawUI.WindowTitle += " [ADMIN]"
}

# Does the the rough equivalent of dir /s /b. For example, dirs *.png is dir /s /b *.png
function dirs {
    if ($args.Count -gt 0) {
        Get-ChildItem -Recurse -Include "$args" | Foreach-Object FullName
    } else {
        Get-ChildItem -Recurse | Foreach-Object FullName
    }
}

# Admin Check and Prompt Customization
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
function prompt {
    if ($isAdmin) { "[" + (Get-Location) + "] # " } else { "[" + (Get-Location) + "] $ " }
}
$adminSuffix = if ($isAdmin) { " [ADMIN]" } else { "" }
$Host.UI.RawUI.WindowTitle = "PowerShell {0}$adminSuffix" -f $PSVersionTable.PSVersion.ToString()

function touch($file) { "" | Out-File $file -Encoding ASCII }
function ff($name) {
    Get-ChildItem -recurse -filter "*${name}*" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "$($_.directory)\$($_)"
    }
}

# Network Utilities
# - Get IP Address
# ! THIS FUNCTION IS NOT SECURE. USE AT YOUR OWN RISK. DO NOT SHARE YOUR IP ADDRESS.
# ! IF SOMEONE IS ASKING FOR YOUR PUBLIC IP ADDRESS, 101% YOU ARE BEING SCAMMED.
function Get-IP {
  $publicIpv4 = $null
  $publicIpv6 = $null

  try {
    $publicIpv4 = (Invoke-WebRequest http://ifconfig.me/ip).Content
  } catch {
    Write-Host "Error retrieving public IPv4 address: $($Error[0].Message)"
  }

  try {
    $publicIpv6 = (Invoke-WebRequest http://ifconfig.me/ip6).Content
  } catch {
    Write-Host "Error retrieving public IPv6 address: $($Error[0].Message)"
  }

  $localIpv4 = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet).IPAddress
  $localIpv6 = (Get-NetIPAddress -AddressFamily IPv6 -InterfaceAlias Ethernet).IPAddress

  Write-Host "Public IP:" -ForegroundColor Yellow
  Write-Host "  IPv4: " -NoNewline -ForegroundColor Green
  Write-Host $publicIpv4
  Write-Host "  IPv6: " -NoNewline -ForegroundColor Blue
  Write-Host $publicIpv6

  Write-Host "Local IP:" -ForegroundColor Yellow
  Write-Host "  IPv4: " -NoNewline -ForegroundColor Green
  Write-Host $localIpv4
  Write-Host "  IPv6: " -NoNewline -ForegroundColor Blue
  Write-Host $localIpv6
}
# System Utilities
# - Check Uptime
function uptime {
    if ($PSVersionTable.PSVersion.Major -eq 5) {
        Get-WmiObject win32_operatingsystem | Select-Object @{Name='LastBootUpTime'; Expression={$_.ConverttoDateTime($_.lastbootuptime)}} | Format-Table -HideTableHeaders
    } else {
        net statistics workstation | Select-String "since" | ForEach-Object { $_.ToString().Replace('Statistics since ', '') }
    }
}

function grep($regex, $dir) {
    if ( $dir ) {
        Get-ChildItem $dir | select-string $regex
        return
    }
    $input | select-string $regex
}

function unzip ($file) {
    Write-Output("Extracting", $file, "to", $pwd)
    $fullFile = Get-ChildItem -Path $pwd -Filter $file | ForEach-Object { $_.FullName }
    Expand-Archive -Path $fullFile -DestinationPath $pwd
}

# Christitus HasteBin Utility
function hb {
    if ($args.Length -eq 0) {
        Write-Error "No file path specified."
        return
    }
    
    $FilePath = $args[0]
    
    if (Test-Path $FilePath) {
        $Content = Get-Content $FilePath -Raw
    } else {
        Write-Error "File path does not exist."
        return
    }
    
    $uri = "http://bin.christitus.com/documents"
    try {
        $response = Invoke-RestMethod -Uri $uri -Method Post -Body $Content -ErrorAction Stop
        $hasteKey = $response.key
        $url = "http://bin.christitus.com/$hasteKey"
        Write-Output $url
    } catch {
        Write-Error "Failed to upload the document. Error: $_"
    }
}

function df {
    get-volume
}

function sed($file, $find, $replace) {
    (Get-Content $file).replace("$find", $replace) | Set-Content $file
}

function which($name) {
    Get-Command $name | Select-Object -ExpandProperty Definition
}

function export($name, $value) {
    set-item -force -path "env:$name" -value $value;
}

function pkill($name) {
    Get-Process $name -ErrorAction SilentlyContinue | Stop-Process
}

function pgrep($name) {
    Get-Process $name
}

function head {
  param($Path, $n = 10)
  Get-Content $Path -Head $n
}

function tail {
  param($Path, $n = 10)
  Get-Content $Path -Tail $n
}

# Quick File Creation
function nf { param($name) New-Item -ItemType "file" -Path . -Name $name }

# Directory Management
function mkcd { param($dir) mkdir $dir -Force; Set-Location $dir }

### Quality of Life Aliases
# Navigation Shortcuts
function docs { Set-Location -Path $HOME\Documents }

function dtop { Set-Location -Path $HOME\Desktop }

# Quick Access to Editing the Profile
function ep { vim $PROFILE }

# Simplified Process Management
function k9 { Stop-Process -Name $args[0] }

# Enhanced Listing
function la { Get-ChildItem -Path . -Force | Format-Table -AutoSize }
function ll { Get-ChildItem -Path . -Force -Hidden | Format-Table -AutoSize }

# Git Shortcuts
function gs { git status }

function ga { git add . }

function gc { param($m) git commit -m "$m" }

function gp { git push }

function g { z Github }

function gcom {
    git add .
    git commit -m "$args"
}
function lazyg {
    git add .
    git commit -m "$args"
    git push
}

# Quick Access to System Information
function sysinfo { Get-ComputerInfo }

# Networking Utilities
function flushdns { Clear-DnsClientCache }

# Clipboard Utilities
function cpy { Set-Clipboard $args[0] }

function pst { Get-Clipboard }

#region Christian Lempa Profile
# TODO: You can check for duplicates of functions and go ahead delete them or do PRs if you want
# ? The config starts here
function goto {
    param (
        $location
    )

    Switch ($location) {
        "prorepos" {
            Set-Location -Path "$HOME\Work Folders\Project Repos"
        }
        "gitrepos" {
            Set-Location -Path "$HOME\Work Folders\Git Repos"
        }
        default {
            Write-Output "Invalid location"
        }
    }
}

# $ENV:KUBECONFIG = ".kube/prod-k8s-clcreative-kubeconfig.yaml;.kube/civo-k8s_test_1-kubeconfig;.kube/k8s_test_1.yml"

# function kn {
#     param (
#         $namespace
#     )

#     if ($namespace -in "default","d") {
#         kubectl config set-context --current --namespace=default
#     } else {
#         kubectl config set-context --current --namespace=$namespace
#     }
# }

# powershell completion for datree                               -*- shell-script -*-

function __datree_debug {
    if ($env:BASH_COMP_DEBUG_FILE) {
        "$args" | Out-File -Append -FilePath "$env:BASH_COMP_DEBUG_FILE"
    }
}

filter __datree_escapeStringWithSpecialChars {
    $_ -replace '\s|#|@|\$|;|,|''|\{|\}|\(|\)|"|`|\||<|>|&','`$&'
}

Register-ArgumentCompleter -CommandName 'datree' -ScriptBlock {
    param(
            $WordToComplete,
            $CommandAst,
            $CursorPosition
        )

    # Get the current command line and convert into a string
    $Command = $CommandAst.CommandElements
    $Command = "$Command"

    __datree_debug ""
    __datree_debug "========= starting completion logic =========="
    __datree_debug "WordToComplete: $WordToComplete Command: $Command CursorPosition: $CursorPosition"

    # The user could have moved the cursor backwards on the command-line.
    # We need to trigger completion from the $CursorPosition location, so we need
    # to truncate the command-line ($Command) up to the $CursorPosition location.
    # Make sure the $Command is longer then the $CursorPosition before we truncate.
    # This happens because the $Command does not include the last space.
    if ($Command.Length -gt $CursorPosition) {
        $Command=$Command.Substring(0,$CursorPosition)
    }
        __datree_debug "Truncated command: $Command"

    $ShellCompDirectiveError=1
    $ShellCompDirectiveNoSpace=2
    $ShellCompDirectiveNoFileComp=4
    $ShellCompDirectiveFilterFileExt=8
    $ShellCompDirectiveFilterDirs=16

        # Prepare the command to request completions for the program.
    # Split the command at the first space to separate the program and arguments.
    $Program,$Arguments = $Command.Split(" ",2)
    $RequestComp="$Program __complete $Arguments"
    __datree_debug "RequestComp: $RequestComp"

    # we cannot use $WordToComplete because it
    # has the wrong values if the cursor was moved
    # so use the last argument
    if ($WordToComplete -ne "" ) {
        $WordToComplete = $Arguments.Split(" ")[-1]
    }
    __datree_debug "New WordToComplete: $WordToComplete"


    # Check for flag with equal sign
    $IsEqualFlag = ($WordToComplete -Like "--*=*" )
    if ( $IsEqualFlag ) {
        __datree_debug "Completing equal sign flag"
        # Remove the flag part
        $Flag,$WordToComplete = $WordToComplete.Split("=",2)
    }

    if ( $WordToComplete -eq "" -And ( -Not $IsEqualFlag )) {
        # If the last parameter is complete (there is a space following it)
        # We add an extra empty parameter so we can indicate this to the go method.
        __datree_debug "Adding extra empty parameter"
        # We need to use `"`" to pass an empty argument a "" or '' does not work!!!
        $RequestComp="$RequestComp" + ' `"`"'
    }

    __datree_debug "Calling $RequestComp"
    #call the command store the output in $out and redirect stderr and stdout to null
    # $Out is an array contains each line per element
    Invoke-Expression -OutVariable out "$RequestComp" 2>&1 | Out-Null


    # get directive from last line
    [int]$Directive = $Out[-1].TrimStart(':')
    if ($Directive -eq "") {
        # There is no directive specified
        $Directive = 0
    }
    __datree_debug "The completion directive is: $Directive"

    # remove directive (last element) from out
    $Out = $Out | Where-Object { $_ -ne $Out[-1] }
    __datree_debug "The completions are: $Out"

    if (($Directive -band $ShellCompDirectiveError) -ne 0 ) {
        # Error code.  No completion.
        __datree_debug "Received error from custom completion go code"
        return
    }

    $Longest = 0
    $Values = $Out | ForEach-Object {
        #Split the output in name and description
        $Name, $Description = $_.Split("`t",2)
        __datree_debug "Name: $Name Description: $Description"

        # Look for the longest completion so that we can format things nicely
        if ($Longest -lt $Name.Length) {
            $Longest = $Name.Length
        }

        # Set the description to a one space string if there is none set.
        # This is needed because the CompletionResult does not accept an empty string as argument
        if (-Not $Description) {
            $Description = " "
        }
        @{Name="$Name";Description="$Description"}
    }


    $Space = " "
    if (($Directive -band $ShellCompDirectiveNoSpace) -ne 0 ) {
        # remove the space here
        __datree_debug "ShellCompDirectiveNoSpace is called"
        $Space = ""
    }

    if (($Directive -band $ShellCompDirectiveNoFileComp) -ne 0 ) {
        __datree_debug "ShellCompDirectiveNoFileComp is called"

        if ($Values.Length -eq 0) {
            # Just print an empty string here so the
            # shell does not start to complete paths.
            # We cannot use CompletionResult here because
            # it does not accept an empty string as argument.
            ""
            return
        }
    }

    if ((($Directive -band $ShellCompDirectiveFilterFileExt) -ne 0 ) -or
       (($Directive -band $ShellCompDirectiveFilterDirs) -ne 0 ))  {
        __datree_debug "ShellCompDirectiveFilterFileExt ShellCompDirectiveFilterDirs are not supported"

        # return here to prevent the completion of the extensions
        return
    }

    $Values = $Values | Where-Object {
        # filter the result
        $_.Name -like "$WordToComplete*"

        # Join the flag back if we have a equal sign flag
        if ( $IsEqualFlag ) {
            __datree_debug "Join the equal sign flag back to the completion value"
            $_.Name = $Flag + "=" + $_.Name
        }
    }

    # Get the current mode
    $Mode = (Get-PSReadLineKeyHandler | Where-Object {$_.Key -eq "Tab" }).Function
    __datree_debug "Mode: $Mode"

    $Values | ForEach-Object {

        # store temporay because switch will overwrite $_
        $comp = $_

        # PowerShell supports three different completion modes
        # - TabCompleteNext (default windows style - on each key press the next option is displayed)
        # - Complete (works like bash)
        # - MenuComplete (works like zsh)
        # You set the mode with Set-PSReadLineKeyHandler -Key Tab -Function <mode>

        # CompletionResult Arguments:
        # 1) CompletionText text to be used as the auto completion result
        # 2) ListItemText   text to be displayed in the suggestion list
        # 3) ResultType     type of completion result
        # 4) ToolTip        text for the tooltip with details about the object

        switch ($Mode) {

            # bash like
            "Complete" {

                if ($Values.Length -eq 1) {
                    __datree_debug "Only one completion left"

                    # insert space after value
                    [System.Management.Automation.CompletionResult]::new($($comp.Name | __datree_escapeStringWithSpecialChars) + $Space, "$($comp.Name)", 'ParameterValue', "$($comp.Description)")

                } else {
                    # Add the proper number of spaces to align the descriptions
                    while($comp.Name.Length -lt $Longest) {
                        $comp.Name = $comp.Name + " "
                    }

                    # Check for empty description and only add parentheses if needed
                    if ($($comp.Description) -eq " " ) {
                        $Description = ""
                    } else {
                        $Description = "  ($($comp.Description))"
                    }

                    [System.Management.Automation.CompletionResult]::new("$($comp.Name)$Description", "$($comp.Name)$Description", 'ParameterValue', "$($comp.Description)")
                }
             }

            # zsh like
            "MenuComplete" {
                # insert space after value
                # MenuComplete will automatically show the ToolTip of
                # the highlighted value at the bottom of the suggestions.
                [System.Management.Automation.CompletionResult]::new($($comp.Name | __datree_escapeStringWithSpecialChars) + $Space, "$($comp.Name)", 'ParameterValue', "$($comp.Description)")
            }

            # TabCompleteNext and in case we get something unknown
            Default {
                # Like MenuComplete but we don't want to add a space here because
                # the user need to press space anyway to get the completion.
                # Description will not be shown because thats not possible with TabCompleteNext
                [System.Management.Automation.CompletionResult]::new($($comp.Name | __datree_escapeStringWithSpecialChars), "$($comp.Name)", 'ParameterValue', "$($comp.Description)")
            }
        }

    }
}
# ? The config ends here

#region My Profile

#region conda initialize
# !! Contents within this block are managed by 'conda init' !!
If (Test-Path "C:\Users\Epb\miniforge3\Scripts\conda.exe") {
    (& "C:\Users\Epb\miniforge3\Scripts\conda.exe" "shell.powershell" "hook") | Out-String | ?{$_} | Invoke-Expression
}
#endregion

# ? - Env Paths
$Env:KOMOREBI_CONFIG_HOME = '%userprofile%\.config\komorebi'
$env:PATH += ";%userprofile%\AppData\Local\pnpm"

# * - Catppuccin Color Scheme Initialization
# Only run this block if Catppuccin module exists
if (Get-Module -ListAvailable -Name Catppuccin) {
    # Import the module (if not already loaded)
    Import-Module Catppuccin -ErrorAction SilentlyContinue
    
    $Flavor = $Catppuccin['Mocha']
    
    # Modified prompt function
    function prompt {
        $(if (Test-Path variable:/PSDebugContext) { "$($Flavor.Red.Foreground())[DBG]: " }
          else { '' }) + "$($Flavor.Teal.Foreground())PS $($Flavor.Yellow.Foreground())" + $(Get-Location) +
            "$($Flavor.Green.Foreground())" + $(if ($NestedPromptLevel -ge 1) { '>>' }) + '> ' + $($PSStyle.Reset)
    }

    # FZF configuration
    $ENV:FZF_DEFAULT_OPTS = @"
--color=bg+:$($Flavor.Surface0),bg:$($Flavor.Base),spinner:$($Flavor.Rosewater)
--color=hl:$($Flavor.Red),fg:$($Flavor.Text),header:$($Flavor.Red)
--color=info:$($Flavor.Mauve),pointer:$($Flavor.Rosewater),marker:$($Flavor.Rosewater)
--color=fg+:$($Flavor.Text),prompt:$($Flavor.Mauve),hl+:$($Flavor.Red)
--color=border:$($Flavor.Surface2)
"@

    # PSReadLine colors
    $Colors = @{
        ContinuationPrompt     = $Flavor.Teal.Foreground()
        Emphasis               = $Flavor.Red.Foreground()
        Selection              = $Flavor.Surface0.Background()
        InlinePrediction       = $Flavor.Overlay0.Foreground()
        ListPrediction         = $Flavor.Mauve.Foreground()
        ListPredictionSelected = $Flavor.Surface0.Background()
        Command                = $Flavor.Blue.Foreground()
        Comment                = $Flavor.Overlay0.Foreground()
        Default                = $Flavor.Text.Foreground()
        Error                  = $Flavor.Red.Foreground()
        Keyword                = $Flavor.Mauve.Foreground()
        Member                 = $Flavor.Rosewater.Foreground()
        Number                 = $Flavor.Peach.Foreground()
        Operator               = $Flavor.Sky.Foreground()
        Parameter              = $Flavor.Pink.Foreground()
        String                 = $Flavor.Green.Foreground()
        Type                   = $Flavor.Yellow.Foreground()
        Variable               = $Flavor.Lavender.Foreground()
    }
    
    Set-PSReadLineOption -Colors $Colors

    # Formatting colors (PS 7.2+ onlyo)
    $PSStyle.Formatting.Debug = $Flavor.Sky.Foreground()
    $PSStyle.Formatting.Error = $Flavor.Red.Foreground()
    $PSStyle.Formatting.ErrorAccent = $Flavor.Blue.Foreground()
    $PSStyle.Formatting.FormatAccent = $Flavor.Teal.Foreground()
    $PSStyle.Formatting.TableHeader = $Flavor.Rosewater.Foreground()
    $PSStyle.Formatting.Verbose = $Flavor.Yellow.Foreground()
    $PSStyle.Formatting.Warning = $Flavor.Peach.Foreground()
}
else {
    Write-Warning "Catppuccin module not found - theme not applied" 
}


# ? - Aria2c CLI
if (Get-Command aria2c -ErrorAction SilentlyContinue) {
    Write-Host "aria2c is installed. Loading..." -ForegroundColor Green
} else {
    if ($internetConnectionEstablished) {
        Write-Host "Internet connection established. " -ForegroundColor Green
        Write-Host "Installing aria2c via scoop..." -ForegroundColor Gray
        try {
            scoop install aria2
            Write-Host "aria2c installed successfully." -ForegroundColor Green
            $reloadpending = $true
        } catch {
            Write-Host "An Error Occurred. Check the error above. Running aria2c will not work." -ForegroundColor Red
        }
    } else {
        Write-Host "No internet connection available. Running aria2c will not work." -ForegroundColor Red
    }
}

# ? - Carapace
# Check if carapace is installed then initialize
if (Get-Command carapace -ErrorAction SilentlyContinue) {
    Write-Host "carapace is installed. Loading..." -ForegroundColor Green
    $env:CARAPACE_BRIDGES = 'zsh,fish,bash,inshellisense' # optional
    Set-PSReadLineOption -Colors @{ "Selection" = "`e[7m" }
    Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete
    carapace _carapace | Out-String | Invoke-Expression
} else {
    if ($internetConnectionEstablished) {
        Write-Host "Internet connection established. Installing carapace via scoop..." -ForegroundColor Green
        try {
            scoop install extras/carapace-bin
            Write-Host "carapace installed successfully." -ForegroundColor Green
            $reloadpending = $true
        } catch {
            Write-Host "An Error Occurred. Check the error above. Running carapace will not work." -ForegroundColor Red
        }
    } else {
        Write-Host "No internet connection available. Running carapace will not work." -ForegroundColor Red
    }
}


# * My Aliases
# ? - I use codium than code, and simply I would just change the alias 
Set-Alias code codium
if (Get-Command fastfetch -ErrorAction SilentlyContinue) {
    # Write-Host "fastfetch is installed. Loading..." -ForegroundColor Green
    Set-Alias neofetch fastfetch
} else {
    if ($internetConnectionEstablished) {
        Write-Host "Internet connection established. Installing fastfetch via scoop..." -ForegroundColor Green
        try {
            scoop install fastfetch
            Write-Host "fastfetch installed successfully." -ForegroundColor Green
            $reloadpending = $true
        } catch {
            Write-Host "An Error Occurred. Check the error above. Running fastfetch will not work." -ForegroundColor Red
        }
    } else {
        Write-Host "An Error Occurred. Check the error above. Running fastfetch will not work." -ForegroundColor Red
    }
}

# ================================================================================

if (Get-Command oh-my-posh -ErrorAction SilentlyContinue) {
    Write-Host "oh-my-posh is installed. Loading..." -ForegroundColor Cyan
    oh-my-posh init pwsh --config $env:POSH_THEMES_PATH/emodipt-extend.omp.json | Invoke-Expression
} else {
    if ($internetConnectionEstablished) {
        Write-Host "Internet connection established. Installing oh-my-posh via scoop..." -ForegroundColor Yellow
        try {
            scoop install oh-my-posh
            Write-Host "oh-my-posh installed successfully. Reloading now..." -ForegroundColor Green
            $reloadpending = $true
        } catch {
            Write-Host "Installation failed. Please check the error above." -ForegroundColor Red
        }
    } else {
        Write-Host "No internet connection available. Running oh-my-posh will not work." -ForegroundColor Red
    }
}

# ================================================================================

if (Get-Command zoxide -ErrorAction SilentlyContinue) {
    Write-Host "zoxide is already installed. Loading..." -ForegroundColor Cyan
} else {
    if ($internetConnectionEstablished) {
        Write-Host "Internet connection established. Installing zoxide via scoop..." -ForegroundColor Yellow
        try {
            scoop install zoxide
            Write-Host "zoxide installed successfully." -ForegroundColor Green
            $reloadpending = $true
        } catch {
            Write-Host "Installation failed. Please check the error above." -ForegroundColor Red
        }
    } else {
        Write-Host "No internet connection available. Running zoxide will not work." -ForegroundColor Red
    }
}

# Check if there is a pending reload of the profile
# If there is, reload the profile to ensure that all the new
# modules and aliases are available in the current session
if ($reloadpending -eq $true) {
    Write-Host "A pending reload has been detected. Reloading now..." -ForegroundColor Magenta
    # Reloading the profile
    $reloadpending = $false
    rld
} else {
    Write-Host "No pending reload detected. Continuing..." -ForegroundColor Gray
    # Clear the screen
    # cls
}

Write-Host ""

# * THIS WILL SCROLL THE PROMPT TO THE TOP
# * Feel free to add anything before this
function Set-PromptToTop {
    # Get console window height
    $height = [console]::WindowHeight

    # Output blank lines to scroll up
    for ($i = 0; $i -lt $height - 1; $i++) {
        Write-Host ""
    }

    # Move cursor to top-left corner (0,0)
    [console]::SetCursorPosition(0,0)
}

# Scroll prompt to top to "hide" previous output
Set-PromptToTop

# ? - fastfetch
if (Get-Command fastfetch -ErrorAction SilentlyContinue) {
    fastfetch
} else {
    Write-Host "fastfetch command not found😓. Skipping the cool system info..." -ForegroundColor Red
}
# ? - Line Divider
# If running with elevated privileges and in a command line host, change console color to red
if ($isAdmin -and $Host.Name -eq "ConsoleHost") {
    Write-Host ""
    Write-Host "==============================================================" -ForegroundColor Red
    Write-Host "|  WARNING: Running with elevated privileges.                |" -ForegroundColor Red
    Write-Host "==============================================================" -ForegroundColor Red
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "==============================================================" -ForegroundColor Green
    Write-Host "|  Running with normal user privileges.                      |" -ForegroundColor Green
    Write-Host "==============================================================" -ForegroundColor Green
    Write-Host ""
}

# zoxide init 
# ! MUST BE LAST or else it will not work
if (Get-Command zoxide -ErrorAction SilentlyContinue) {
    Remove-Item Alias:\cd -ErrorAction SilentlyContinue
    Set-Alias cd z
    function cd {
        z 
    }
    Invoke-Expression (& { (zoxide init powershell | Out-String) })
}
