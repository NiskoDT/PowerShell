Write-Host "Loading profile..." -ForegroundColor Green
Write-Host ""

#region Initialization of states
# * Admin Check and Internet Connection
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
#endregion Initialization of states

#region Profile Utilities
function rld {
    Write-Host ""
    Write-Host "Profile will be reloaded in 5 seconds..." -ForegroundColor Yellow
    Write-Host "Press Ctrl + C to cancel!" -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    . $PROFILE.CurrentUserAllHosts
}
#endregion Profile Utilities

#region Terminal Package Managers
# Scoop
$script:scoopAvailable = $null -ne (Get-Command scoop -ErrorAction SilentlyContinue)
if ($script:scoopAvailable) {
    if (-not $script:scoopSearchDone) {
        Write-Host "Running scoop-search hook..."
        Invoke-Expression (&scoop-search --hook)
        $script:scoopSearchDone = $true
    }
} else {
    Write-Host "Scoop is not installed." -ForegroundColor Yellow
    Write-Host "  Install manually: iex (irm https://get.scoop.sh)" -ForegroundColor Gray
}

# Chocolatey
if (Get-Command choco -ErrorAction SilentlyContinue) {
    $ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
    if (Test-Path($ChocolateyProfile)) {
        Import-Module "$ChocolateyProfile"
    }
} else {
    Write-Host "Chocolatey is not installed." -ForegroundColor Yellow
}

# * - PSReadLine
if (-not (Get-Module -ListAvailable -Name PSReadLine)) {
    try {
        Install-Module -Name PSReadLine -Force -Repository PSGallery
    } catch {
        Write-Error "Failed to install PSReadLine module. Error: $_"
        return
    }
    if (Get-Module -ListAvailable -Name PSReadLine) {
        Import-Module "PSReadline"
    } else {
        Write-Error "Failed to load PSReadLine module after installation."
        return
    }
}

Set-PSReadLineOption -PredictionSource HistoryAndPlugin
Set-PSReadLineOption -PredictionViewStyle ListView

# Key Bindings
Set-PSReadLineKeyHandler -Key UpArrow -Function HistorySearchBackward
Set-PSReadLineKeyHandler -Key DownArrow -Function HistorySearchForward
Set-PSReadLineKeyHandler -Chord 'Ctrl+d' -Function DeleteChar
Set-PSReadLineKeyHandler -Chord 'Ctrl+w' -Function BackwardDeleteWord
Set-PSReadLineKeyHandler -Chord 'Alt+d' -Function DeleteWord
Set-PSReadLineKeyHandler -Chord 'Ctrl+LeftArrow' -Function BackwardWord
Set-PSReadLineKeyHandler -Chord 'Ctrl+RightArrow' -Function ForwardWord
Set-PSReadLineKeyHandler -Chord 'Ctrl+z' -Function Undo
Set-PSReadLineKeyHandler -Chord 'Ctrl+y' -Function Redo

# PSReadLine Colors
Set-PSReadLineOption -Colors @{
    Command   = '#87CEEB'
    Parameter = '#98FB98'
    Operator  = '#FFB6C1'
    Variable  = '#DDA0DD'
    String    = '#FFDAB9'
    Number    = '#B0E0E6'
    Type      = '#F0E68C'
    Comment   = '#D3D3D3'
    Keyword   = '#8367c7'
    Error     = '#FF6347'
}

# ? - Terminal-Icons
if (Get-Module -ListAvailable -Name Terminal-Icons) {
    Import-Module -Name Terminal-Icons
} else {
    Write-Warning "Terminal-Icons module not found."
}

# ? - gsudo
function Initialize-gsudo {
    try {
        Import-Module 'gsudoModule' -ErrorAction Stop
        Write-Host "gsudo is installed." -ForegroundColor Green
        Set-Alias -Name su -Value gsudo
        Set-Alias -Name sudo -Value gsudo
        return $true
    } catch {
        return $false
    }
}

if (-not (Initialize-gsudo)) {
    if ($script:scoopAvailable) {
        Write-Host "gsudo module failed to load. Reinstalling via scoop..." -ForegroundColor Yellow
        try {
            $null = Invoke-Expression "scoop install gsudo 2>&1" -ErrorAction Stop
            if (Get-Command gsudo -ErrorAction SilentlyContinue) {
                if (Initialize-gsudo) {
                    Write-Host "gsudo reinstalled successfully." -ForegroundColor Green
                } else {
                    Write-Host "gsudo reinstalled but module still fails to load." -ForegroundColor Red
                    Write-Host "  Try manually: scoop install gsudo" -ForegroundColor Gray
                }
            } else {
                Write-Host "gsudo reinstall reported success but command still missing." -ForegroundColor Red
                Write-Host "  Try manually: scoop install gsudo" -ForegroundColor Gray
            }
        } catch {
            Write-Host "gsudo install/reinstall failed." -ForegroundColor Red
            Write-Host "  Install manually: scoop install gsudo" -ForegroundColor Gray
        }
    } else {
        Write-Host "gsudo not found." -ForegroundColor Red
        Write-Host "  Install: scoop install gsudo" -ForegroundColor Gray
    }
}
#endregion Terminal Package Managers

#region Editor Configuration
$terminalEditor = if (Test-CommandExists nvim) { 'nvim' }
                  elseif (Test-CommandExists vim) { 'vim' }
                  else { $null }

$appEditor = if (Test-CommandExists code) { 'code' }
              elseif (Test-CommandExists codium) { 'codium' }
              elseif (Test-CommandExists notepad++) { 'notepad++' }
              elseif (Test-CommandExists sublime_text) { 'sublime_text' }
              else { 'notepad' }

$editor = if ($terminalEditor) { $terminalEditor } else { $appEditor }

function Edit-Profile {
    param($EditorOverride)
    if ([string]::IsNullOrEmpty($EditorOverride)) {
        & $script:editor $PROFILE.CurrentUserAllHosts
    } else {
        & $EditorOverride $PROFILE.CurrentUserAllHosts
    }
}
#endregion Editor Configuration

# Navigation and Utilities
function cd... { Set-Location ..\.. }
function cd.... { Set-Location ..\..\.. }

function md5 { param($Path) Get-FileHash -Algorithm MD5 $Path }
function sha1 { param($Path) Get-FileHash -Algorithm SHA1 $Path }
function sha256 { param($Path) Get-FileHash -Algorithm SHA256 $Path }

function aedit { if ($appEditor) { & $appEditor $args } else { Write-Error "No app-based editor found" } }
function tedit { if ($terminalEditor) { & $terminalEditor $args } else { Write-Error "No terminal editor found" } }

function HKLM: { Set-Location HKLM: }
function HKCU: { Set-Location HKCU: }
function Env: { Set-Location Env: }

function dirs {
    param([string[]]$Patterns)
    if ($Patterns.Count -gt 0) {
        Get-ChildItem -Recurse -Path "$pwd\*" -Include $Patterns | ForEach-Object FullName
    } else {
        Get-ChildItem -Recurse | ForEach-Object FullName
    }
}

function touch {
    param($File)
    if (Test-Path $File) {
        (Get-Item $File).LastWriteTime = Get-Date
    } else {
        New-Item $File -ItemType File | Out-Null
    }
}

function mkcd {
    param($Path)
    New-Item -Path $Path -ItemType Directory -Force | Out-Null
    Set-Location -Path $Path
}

function trash($Path) {
    if (Test-Path $Path -PathType Container) {
        [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory($Path, 'OnlyErrorDialogs', 'SendToRecycleBin')
    } else {
        [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($Path, 'OnlyErrorDialogs', 'SendToRecycleBin')
    }
}

function nf { param($Name) New-Item -ItemType "file" -Path . -Name $Name }

function ff {
    param($Name)
    Get-ChildItem -Recurse -Filter $Name -File | Select-Object -ExpandProperty FullName
}

function head {
    param($Path, $n = 10)
    Get-Content $Path -Head $n
}

function tail {
    param($Path, $n = 10)
    Get-Content $Path -Tail $n
}

function sed {
    param($File, $Find, $Replace)
    (Get-Content $File) -replace "$Find", "$Replace" | Set-Content $File
}

function which {
    param($Name)
    (Get-Command $Name).Source
}

function pgrep($Name) {
    Get-Process -Name $Name -ErrorAction SilentlyContinue
}

function pkill($Name) {
    Get-Process -Name $Name -ErrorAction SilentlyContinue | Stop-Process -Force
}

function k9($Name) {
    pkill $Name
}

function uptime {
    (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime | Select-Object Days, Hours, Minutes, Seconds
}

function docs {
    Set-Location -Path ([Environment]::GetFolderPath("MyDocuments"))
}

function dtop {
    Set-Location -Path ([Environment]::GetFolderPath("Desktop"))
}

function cpy { Set-Clipboard $args[0] }
function pst { Get-Clipboard }

function flushdns { Clear-DnsClientCache }

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
    $defaultRoute = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1
    if ($defaultRoute) {
        $localIpv4 = (Get-NetIPAddress -InterfaceIndex $defaultRoute.InterfaceIndex -AddressFamily IPv4).IPAddress
        $localIpv6 = (Get-NetIPAddress -InterfaceIndex $defaultRoute.InterfaceIndex -AddressFamily IPv6).IPAddress
    }
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

function hb {
    param($FilePath)
    if (-not $FilePath) { Write-Error "No file path specified."; return }
    if (-not (Test-Path $FilePath)) { Write-Error "File path does not exist."; return }
    $Content = Get-Content $FilePath -Raw
    try {
        $response = Invoke-RestMethod -Uri "https://bin.christitus.com/documents" -Method Post -Body $Content -ErrorAction Stop
        Write-Output "https://bin.christitus.com/$($response.key)"
    } catch {
        Write-Error "Failed to upload the document. Error: $_"
    }
}

function df { get-volume }
function sysinfo { Get-ComputerInfo }

function weather {
    param(
        [Parameter(Position = 0)]
        [string]$Location
    )
    $url = if ($Location) {
        "https://wttr.in/$($Location -replace ' ', '+')?m&format=v2"
    } else {
        "https://wttr.in/?m&format=v2"
    }
    try {
        (Invoke-WebRequest -Uri $url -UseBasicParsing).Content
    } catch {
        Write-Error "Failed to fetch weather: $_"
    }
}

# Override ping: calls gping instead (scoop package with per-hop timeline chart)
# Falls back to stock ping.exe if gping is missing.
function ping {
    if (Get-Command gping -ErrorAction SilentlyContinue) {
        gping @args
    } else {
        & "$env:SystemRoot\System32\ping.exe" @args
    }
}

function clx {
    $height = [console]::WindowHeight
    for ($i = 0; $i -lt $height - 1; $i++) { Write-Host "" }
    [console]::SetCursorPosition(0, 0)
}

function la { Get-ChildItem -Path . -Force | Format-Table -AutoSize }
function ll { Get-ChildItem -Path . -Force -Hidden | Format-Table -AutoSize }

# Aliases
Set-Alias -Name unzip -Value Expand-Archive
# Override grep: calls ripgrep (rg). Respects .gitignore, skips binary files, color output.
function grep {
    if (Get-Command rg -ErrorAction SilentlyContinue) {
        rg @args
    } else {
        Select-String @args
    }
}

# Override cat: calls bat instead. Adds syntax highlighting, line numbers, git gutter.
function cat {
    if (Get-Command bat -ErrorAction SilentlyContinue) {
        bat @args
    } else {
        Get-Content @args
    }
}

# Git Shortcuts
function gs { git status }
function ga { git add . }
function gc { param($m) git commit -m "$m" }
function gp { git push }
function gpush { git push }
function gpull { git pull }
function gcl { git clone $args }
function gcom {
    git add .
    git commit -m "$args"
}
function lazyg {
    git add .
    git commit -m "$args"
    git push
}
function g { __zoxide_z github }

# System Utilities
function winutil { Invoke-RestMethod https://christitus.com/win | Invoke-Expression }
function winutildev { Invoke-RestMethod https://christitus.com/windev | Invoke-Expression }

# Help Function
function Show-Help {
    $_t = $PSStyle.Foreground.BrightMagenta
    $_s = $PSStyle.Foreground.BrightBlue
    $_c = $PSStyle.Foreground.BrightGreen
    $_d = $PSStyle.Foreground.BrightWhite
    $_a = $PSStyle.Foreground.BrightYellow
    $_m = $PSStyle.Foreground.BrightBlack
    $_r = $PSStyle.Reset
    Write-Host @"
${_t}POWERSHELL PROFILE HELP${_r}
${_m}========================${_r}
${_s}EDIT${_r}
  ${_c}Edit-Profile${_r}            ${_a}->${_r} ${_d}Open profile in editor${_r}
  ${_c}rld${_r}                     ${_a}->${_r} ${_d}Reload profile${_r}
${_s}GIT${_r}
  ${_c}g${_r}                       ${_a}->${_r} ${_d}Go to github directory${_r}
  ${_c}ga${_r}                      ${_a}->${_r} ${_d}git add .${_r}
  ${_c}gcl<repo>${_r}               ${_a}->${_r} ${_d}git clone${_r}
  ${_c}gcom<msg>${_r}               ${_a}->${_r} ${_d}add+commit${_r}
  ${_c}gp/gpush${_r}                ${_a}->${_r} ${_d}git push${_r}
  ${_c}gpull${_r}                   ${_a}->${_r} ${_d}git pull${_r}
  ${_c}gs${_r}                      ${_a}->${_r} ${_d}git status${_r}
  ${_c}lazyg<msg>${_r}              ${_a}->${_r} ${_d}add+commit+push${_r}
${_s}FILES${_r}
  ${_c}dirs[pat]${_r}               ${_a}->${_r} ${_d}Recursive listing${_r}
  ${_c}ff<name>${_r}                ${_a}->${_r} ${_d}Find files${_r}
  ${_c}grep<pat>${_r}               ${_a}->${_r} ${_d}Search text${_r}
  ${_c}head<file>${_r}              ${_a}->${_r} ${_d}First 10 lines${_r}
  ${_c}tail<file>${_r}              ${_a}->${_r} ${_d}Last 10 lines${_r}
  ${_c}touch<file>${_r}             ${_a}->${_r} ${_d}Create/update file${_r}
  ${_c}mkcd<dir>${_r}               ${_a}->${_r} ${_d}Create+enter dir${_r}
  ${_c}nf<name>${_r}                ${_a}->${_r} ${_d}New file here${_r}
  ${_c}trash<path>${_r}             ${_a}->${_r} ${_d}Recycle bin${_r}
${_s}SYSTEM${_r}
  ${_c}docs${_r}                    ${_a}->${_r} ${_d}Documents folder${_r}
  ${_c}dtop${_r}                    ${_a}->${_r} ${_d}Desktop folder${_r}
  ${_c}uptime${_r}                  ${_a}->${_r} ${_d}System uptime${_r}
  ${_c}Get-IP${_r}                  ${_a}->${_r} ${_d}Show IP addrs${_r}
  ${_c}flushdns${_r}                ${_a}->${_r} ${_d}Clear DNS cache${_r}
  ${_c}winutil${_r}                 ${_a}->${_r} ${_d}Run WinUtil${_r}
${_s}PROCESS${_r}
  ${_c}k9<name>${_r}                ${_a}->${_r} ${_d}Kill process${_r}
  ${_c}pgrep<name>${_r}             ${_a}->${_r} ${_d}Find process${_r}
  ${_c}pkill<name>${_r}             ${_a}->${_r} ${_d}Stop process${_r}
${_s}UTILITIES${_r}
  ${_c}cpy${_r}                     ${_a}->${_r} ${_d}Copy clipboard${_r}
  ${_c}pst${_r}                     ${_a}->${_r} ${_d}Paste clipboard${_r}
  ${_c}which<name>${_r}             ${_a}->${_r} ${_d}Locate command${_r}
  ${_c}sed<f><find><rpl>${_r}       ${_a}->${_r} ${_d}Replace in file${_r}
  ${_c}clx${_r}                     ${_a}->${_r} ${_d}Clear scroll buf${_r}
${_m}========================${_r}
"@
}

# User Aliases
Set-Alias code codium

# Env Paths
$Env:KOMOREBI_CONFIG_HOME = '%userprofile%\.config\komorebi'
$env:PATH += ";%userprofile%\AppData\Local\pnpm"
# fzf file listing via ripgrep: faster, respects .gitignore, includes hidden files
$env:FZF_DEFAULT_COMMAND = 'rg --files --hidden --follow --glob "!.git"'

# Tools Detection: auto-install via scoop, warn on failure
$tools = @(
    @{Name="aria2c"; Display="aria2c"; InstallCmd="scoop install aria2"},
    @{Name="rg"; Display="ripgrep"; InstallCmd="scoop install ripgrep"},
    @{Name="gping"; Display="gping"; InstallCmd="scoop install gping"},
    @{Name="bat"; Display="bat"; InstallCmd="scoop install bat"}
)
foreach ($tool in $tools) {
    if (Get-Command $tool.Name -ErrorAction SilentlyContinue) {
        Write-Host "$($tool.Display) is installed." -ForegroundColor Green
    } elseif ($script:scoopAvailable) {
        Write-Host "$($tool.Display) not found. Attempting install..." -ForegroundColor Yellow
        try {
            $null = Invoke-Expression "$($tool.InstallCmd) 2>&1" -ErrorAction Stop
            if (Get-Command $tool.Name -ErrorAction SilentlyContinue) {
                Write-Host "$($tool.Display) installed successfully." -ForegroundColor Green
            } else {
                Write-Host "$($tool.Display) install reported success but command still missing." -ForegroundColor Red
                Write-Host "  Try manually: $($tool.InstallCmd)" -ForegroundColor Gray
            }
        } catch {
            Write-Host "$($tool.Display) install failed." -ForegroundColor Red
            Write-Host "  Install manually: $($tool.InstallCmd)" -ForegroundColor Gray
        }
    } else {
        Write-Host "$($tool.Display) not found." -ForegroundColor Red
        Write-Host "  Install: $($tool.InstallCmd)" -ForegroundColor Gray
    }
}

# carapace
if (Get-Command carapace -ErrorAction SilentlyContinue) {
    Write-Host "carapace is installed." -ForegroundColor Green
    $env:CARAPACE_BRIDGES = 'zsh,fish,bash,inshellisense'
    Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete
    carapace _carapace | Out-String | Invoke-Expression
} elseif ($script:scoopAvailable) {
    Write-Host "carapace not found. Attempting install..." -ForegroundColor Yellow
    try {
        $null = Invoke-Expression "scoop install carapace-bin 2>&1" -ErrorAction Stop
        if (Get-Command carapace -ErrorAction SilentlyContinue) {
            Write-Host "carapace installed successfully." -ForegroundColor Green
            $env:CARAPACE_BRIDGES = 'zsh,fish,bash,inshellisense'
            Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete
            carapace _carapace | Out-String | Invoke-Expression
        } else {
            Write-Host "carapace install reported success but command still missing." -ForegroundColor Red
            Write-Host "  Try manually: scoop install carapace-bin" -ForegroundColor Gray
        }
    } catch {
        Write-Host "carapace install failed." -ForegroundColor Red
        Write-Host "  Install manually: scoop install carapace-bin" -ForegroundColor Gray
    }
} else {
    Write-Host "carapace not found." -ForegroundColor Red
    Write-Host "  Install: scoop install carapace-bin" -ForegroundColor Gray
}

# langflow completer
$env:DO_NOT_TRACK = "true"
Register-ArgumentCompleter -Native -CommandName langflow -ScriptBlock {
    param($w, $ca, $cp)
    $Env:_LANGFLOW_COMPLETE = "complete_powershell"
    $Env:_TYPER_COMPLETE_ARGS = $ca.ToString()
    $Env:_TYPER_COMPLETE_WORD_TO_COMPLETE = $w
    langflow | ForEach-Object {
        $parts = $_ -Split ":::"
        [System.Management.Automation.CompletionResult]::new($parts[0], $parts[0], 'ParameterValue', $parts[1])
    }
    $Env:_LANGFLOW_COMPLETE = $Env:_TYPER_COMPLETE_ARGS = $Env:_TYPER_COMPLETE_WORD_TO_COMPLETE = ""
}

# Window Title + Prompt
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$Host.UI.RawUI.WindowTitle = "PowerShell {0}$(if ($isAdmin) { ' [ADMIN]' } else { '' })" -f $PSVersionTable.PSVersion.ToString()

function prompt {
    if ($isAdmin) { "[" + (Get-Location) + "] # " } else { "[" + (Get-Location) + "] $ " }
}

# fzf + ripgrep interactive file content search
function rfv {
    param([string]$Query = '')
    $reload = 'reload:rg --column --color=always --smart-case {q} || :'
    fzf --disabled --ansi --multi `
        --bind "start:$reload" `
        --bind "change:$reload" `
        --bind "enter:execute($editor {1})" `
        --delimiter : `
        --preview "bat --style=full --color=always --highlight-line {2} {1}" `
        --preview-window '~4,+{2}+4/3,<80(up)' `
        --query "$Query"
}

# oh-my-posh deferred init
$poshTheme = if (-not [string]::IsNullOrWhiteSpace($env:POSH_THEME)) { $env:POSH_THEME } else { "$env:POSH_THEMES_PATH/emodipt-extend.omp.json" }
$shouldInitPosh = (Get-Command oh-my-posh -ErrorAction SilentlyContinue) -and (Test-Path $poshTheme)
if (-not (Get-Command oh-my-posh -ErrorAction SilentlyContinue)) { Write-Warning "oh-my-posh is not installed." }
elseif (-not (Test-Path $poshTheme)) { Write-Warning "oh-my-posh theme not found at $poshTheme." }

# zoxide deferred init
$shouldInitZoxide = $null -ne (Get-Command zoxide -ErrorAction SilentlyContinue)
if (-not $shouldInitZoxide) { Write-Warning "zoxide is not installed." }

# conda initialize
If (Test-Path "C:\Users\Epb\miniforge3\Scripts\conda.exe") {
    (& "C:\Users\Epb\miniforge3\Scripts\conda.exe" "shell.powershell" "hook") | Out-String | ?{$_} | Invoke-Expression
}

clx

# fastfetch at startup
if (Get-Command fastfetch -ErrorAction SilentlyContinue) { fastfetch }

# Admin Warning
if ($isAdmin -and $Host.Name -eq "ConsoleHost") {
    Write-Host "`nWARNING: Running with ELEVATED privileges.`n" -ForegroundColor Red
} else {
    Write-Host "Running with normal user privileges." -ForegroundColor Green
}

Write-Host "Use 'Show-Help' to list all available functions`n" -ForegroundColor Yellow

# Init Commands (MUST be last)
if ($shouldInitPosh) {
    Invoke-Expression (& { (oh-my-posh init pwsh --config $poshTheme | Out-String) })
}
if ($shouldInitZoxide) {
    Invoke-Expression (& { (zoxide init powershell | Out-String) })
    Remove-Item Alias:\cd -ErrorAction SilentlyContinue
    function global:cd { __zoxide_z @args }
}