#!PowerShell
using namespace System.Management.Automation
using namespace System.Management.Automation.Language
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force;
#$CurrentValue = [Environment]::GetEnvironmentVariable("PSModulePath", "Machine")
#[Environment]::SetEnvironmentVariable("PSModulePath", $CurrentValue + ";$env:ProgramFiles\WindowsPowerShell\Modules")
# (get-psprovider 'FileSystem').Home = $env:HOME
# Set-Variable HOME $env:HOME -Force

$RootBin = Split-Path $PSHOME -Parent # (Get-Item -Path "$PSHOME").Parent
$PROFILE = $PSCommandPath
$env:XDG_DATA_HOME= $RootBin + '\.local\share'
$env:XDG_CONFIG_HOME = $RootBin + '\.config' 
$env:PSModulePath +=";$RootBin\PSModules"
$env:Path += ";$((Get-ChildItem -Path $RootBin -Directory -Force -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName) -join ';')"

if ($host.Name -eq 'ConsoleHost')
{
	$env:TERM="xterm-256color"
    $env:SEE_MASK_NOZONECHECKS = 1
    $env:DISPLAY="127.0.0.1:0"
	$env:LANG="ru_RU.UTF-8"
    $VIMRC="$env:XDG_CONFIG_HOME\vimfiles\vimrc"
	$env:VIMINIT="source $VIMRC"
	$env:POSH_THEME="$env:XDG_CONFIG_HOME\oh-my-posh\1_shell.omp.json"
	$env:POSH_GIT_ENABLED='True'
    $env:POSH_INSTALLER='manual'
    
    Import-Module PSReadLine
	Import-Module DirColors
	Import-Module Terminal-Icons
	Import-Module PSWriteColor
	# Import-Module z
	# Import-Module kbupdate
	Import-Module PwshComplete
	Import-Module posh-git
	Import-Module DockerCompletion
	#Import-Module PSFzf
	# set-alias code "Desktop.ps1"
	#if ( "$env:USERPROFILE\.ssh\config" | Test-Path) {$SSH="$env:USERPROFILE\.ssh\config"}
	# if ("c:\Program Files\Notepad++" | Test-Path) {$env:Path +=$env:BINDIr';set-alias nano notepad++}
	if ((Get-Command "vim.exe" -ErrorAction SilentlyContinue) -eq $null) 
	{ 
		function vi { vim.exe }
		# $args --rcfile $RootPath\bin\.nanorc }
		# set-alias nano1 "$RootPath\bin\nano.exe 
	}
	
  # if ("nano.exe" | Test-Path) { set-alias nano nano.exe --rcfile $env:BINDIR\.nanorc }
  if ("C:\Program Files\Microsoft VS Code Insiders\Code - Insiders.exe" | Test-Path) {$env:Path += 'C:\Program Files\Microsoft VS Code Insiders'; set-alias code "Code - Insiders.exe"}
	set-alias ssh-copy-id ssh-copy-key 
	#Invoke-Expression -Command $(gh completion -s powershell | Out-String)
    # PSReadLine
    Set-PSReadLineOption -PredictionSource History
    Set-PSReadLineOption -PredictionViewStyle ListView
    Set-PSReadLineOption -EditMode Windows
    Set-PSReadLineKeyHandler -Key Tab -Function Complete
	Set-PSReadLineKeyHandler -Key UpArrow -Function HistorySearchBackward
	Set-PSReadLineKeyHandler -Key DownArrow -Function HistorySearchForward
    
	
	$env:FZF_DEFAULT_COMMAND='fd --type f --hidden --follow --exclude .git'
	$env:FZF_DEFAULT_OPT = @(
		'--layout=reverse --inline-info --ansi --bind ctrl-a:select-all,ctrl-d:deselect-all,ctrl-t:toggle'
		'--prompt="> " --marker=">" --pointer="◆" --separator="─" --scrollbar="│" --info="right"'
		)
    #$env:FZF_DEFAULT_COMMAND = 'rg --files --hidden --follow --glob "!.git/*"'
	#$env:FZF_DEFAULT_OPTS='--layout=reverse --inline-info --ansi --bind ctrl-a:select-all,ctrl-d:deselect-all,ctrl-t:toggle'
	$env:FZF_CTRL_T_COMMAND=$env:FZF_DEFAULT_COMMAND 
	$env:FZF_CTRL_T_OPTS="--preview 'bat --style=numbers --color=always --line-range :50 {}'"
	$env:FZF_ALT_C_COMMAND='fd --type d . --color=always --hidden'
	$env:FZF_ALT_C_OPTS="--preview 'tree -C {} | head -50'"
   # PSfzf
    Import-Module PSFzf
    # Override PSReadLine's history search
    Set-PsFzfOption -PSReadlineChordProvider 'Ctrl+t' -PSReadlineChordReverseHistory 'Ctrl+r'
    # Override default tab completion
    Set-PSReadLineKeyHandler -Key Tab -ScriptBlock { Invoke-FzfTabCompletion }
    oh-my-posh.exe --init --shell pwsh | Invoke-Expression #--config "$env:POSH_THEMES_PATH\1_shell.omp.json"
}

# set-alias desktop "Desktop.ps1"

function ssh-copy-key () {
     param(
        [Parameter(Mandatory = $true, Position = 1, HelpMessage = "nedded argument: user@host")]
        [string]$user_host
    )
  type $env:USERPROFILE\.ssh\id_rsa.pub | ssh -T $user_host "mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys; cat >> ~/.ssh/authorized_keys"
}

#For PowerShell v3
# Function gig {
  # param(
    # [Parameter(Mandatory=$true)]
    # [string[]]$list
  # )
  # $params = ($list | ForEach-Object { [uri]::EscapeDataString($_) }) -join ","
  # Invoke-WebRequest -Uri "https://www.toptal.com/developers/gitignore/api/$params" | select -ExpandProperty content | Out-File -FilePath $(Join-Path -path $pwd -ChildPath ".gitignore") -Encoding ascii
# }

function testFunction ($arg1, $arg2) {
  Write-Host $arg1
  Write-Host $arg2
}

function _ssh ($arg1) {
  $ips = [System.Net.Dns]::GetHostAddresses($arg1)[0]
  ssh $ips
}

function _vnctun ($arg1) {
  $ips = [System.Net.Dns]::GetHostAddresses($arg1)[0]
  ssh -L 5901:localhost:5900 $ips
}

function _uvnc ($arg1) {
  _vnctun($arg1)
  uvncviewer localhost:5001
}
function _tvnc ($arg1) {
    _vnctun($arg1)
	tvncviewer localhost:5001
}

# Register-ArgumentCompleter -Native -CommandName winget -ScriptBlock {
    # param($wordToComplete, $commandAst, $cursorPosition)
        # [Console]::InputEncoding = [Console]::OutputEncoding = $OutputEncoding = [System.Text.Utf8Encoding]::new()
        # $Local:word = $wordToComplete.Replace('"', '""')
        # $Local:ast = $commandAst.ToString().Replace('"', '""')
        # winget complete --word="$Local:word" --commandline "$Local:ast" --position $cursorPosition | ForEach-Object {
            # [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        # }
# }

# PowerShell parameter completion shim for the dotnet CLI
# Register-ArgumentCompleter -Native -CommandName dotnet -ScriptBlock {
     # param($commandName, $wordToComplete, $cursorPosition)
         # dotnet complete --position $cursorPosition "$wordToComplete" | ForEach-Object {
            # [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
         # }
 # }

# ---
