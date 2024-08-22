#!PowerShell
using namespace System.Management.Automation
using namespace System.Management.Automation.Language
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force;

#$CurrentValue = [Environment]::GetEnvironmentVariable("PSModulePath", "Machine")
#[Environment]::SetEnvironmentVariable("PSModulePath", $CurrentValue + ";$env:ProgramFiles\WindowsPowerShell\Modules")
#$env:Path += ";$((Get-ChildItem -Path $RootBin -Directory -Force -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName) -join ';')"

if ($host.Name -eq 'ConsoleHost') {
    #$PROFILE = $PSCommandPath
    #$env:RBENV_ROOT = $RootBin + '\Ruby1'
    #$env:XDG_DATA_HOME= $RootBin + '\.local\share'
    #$env:XDG_CONFIG_HOME = $RootBin + '\.config'

	(get-psprovider 'FileSystem').Home = $env:HOME
    $RootBin = Split-Path $PSHOME -Parent # (Get-Item -Path "$PSHOME").Parent
    $env:PSModulePath += ";$RootBin\PSModules;"
    $env:SEE_MASK_NOZONECHECKS = 1
    $env:POSH_THEME = "$env:XDG_CONFIG_HOME\oh-my-posh\1_shell.omp.json"
    $env:POSH_GIT_ENABLED = 'True'
    $env:POSH_INSTALLER = 'manual'
    #    Import-Module PSReadLine
    Import-Module DirColors
    Import-Module Terminal-Icons
    Import-Module PSWriteColor
    Import-Module PSReadLine
    Import-Module z
    Import-Module PwshComplete
    Import-Module DockerCompletion
    Import-Module PSFzf
    # PSReadLine
    Set-PSReadLineOption -PredictionSource HistoryAndPlugin
    Set-PSReadLineOption -PredictionViewStyle ListView 
    Set-PSReadLineOption -EditMode Windows 
    Set-PSReadLineOption -HistorySearchCursorMovesToEnd 
    Set-PSReadLineOption -ShowToolTips
    Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete 
    Set-PSReadlineKeyHandler -Key UpArrow -Function HistorySearchBackward 
    Set-PSReadlineKeyHandler -Key DownArrow -Function HistorySearchForward
    # Set-PSReadLineKeyHandler -Key Tab -ScriptBlock { Invoke-FzfTabCompletion }
    Set-PsFzfOption -PSReadlineChordProvider 'Ctrl+t' -PSReadlineChordReverseHistory 'Ctrl+r'
    $env:FZF_DEFAULT_COMMAND = 'fd --type f --hidden --follow --exclude .git'
    $env:FZF_DEFAULT_OPT = @(
        '--layout=reverse --inline-info --ansi --bind ctrl-a:select-all,ctrl-d:deselect-all,ctrl-t:toggle'
        '--prompt=" " --marker="" --pointer="◆" --separator="─" --scrollbar="│" --info="right"'
    )
    #$env:FZF_DEFAULT_COMMAND = 'rg --files --hidden --follow --glob "!.git/*"'
    #$env:FZF_DEFAULT_OPTS='--layout=reverse --inline-info --ansi --bind ctrl-a:select-all,ctrl-d:deselect-all,ctrl-t:toggle'
    $env:FZF_CTRL_T_COMMAND = $env:FZF_DEFAULT_COMMAND
    $env:FZF_CTRL_T_OPTS = "--preview 'bat --style=numbers --color=always --line-range :50 {}'"
    $env:FZF_ALT_C_COMMAND = 'fd --type d . --color=always --hidden'
    $env:FZF_ALT_C_OPTS = "--preview 'tree -C {} | head -50'"
    oh-my-posh.exe --init --shell pwsh | Invoke-Expression #--config "$env:POSH_THEMES_PATH\1_shell.omp.json"
    if ((Get-Command "$env:MINGW\vim.exe" -EA Silently )) { set-alias vi "$env:MINGW\vim.exe" }
    if ((Get-Command "$env:MINGW\ssh.exe" -EA Silently )) { set-alias ssh "$env:MINGW\ssh.exe" }
    if ((Get-Command "$env:XDG_APP\Notepad++\Notepad++.exe" -EA Silently )){ set-alias notepad "$env:XDG_APP\Notepad++\Notepad++.exe" }
    if ((Get-Command "$env:XDG_APP\uvnc\uvnc.exe" -EA Silently )) { set-alias uvnc "$env:XDG_APP\uvnc\uvnc.exe" }

}

# function ssh-
#     param(
#         [Parameter(Mandatory = $true, Position = 1, HelpMessage = "nedded argument: user@host")]
#         [string]$user_host
#     )
#     type $env:USERPROFILE\.ssh\id_rsa.pub | ssh -T $user_host "mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys; cat  ~/.ssh/authorized_keys"
# }

# For PowerShell v3
# Function gig {
# param(
# [Parameter(Mandatory=$true)]
# [string[]]$list
# )
# $params = ($list | ForEach-Object { [uri]::EscapeDataString($_) }) -join ","
# Invoke-WebRequest -Uri "https://www.toptal.com/developers/gitignore/api/$params" | select -ExpandProperty content | Out-File -FilePath $(Join-Path -path $pwd -ChildPath ".gitignore") -Encoding ascii
# }

# function testFunction ($arg1, $arg2) {
# Write-Host $arg1
# Write-Host $arg2
# }

function CheckConnectSsh () {
    param ( 
	[string]$RemoteHost,
	[string]$RemotePort='22'  
	)
	begin {
		# if ( $RemotePort )
        # { Write-Host Test-Connection $RemoteHost -IPv4 -ResolveDestination -Count 1 -TcpPort $RemotePort -ErrorAction Stop } 
		# else { Write-Host Test-Connection $RemoteHost -IPv4 -ResolveDestination -Count 1 -ErrorAction Stop }
	}
	process {
		if ( ([bool]( $RemoteHost -as [ipaddress])) `
			-or ([bool]( $RemoteHost -match '^\w+-\w+$')) `
			-or ([bool]( $RemoteHost -match '^\w+.\w+$')) ){
				# Write-Host $exec  
			try {
				$connect = Test-Connection $RemoteHost -IPv4 -ResolveDestination -Count 1 -ErrorAction Stop | select Destination,DisplayAddress
				if ( $RemotePort ){	
						if ( Test-Connection $connect.Destination -IPv4 -Count 1 -TcpPort $RemotePort -ErrorAction Stop )
							{ return @( $connect.Destination, $RemotePort )	}	
						if ( Test-Connection $connect.DisplayAddress -IPv4 -Count 1 -TcpPort $RemotePort -ErrorAction Stop )
							{ return @( $connect.DisplayAddress, $RemotePort ) }	
					}
				if ( $connect.Destination ){ return $connect.Destination, '0' }
				if ( $connect.DisplayAddress ){ return $connect.DisplayAddress, '0' }
			} 
			catch { 
				Write-Error "Not connected $RemoteHost $RemotePort" 
				break
			}
		}
		else {	
			Write-Error "$RemoteHost is not HostName or IP !" 
			break	
		}
	}
}

    # $ip=[system.net.dns]::resolve("localhost")
    # Test-Connection $ip -IPv4 -ResolveDestination -Quiet -Count 1
    # $store_name = $host.UI.RawUI.WindowTitle
    # $host.UI.RawUI.WindowTitle = "ssh: $RemoteHost <> "
    # ssh -t $RemoteHost tmux
    # $host.UI.RawUI.WindowTitle = $store_name 
# }

function _termscp () {
    Param (
        [string]$RemoteHost = "127.0.0.1",
        [string]$LocalPath = "D:\temp"
    )
    $RemoteHost =( [system.net.dns]::GetHostEntry($RemoteHost).HostName ).split('.')[0]
    $store_name = $host.UI.RawUI.WindowTitle
    $host.UI.RawUI.WindowTitle = "scp: $RemoteHost <> $LocalPath "
    termscp $RemoteHost $LocalPath
    $host.UI.RawUI.WindowTitle = $store_name 
}


function _vnc () {
    Param (
        [string]$RemoteHost = "127.0.0.1",
        [int]$RemotePort = "5900"
    )
    $RemoteHost =( [system.net.dns]::GetHostEntry($RemoteHost).HostName ).split('.')[0]
    $OpenPorts = (Get-NetTCPConnection).LocalPort
    $LocalPort = 0
    While ($LocalPort -eq 0) {
        $RandomPort = Get-Random -Minimum 49152 -Maximum 65535
        If ($OpenPorts -notcontains $RandomPort) {
            $LocalPort = $RandomPort
        }
    }
    $command = {
        Param($LocalPort, $RemotePort, $RemoteHost )
        $_ssh = $LocalPort, 'localhost', $RemotePort -join ':'
        $_vnc = 'localhost', $LocalPort -join ':'
        $sshProcessID = Start-Process -PassThru ssh -ArgumentList @('-L', $_ssh , $RemoteHost) -WindowStyle hidden
        Start-Process -Wait uvnc -ArgumentList @('-connect', $_vnc) 
        Stop-Process $sshProcessID
        Exit
    }
    Start-Process pwsh -ArgumentList @('-NoExit', '-nologo', '-noprofile', "-command & { $command } $LocalPort $RemotePort $RemoteHost") -WindowStyle hidden | Out-Null
}

function _uvnc () {
    Param (
        [string]$RemoteUser = "awurthmann",
        [string]$RemoteHost = "10.1.33.7",
        [int]$RemotePort = "5900"
    )
    [int]$Tries = 0
    [bool]$KeepTrying = $True
    [bool]$Connect = $True
    While ($KeepTrying) {
        $Connection = Get-NetTCPConnection | Where { $_.LocalPort -eq $LocalPort }
        If ($Connection) { $KeepTrying = $False }
        Else { $Tries++ }
        If ($Tries -ge 30) {
            $KeepTrying = $False
            $Connect = $False
        }
        Start-Sleep -Seconds 1
    }
    If (!($KeepTrying) -and $Connect) {
        Start-Process -FilePath $VNCFilePath -ArgumentList $VNCHostAndPort
    }
}

Register-ArgumentCompleter -CommandName ssh,scp,sftp -Native -ScriptBlock {
	param($wordToComplete, $commandAst, $cursorPosition)
	$sshConfigFile = "$env:HOME\.ssh\config"
    if (Test-Path $sshConfigFile) {
        Get-Content $sshConfigFile | 
        Where-Object {$_ -match "^Host" -and $_.Split()[1] -like "$wordToComplete*"} |
        ForEach-Object {$_.Split()[1]} |
        Sort-Object -Unique |
        ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    } else {
        return @()
    }
}

Register-ArgumentCompleter -CommandName ssh, scp, sftp, _termscp, _vnc, _ssh -Native -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    function Get-SSHHostList($sshConfigPath) {
        Get-Content -Path $sshConfigPath `
        | Select-String -Pattern '^Host ' `
        | ForEach-Object { $_ -replace 'Host ', '' } `
        | ForEach-Object { $_ -split ' ' } `
        | Sort-Object -Unique `
        | Select-String -Pattern '^.*[*!?].*$' -NotMatch
    }

    function Get-SSHKnownHost($sshKnownHostsPath) {
       Get-Content -Path $sshKnownHostsPath `
       | ForEach-Object { $_.split(' ')[0] } `
       | Sort-Object -Unique
     }
   
    # function Get-SSHConfigFileList ($sshConfigFilePath) {
        # $sshConfigDir = Split-Path -Path $sshConfigFilePath -Resolve -Parent
        # $sshConfigFilePaths = @()
        # $sshConfigFilePaths += $sshConfigFilePath
        # $pathsPatterns = @()
        # Get-Content -Path $sshConfigFilePath `
        # | Select-String -Pattern '^Include ' `
        # | ForEach-Object { $_ -replace 'Include ', '' }  `
        # | ForEach-Object { $_ -replace '~', $Env:USERPROFILE } `
        # | ForEach-Object { $_ -replace '\$Env:USERPROFILE', $Env:USERPROFILE } `
        # | ForEach-Object { $_ -replace '\$Env:HOMEPATH', $Env:USERPROFILE } `
        # | ForEach-Object {
            # $sshConfigFilePaths += $(Get-ChildItem -Path $sshConfigDir\$_ -File -ErrorAction SilentlyContinue -Force).FullName `
            # | ForEach-Object { Get-SSHConfigFileList $_ }
        # }

        # if (($sshConfigFilePaths.Length -eq 1) -and ($sshConfigFilePaths.item(0) -eq $sshConfigFilePath) ) {
            # return $sshConfigFilePath
        # }

        # return $sshConfigFilePaths | Sort-Object -Unique
    # }

    $sshPath = "$Env:HOME\.ssh"
    $hosts = Get-SSHConfigFileList "$sshPath\config" `
    $hosts = Get-SSHKnownHost "$env:HOME\.ssh\known_hosts" 
    
    $hosts = ForEach-Object { Get-SSHHostList "$sshPath\config" } `
    # For now just assume it's a hostname.
    $textToComplete = $wordToComplete
    $generateCompletionText = {
      param($x)
        $x
     }

    if ($wordToComplete -match "^(?<user[-\w/\\]+)@(?<host[-.\w]+)$") {
      $textToComplete = $Matches["host"]
      $generateCompletionText = {
        param($hostname)
        $Matches["user"] + "@" + $hostname
      }
    }

    # $hosts `
    # | Where-Object { $_ -like "${textToComplete}*" } `
    # | ForEach-Object { [CompletionResult]::new((&$generateCompletionText($_)), $_, [CompletionResultType]::ParameterValue, $_) }

}

# function GetKnonwHost (){
 # [regex]$rx = "(?<host>^\S+?)((?=:))?((?<=:)(?<port>\d+))?(,(?<address>\S+))?\s(?<type>[\w-]+)\s(?<thumbprint>.*)"
    # $known = "~\.ssh\known_hosts"
    # Write-Verbose "Testing for $known"
    # if (Test-Path $known) {
        # $content = (Get-Content -Path $known) -split "`n"
        # Write-Verbose "Found $($content.count) entries"

        # #process all entries even if searching for a single hostname because there
        # #might be multiple entries
        # foreach ($entry in $content) {
            # $matched = $rx.Match($entry)
            # $sshHost = $matched.groups["host"].value -replace ":$|\[|\]", ""
            # $IP = $matched.groups["address"].value -replace "\[|\]", ""
            # Write-Verbose "Processing $sshHost"
            # } #foreach entry
            # #regex named captures are case-sensitive
            # #I haven't perfected the regex capture so I'll manually trim and trailing : in the hostname capture
            # $obj = [pscustomobject]@{
                # PSTypeName = "sshKnownHost"
                # Hostname   = $sshHost
                # Port       = $matched.groups["port"].value
                # Address    = $IP
                # Keytype    = $matched.groups["type"].value
                # Thumbprint = $matched.groups["thumbprint"].value
            # }            #add each new object to the list
            # $data.Add($obj)
        # } #foreach entry
    # }

# }

# Register-ArgumentCompleter -CommandName 'ssh', 'scp', 'sftp' -Native -ScriptBlock {
  # param($wordToComplete, $commandAst, $cursorPosition)
   


  # if ($wordToComplete -match '^(?<user>[-\w/\\]+)@(?<host>[-.\w]+)$') {
    # $hosts | Where-Object { $_ -like "$($Matches['host'].ToString())*" } `
    # | ForEach-Object { "$($Matches['user'].ToString())@$_" }
  # }
# }


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


# This key handler shows the entire or filtered history using Out-GridView. The
# typed text is used as the substring pattern for filtering. A selected command
# is inserted to the command line without invoking. Multiple command selection
# is supported, e.g. selected by Ctrl + Click.
# Set-PSReadLineKeyHandler -Key F7 `
# -BriefDescription History `
# -LongDescription 'Show command history' `
# -ScriptBlock {
# $pattern = $null
# [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$pattern, [ref]$null)
# if ($pattern)
# {
# $pattern = [regex]::Escape($pattern)
# }

# $history = [System.Collections.ArrayList]@(
# $last = ''
# $lines = ''
# foreach ($line in [System.IO.File]::ReadLines((Get-PSReadLineOption).HistorySavePath))
# {
# if ($line.EndsWith('`'))
# {
# $line = $line.Substring(0, $line.Length - 1)
# $lines = if ($lines)
# {
# "$lines`n$line"
# }
# else
# {
# $line
# }
# continue
# }

# if ($lines)
# {
# $line = "$lines`n$line"
# $lines = ''
# }

# if (($line -cne $last) -and (!$pattern -or ($line -match $pattern)))
# {
# $last = $line
# $line
# }
# }
# )
# $history.Reverse()

# $command = $history | Out-GridView -Title History -PassThru
# if ($command)
# {
# [Microsoft.PowerShell.PSConsoleReadLine]::RevertLine()
# [Microsoft.PowerShell.PSConsoleReadLine]::Insert(($command -join "`n"))
# }
# }


# # CaptureScreen is good for blog posts or email showing a transaction
# # of what you did when asking for help or demonstrating a technique.
# Set-PSReadLineKeyHandler -Chord 'Ctrl+d,Ctrl+c' -Function CaptureScreen

# # The built-in word movement uses character delimiters, but token based word
# # movement is also very useful - these are the bindings you'd use if you
# # prefer the token based movements bound to the normal emacs word movement
# # key bindings.
# Set-PSReadLineKeyHandler -Key Alt+d -Function ShellKillWord
# Set-PSReadLineKeyHandler -Key Alt+Backspace -Function ShellBackwardKillWord
# Set-PSReadLineKeyHandler -Key Alt+b -Function ShellBackwardWord
# Set-PSReadLineKeyHandler -Key Alt+f -Function ShellForwardWord
# Set-PSReadLineKeyHandler -Key Alt+B -Function SelectShellBackwardWord
# Set-PSReadLineKeyHandler -Key Alt+F -Function SelectShellForwardWord

# #region Smart Insert/Delete

# # The next four key handlers are designed to make entering matched quotes
# # parens, and braces a nicer experience.  I'd like to include functions
# # in the module that do this, but this implementation still isn't as smart
# # as ReSharper, so I'm just providing it as a sample.

# Set-PSReadLineKeyHandler -Key '"',"'" `
# -BriefDescription SmartInsertQuote `
# -LongDescription "Insert paired quotes if not already on a quote" `
# -ScriptBlock {
# param($key, $arg)

# $quote = $key.KeyChar

# $selectionStart = $null
# $selectionLength = $null
# [Microsoft.PowerShell.PSConsoleReadLine]::GetSelectionState([ref]$selectionStart, [ref]$selectionLength)

# $line = $null
# $cursor = $null
# [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$line, [ref]$cursor)

# # If text is selected, just quote it without any smarts
# if ($selectionStart -ne -1)
# {
# [Microsoft.PowerShell.PSConsoleReadLine]::Replace($selectionStart, $selectionLength, $quote + $line.SubString($selectionStart, $selectionLength) + $quote)
# [Microsoft.PowerShell.PSConsoleReadLine]::SetCursorPosition($selectionStart + $selectionLength + 2)
# return
# }

# $ast = $null
# $tokens = $null
# $parseErrors = $null
# [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$ast, [ref]$tokens, [ref]$parseErrors, [ref]$null)

# function FindToken
# {
# param($tokens, $cursor)

# foreach ($token in $tokens)
# {
# if ($cursor -lt $token.Extent.StartOffset) { continue }
# if ($cursor -lt $token.Extent.EndOffset) {
# $result = $token
# $token = $token -as [StringExpandableToken]
# if ($token) {
# $nested = FindToken $token.NestedTokens $cursor
# if ($nested) { $result = $nested }
# }

# return $result
# }
# }
# return $null
# }

# $token = FindToken $tokens $cursor

# # If we're on or inside a **quoted** string token (so not generic), we need to be smarter
# if ($token -is [StringToken] -and $token.Kind -ne [TokenKind]::Generic) {
# # If we're at the start of the string, assume we're inserting a new string
# if ($token.Extent.StartOffset -eq $cursor) {
# [Microsoft.PowerShell.PSConsoleReadLine]::Insert("$quote$quote ")
# [Microsoft.PowerShell.PSConsoleReadLine]::SetCursorPosition($cursor + 1)
# return
# }

# # If we're at the end of the string, move over the closing quote if present.
# if ($token.Extent.EndOffset -eq ($cursor + 1) -and $line[$cursor] -eq $quote) {
# [Microsoft.PowerShell.PSConsoleReadLine]::SetCursorPosition($cursor + 1)
# return
# }
# }

# if ($null -eq $token -or
# $token.Kind -eq [TokenKind]::RParen -or $token.Kind -eq [TokenKind]::RCurly -or $token.Kind -eq [TokenKind]::RBracket) {
# if ($line[0..$cursor].Where{$_ -eq $quote}.Count % 2 -eq 1) {
# # Odd number of quotes before the cursor, insert a single quote
# [Microsoft.PowerShell.PSConsoleReadLine]::Insert($quote)
# }
# else {
# # Insert matching quotes, move cursor to be in between the quotes
# [Microsoft.PowerShell.PSConsoleReadLine]::Insert("$quote$quote")
# [Microsoft.PowerShell.PSConsoleReadLine]::SetCursorPosition($cursor + 1)
# }
# return
# }

# # If cursor is at the start of a token, enclose it in quotes.
# if ($token.Extent.StartOffset -eq $cursor) {
# if ($token.Kind -eq [TokenKind]::Generic -or $token.Kind -eq [TokenKind]::Identifier -or
# $token.Kind -eq [TokenKind]::Variable -or $token.TokenFlags.hasFlag([TokenFlags]::Keyword)) {
# $end = $token.Extent.EndOffset
# $len = $end - $cursor
# [Microsoft.PowerShell.PSConsoleReadLine]::Replace($cursor, $len, $quote + $line.SubString($cursor, $len) + $quote)
# [Microsoft.PowerShell.PSConsoleReadLine]::SetCursorPosition($end + 2)
# return
# }
# }

# # We failed to be smart, so just insert a single quote
# [Microsoft.PowerShell.PSConsoleReadLine]::Insert($quote)
# }

# Set-PSReadLineKeyHandler -Key '(','{','[' `
# -BriefDescription InsertPairedBraces `
# -LongDescription "Insert matching braces" `
# -ScriptBlock {
# param($key, $arg)

# $closeChar = switch ($key.KeyChar)
# {
# <#case# '(' { [char]')'; break }
# <#case# '{' { [char]'}'; break }
# <#case# '[' { [char]']'; break }
# }

# $selectionStart = $null
# $selectionLength = $null
# [Microsoft.PowerShell.PSConsoleReadLine]::GetSelectionState([ref]$selectionStart, [ref]$selectionLength)

# $line = $null
# $cursor = $null
# [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$line, [ref]$cursor)

# if ($selectionStart -ne -1)
# {
# # Text is selected, wrap it in brackets
# [Microsoft.PowerShell.PSConsoleReadLine]::Replace($selectionStart, $selectionLength, $key.KeyChar + $line.SubString($selectionStart, $selectionLength) + $closeChar)
# [Microsoft.PowerShell.PSConsoleReadLine]::SetCursorPosition($selectionStart + $selectionLength + 2)
# } else {
# # No text is selected, insert a pair
# [Microsoft.PowerShell.PSConsoleReadLine]::Insert("$($key.KeyChar)$closeChar")
# [Microsoft.PowerShell.PSConsoleReadLine]::SetCursorPosition($cursor + 1)
# }
# }

# Set-PSReadLineKeyHandler -Key ')',']','}' `
# -BriefDescription SmartCloseBraces `
# -LongDescription "Insert closing brace or skip" `
# -ScriptBlock {
# param($key, $arg)

# $line = $null
# $cursor = $null
# [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$line, [ref]$cursor)

# if ($line[$cursor] -eq $key.KeyChar)
# {
# [Microsoft.PowerShell.PSConsoleReadLine]::SetCursorPosition($cursor + 1)
# }
# else
# {
# [Microsoft.PowerShell.PSConsoleReadLine]::Insert("$($key.KeyChar)")
# }
# }

# Set-PSReadLineKeyHandler -Key Backspace `
# -BriefDescription SmartBackspace `
# -LongDescription "Delete previous character or matching quotes/parens/braces" `
# -ScriptBlock {
# param($key, $arg)

# $line = $null
# $cursor = $null
# [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$line, [ref]$cursor)

# if ($cursor -gt 0)
# {
# $toMatch = $null
# if ($cursor -lt $line.Length)
# {
# switch ($line[$cursor])
# {
# <#case# '"' { $toMatch = '"'; break }
# <#case# "'" { $toMatch = "'"; break }
# <#case# ')' { $toMatch = '('; break }
# <#case# ']' { $toMatch = '['; break }
# <#case# '}' { $toMatch = '{'; break }
# }
# }

# if ($toMatch -ne $null -and $line[$cursor-1] -eq $toMatch)
# {
# [Microsoft.PowerShell.PSConsoleReadLine]::Delete($cursor - 1, 2)
# }
# else
# {
# [Microsoft.PowerShell.PSConsoleReadLine]::BackwardDeleteChar($key, $arg)
# }
# }
# }

# #endregion Smart Insert/Delete

# # Sometimes you enter a command but realize you forgot to do something else first.
# # This binding will let you save that command in the history so you can recall it,
# # but it doesn't actually execute.  It also clears the line with RevertLine so the
# # undo stack is reset - though redo will still reconstruct the command line.
# Set-PSReadLineKeyHandler -Key Alt+w `
# -BriefDescription SaveInHistory `
# -LongDescription "Save current line in history but do not execute" `
# -ScriptBlock {
# param($key, $arg)

# $line = $null
# $cursor = $null
# [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$line, [ref]$cursor)
# [Microsoft.PowerShell.PSConsoleReadLine]::AddToHistory($line)
# [Microsoft.PowerShell.PSConsoleReadLine]::RevertLine()
# }

# # Insert text from the clipboard as a here string
# Set-PSReadLineKeyHandler -Key Ctrl+V `
# -BriefDescription PasteAsHereString `
# -LongDescription "Paste the clipboard text as a here string" `
# -ScriptBlock {
# param($key, $arg)

# Add-Type -Assembly PresentationCore
# if ([System.Windows.Clipboard]::ContainsText())
# {
# # Get clipboard text - remove trailing spaces, convert \r\n to \n, and remove the final \n.
# $text = ([System.Windows.Clipboard]::GetText() -replace "\p{ Zs }*`r?`n","`n").TrimEnd()
# [Microsoft.PowerShell.PSConsoleReadLine]::Insert("@'`n$text`n'@")
# }
# else
# {
# [Microsoft.PowerShell.PSConsoleReadLine]::Ding()
# }
# }

# # Sometimes you want to get a property of invoke a member on what you've entered so far
# # but you need parens to do that.  This binding will help by putting parens around the current selection,
# # or if nothing is selected, the whole line.
# Set-PSReadLineKeyHandler -Key 'Alt+(' `
# -BriefDescription ParenthesizeSelection `
# -LongDescription "Put parenthesis around the selection or entire line and move the cursor to after the closing parenthesis" `
# -ScriptBlock {
# param($key, $arg)

# $selectionStart = $null
# $selectionLength = $null
# [Microsoft.PowerShell.PSConsoleReadLine]::GetSelectionState([ref]$selectionStart, [ref]$selectionLength)

# $line = $null
# $cursor = $null
# [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$line, [ref]$cursor)
# if ($selectionStart -ne -1)
# {
# [Microsoft.PowerShell.PSConsoleReadLine]::Replace($selectionStart, $selectionLength, '(' + $line.SubString($selectionStart, $selectionLength) + ')')
# [Microsoft.PowerShell.PSConsoleReadLine]::SetCursorPosition($selectionStart + $selectionLength + 2)
# }
# else
# {
# [Microsoft.PowerShell.PSConsoleReadLine]::Replace(0, $line.Length, '(' + $line + ')')
# [Microsoft.PowerShell.PSConsoleReadLine]::EndOfLine()
# }
# }

# # Each time you press Alt+', this key handler will change the token
# # under or before the cursor.  It will cycle through single quotes, double quotes, or
# # no quotes each time it is invoked.
# Set-PSReadLineKeyHandler -Key "Alt+'" `
# -BriefDescription ToggleQuoteArgument `
# -LongDescription "Toggle quotes on the argument under the cursor" `
# -ScriptBlock {
# param($key, $arg)

# $ast = $null
# $tokens = $null
# $errors = $null
# $cursor = $null
# [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$ast, [ref]$tokens, [ref]$errors, [ref]$cursor)

# $tokenToChange = $null
# foreach ($token in $tokens)
# {
# $extent = $token.Extent
# if ($extent.StartOffset -le $cursor -and $extent.EndOffset -ge $cursor)
# {
# $tokenToChange = $token

# # If the cursor is at the end (it's really 1 past the end) of the previous token,
# # we only want to change the previous token if there is no token under the cursor
# if ($extent.EndOffset -eq $cursor -and $foreach.MoveNext())
# {
# $nextToken = $foreach.Current
# if ($nextToken.Extent.StartOffset -eq $cursor)
# {
# $tokenToChange = $nextToken
# }
# }
# break
# }
# }

# if ($tokenToChange -ne $null)
# {
# $extent = $tokenToChange.Extent
# $tokenText = $extent.Text
# if ($tokenText[0] -eq '"' -and $tokenText[-1] -eq '"')
# {
# # Switch to no quotes
# $replacement = $tokenText.Substring(1, $tokenText.Length - 2)
# }
# elseif ($tokenText[0] -eq "'" -and $tokenText[-1] -eq "'")
# {
# # Switch to double quotes
# $replacement = '"' + $tokenText.Substring(1, $tokenText.Length - 2) + '"'
# }
# else
# {
# # Add single quotes
# $replacement = "'" + $tokenText + "'"
# }

# [Microsoft.PowerShell.PSConsoleReadLine]::Replace(
# $extent.StartOffset,
# $tokenText.Length,
# $replacement)
# }
# }

# # This example will replace any aliases on the command line with the resolved commands.
# Set-PSReadLineKeyHandler -Key "Alt+%" `
# -BriefDescription ExpandAliases `
# -LongDescription "Replace all aliases with the full command" `
# -ScriptBlock {
# param($key, $arg)

# $ast = $null
# $tokens = $null
# $errors = $null
# $cursor = $null
# [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$ast, [ref]$tokens, [ref]$errors, [ref]$cursor)

# $startAdjustment = 0
# foreach ($token in $tokens)
# {
# if ($token.TokenFlags -band [TokenFlags]::CommandName)
# {
# $alias = $ExecutionContext.InvokeCommand.GetCommand($token.Extent.Text, 'Alias')
# if ($alias -ne $null)
# {
# $resolvedCommand = $alias.ResolvedCommandName
# if ($resolvedCommand -ne $null)
# {
# $extent = $token.Extent
# $length = $extent.EndOffset - $extent.StartOffset
# [Microsoft.PowerShell.PSConsoleReadLine]::Replace(
# $extent.StartOffset + $startAdjustment,
# $length,
# $resolvedCommand)

# # Our copy of the tokens won't have been updated, so we need to
# # adjust by the difference in length
# $startAdjustment += ($resolvedCommand.Length - $length)
# }
# }
# }
# }
# }

# # F1 for help on the command line - naturally
# Set-PSReadLineKeyHandler -Key F1 `
# -BriefDescription CommandHelp `
# -LongDescription "Open the help window for the current command" `
# -ScriptBlock {
# param($key, $arg)

# $ast = $null
# $tokens = $null
# $errors = $null
# $cursor = $null
# [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$ast, [ref]$tokens, [ref]$errors, [ref]$cursor)

# $commandAst = $ast.FindAll( {
# $node = $args[0]
# $node -is [CommandAst] -and
# $node.Extent.StartOffset -le $cursor -and
# $node.Extent.EndOffset -ge $cursor
# }, $true) | Select-Object -Last 1

# if ($commandAst -ne $null)
# {
# $commandName = $commandAst.GetCommandName()
# if ($commandName -ne $null)
# {
# $command = $ExecutionContext.InvokeCommand.GetCommand($commandName, 'All')
# if ($command -is [AliasInfo])
# {
# $commandName = $command.ResolvedCommandName
# }

# if ($commandName -ne $null)
# {
# Get-Help $commandName -ShowWindow
# }
# }
# }
# }


# #
# # Ctrl+Shift+j then type a key to mark the current directory.
# # Ctrj+j then the same key will change back to that directory without
# # needing to type cd and won't change the command line.

# #
# $global:PSReadLineMarks = @{}

# Set-PSReadLineKeyHandler -Key Ctrl+J `
# -BriefDescription MarkDirectory `
# -LongDescription "Mark the current directory" `
# -ScriptBlock {
# param($key, $arg)

# $key = [Console]::ReadKey($true)
# $global:PSReadLineMarks[$key.KeyChar] = $pwd
# }

# Set-PSReadLineKeyHandler -Key Ctrl+j `
# -BriefDescription JumpDirectory `
# -LongDescription "Goto the marked directory" `
# -ScriptBlock {
# param($key, $arg)

# $key = [Console]::ReadKey()
# $dir = $global:PSReadLineMarks[$key.KeyChar]
# if ($dir)
# {
# cd $dir
# [Microsoft.PowerShell.PSConsoleReadLine]::InvokePrompt()
# }
# }

# Set-PSReadLineKeyHandler -Key Alt+j `
# -BriefDescription ShowDirectoryMarks `
# -LongDescription "Show the currently marked directories" `
# -ScriptBlock {
# param($key, $arg)

# $global:PSReadLineMarks.GetEnumerator() | % {
# [PSCustomObject]@{Key = $_.Key; Dir = $_.Value} } |
# Format-Table -AutoSize | Out-Host

# [Microsoft.PowerShell.PSConsoleReadLine]::InvokePrompt()
# }

# # Auto correct 'git cmt' to 'git commit'
# Set-PSReadLineOption -CommandValidationHandler {
# param([CommandAst]$CommandAst)

# switch ($CommandAst.GetCommandName())
# {
# 'git' {
# $gitCmd = $CommandAst.CommandElements[1].Extent
# switch ($gitCmd.Text)
# {
# 'cmt' {
# [Microsoft.PowerShell.PSConsoleReadLine]::Replace(
# $gitCmd.StartOffset, $gitCmd.EndOffset - $gitCmd.StartOffset, 'commit')
# }
# }
# }
# }
# }

# # `ForwardChar` accepts the entire suggestion text when the cursor is at the end of the line.
# # This custom binding makes `RightArrow` behave similarly - accepting the next word instead of the entire suggestion text.
# Set-PSReadLineKeyHandler -Key RightArrow `
# -BriefDescription ForwardCharAndAcceptNextSuggestionWord `
# -LongDescription "Move cursor one character to the right in the current editing line and accept the next word in suggestion when it's at the end of current editing line" `
# -ScriptBlock {
# param($key, $arg)

# $line = $null
# $cursor = $null
# [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$line, [ref]$cursor)

# if ($cursor -lt $line.Length) {
# [Microsoft.PowerShell.PSConsoleReadLine]::ForwardChar($key, $arg)
# } else {
# [Microsoft.PowerShell.PSConsoleReadLine]::AcceptNextSuggestionWord($key, $arg)
# }
# }

# # Cycle through arguments on current line and select the text. This makes it easier to quickly change the argument if re-running a previously run command from the history
# # or if using a psreadline predictor. You can also use a digit argument to specify which argument you want to select, i.e. Alt+1, Alt+a selects the first argument
# # on the command line.
# Set-PSReadLineKeyHandler -Key Alt+a `
# -BriefDescription SelectCommandArguments `
# -LongDescription "Set current selection to next command argument in the command line. Use of digit argument selects argument by position" `
# -ScriptBlock {
# param($key, $arg)

# $ast = $null
# $cursor = $null
# [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$ast, [ref]$null, [ref]$null, [ref]$cursor)

# $asts = $ast.FindAll( {
# $args[0] -is [System.Management.Automation.Language.ExpressionAst] -and
# $args[0].Parent -is [System.Management.Automation.Language.CommandAst] -and
# $args[0].Extent.StartOffset -ne $args[0].Parent.Extent.StartOffset
# }, $true)

# if ($asts.Count -eq 0) {
# [Microsoft.PowerShell.PSConsoleReadLine]::Ding()
# return
# }

# $nextAst = $null

# if ($null -ne $arg) {
# $nextAst = $asts[$arg - 1]
# }
# else {
# foreach ($ast in $asts) {
# if ($ast.Extent.StartOffset -ge $cursor) {
# $nextAst = $ast
# break
# }
# }

# if ($null -eq $nextAst) {
# $nextAst = $asts[0]
# }
# }

# $startOffsetAdjustment = 0
# $endOffsetAdjustment = 0

# if ($nextAst -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
# $nextAst.StringConstantType -ne [System.Management.Automation.Language.StringConstantType]::BareWord) {
# $startOffsetAdjustment = 1
# $endOffsetAdjustment = 2
# }

# [Microsoft.PowerShell.PSConsoleReadLine]::SetCursorPosition($nextAst.Extent.StartOffset + $startOffsetAdjustment)
# [Microsoft.PowerShell.PSConsoleReadLine]::SetMark($null, $null)
# [Microsoft.PowerShell.PSConsoleReadLine]::SelectForwardChar($null, ($nextAst.Extent.EndOffset - $nextAst.Extent.StartOffset) - $endOffsetAdjustment)
# }

# # This is an example of a macro that you might use to execute a command.
# # This will add the command to history.
# Set-PSReadLineKeyHandler -Key Ctrl+Shift+b `
# -BriefDescription BuildCurrentDirectory `
# -LongDescription "Build the current directory" `
# -ScriptBlock {
# [Microsoft.PowerShell.PSConsoleReadLine]::RevertLine()
# [Microsoft.PowerShell.PSConsoleReadLine]::Insert("dotnet build")
# [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
# }

# Set-PSReadLineKeyHandler -Key Ctrl+Shift+t `
# -BriefDescription BuildCurrentDirectory `
# -LongDescription "Build the current directory" `
# -ScriptBlock {
# [Microsoft.PowerShell.PSConsoleReadLine]::RevertLine()
# [Microsoft.PowerShell.PSConsoleReadLine]::Insert("dotnet test")
# [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
# }

