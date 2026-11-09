# Runs the hunt's attack simulation and the benign developer activity inside
# the lab VM, each step as its own child process so Sysmon records the
# command line the way a real shell would launch it. Atomic Red Team
# T1552.001 tests 4, 13 and 14 are run by hand (no Invoke-AtomicRedTeam);
# the AI-key searches are adapted from test 4 and from test 26, the
# Linux/macOS ".env files containing application credentials" search.
#
# Run from an elevated PowerShell (tests 13 and 14 need it) after
# seed-canaries.ps1. Writes one JSON line per step to -LogPath.

param([string] $LogPath = 'Z:\steps.jsonl')

$ErrorActionPreference = 'Stop'
$repos = Join-Path $env:USERPROFILE 'source\repos'
$harvester = 'C:\Users\Public\Documents\collect.ps1'
$keyPattern = "'sk-ant-','sk-proj-','OPENAI_API_KEY','ANTHROPIC_API_KEY'"

# The blind-spot case: the same search, from a script file, so the command
# line carries none of it.
Set-Content -Path $harvester -Encoding utf8 -Value @"
Get-ChildItem -Path `$env:USERPROFILE -Recurse -Force -File -Include .env,.env.*,*.json -ErrorAction SilentlyContinue |
    Select-String -Pattern $keyPattern -List | Select-Object -ExpandProperty Path
"@

$steps = @(
    # Attack simulation
    @{ name = 'atomic-4-findstr-pass'; kind = 'attack'; dir = $env:USERPROFILE; exe = 'powershell.exe'
       args = '-NoProfile -Command "& {findstr /si pass *.xml *.doc *.txt *.xls; ls -R | select-string -ErrorAction SilentlyContinue -Pattern password}"' }
    @{ name = 'atomic-13-credential-files-powershell'; kind = 'attack'; dir = $env:USERPROFILE; exe = 'powershell.exe'
       args = '-NoProfile -Command "& {$usernameinfo = (Get-ChildItem Env:USERNAME).Value; Get-ChildItem -Hidden C:\Users\$usernameinfo\AppData\Roaming\Microsoft\Credentials\; Get-ChildItem -Hidden C:\Users\$usernameinfo\AppData\Local\Microsoft\Credentials\}"' }
    @{ name = 'atomic-14-credential-files-cmd'; kind = 'attack'; dir = $env:USERPROFILE; exe = 'cmd.exe'
       args = '/c "dir /a:h C:\Users\%USERNAME%\AppData\Local\Microsoft\Credentials\ & dir /a:h C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Credentials\"' }
    @{ name = 'ai-findstr-recursive'; kind = 'attack'; dir = $env:USERPROFILE; exe = 'cmd.exe'
       args = '/c findstr /s /i /m /c:"sk-ant-" /c:"sk-proj-" /c:"OPENAI_API_KEY" /c:"ANTHROPIC_API_KEY" *.env *.env.* *.json' }
    @{ name = 'ai-select-string-recursive'; kind = 'attack'; dir = $env:USERPROFILE; exe = 'powershell.exe'
       args = "-NoProfile -Command `"Get-ChildItem -Path `$env:USERPROFILE -Recurse -Force -File -Include .env,.env.*,*.json -ErrorAction SilentlyContinue | Select-String -Pattern $keyPattern -List | Select-Object -ExpandProperty Path`"" }
    @{ name = 'ai-config-read'; kind = 'attack'; dir = $env:USERPROFILE; exe = 'cmd.exe'
       args = '/c type "%APPDATA%\Claude\claude_desktop_config.json" "%USERPROFILE%\.cursor\mcp.json" "%USERPROFILE%\.anthropic\config.json"' }
    @{ name = 'ai-script-harvester'; kind = 'attack'; dir = $env:USERPROFILE; exe = 'powershell.exe'
       args = "-NoProfile -ExecutionPolicy Bypass -File $harvester" }

    # Benign developer activity
    @{ name = 'dev-findstr-one-file'; kind = 'benign'; dir = "$repos\chat-app"; exe = 'cmd.exe'
       args = '/c findstr OPENAI_API_KEY .env' }
    @{ name = 'dev-select-string-one-file'; kind = 'benign'; dir = "$repos\chat-app"; exe = 'powershell.exe'
       args = '-NoProfile -Command "Select-String -Path .env -Pattern OPENAI_API_KEY"' }
    @{ name = 'dev-get-content'; kind = 'benign'; dir = "$repos\rag-service"; exe = 'powershell.exe'
       args = '-NoProfile -Command "Get-Content .env.local"' }
    @{ name = 'dev-todo-search-recursive'; kind = 'benign'; dir = $repos; exe = 'cmd.exe'
       args = '/c findstr /s /i /n TODO *.py *.js' }
    @{ name = 'dev-list-env-files'; kind = 'benign'; dir = $repos; exe = 'cmd.exe'
       args = '/c dir /s /b *.env' }
    @{ name = 'dev-edit-mcp-config'; kind = 'benign'; dir = $env:USERPROFILE; exe = 'notepad.exe'
       args = "`"$env:APPDATA\Claude\claude_desktop_config.json`""; close = $true }
    @{ name = 'av-custom-scan'; kind = 'benign'; dir = $env:USERPROFILE; exe = "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"
       args = "-Scan -ScanType 3 -File `"$repos`"" }
)

$utf8 = New-Object System.Text.UTF8Encoding $false
foreach ($s in $steps) {
    $start = [DateTime]::UtcNow
    if ($s.close) {
        $p = Start-Process -FilePath $s.exe -ArgumentList $s.args -WorkingDirectory $s.dir -PassThru
        Start-Sleep -Seconds 3
        Stop-Process -Id $p.Id
    } else {
        Start-Process -FilePath $s.exe -ArgumentList $s.args -WorkingDirectory $s.dir -Wait -NoNewWindow
    }
    $end = [DateTime]::UtcNow
    $line = [ordered]@{ step = $s.name; kind = $s.kind; exe = $s.exe; args = $s.args; dir = $s.dir
                        start = $start.ToString('o'); end = $end.ToString('o') } | ConvertTo-Json -Compress
    [IO.File]::AppendAllText($LogPath, $line + "`n", $utf8)
    Write-Output "$($s.kind) $($s.name) done"
    Start-Sleep -Seconds 2
}
