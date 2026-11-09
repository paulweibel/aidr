# Exports the Sysmon log from the lab VM as JSON lines, one event per line,
# with EventData flattened to Sysmon's own field names (Image, CommandLine,
# ParentImage, User, TargetFilename, ...). The output goes to the host
# through the shared folder and into Splunk as sourcetype _json; the same
# records are where the Sigma fixtures come from.

param([string] $OutPath = 'Z:\sysmon-events.jsonl')

$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding $false
$lines = foreach ($e in Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -Oldest) {
    $o = [ordered]@{
        TimeCreated = $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        EventID     = $e.Id
        Computer    = $e.MachineName
        RecordID    = $e.RecordId
    }
    foreach ($d in ([xml]$e.ToXml()).Event.EventData.Data) { $o[$d.Name] = $d.'#text' }
    $o | ConvertTo-Json -Compress
}
[IO.File]::WriteAllLines($OutPath, [string[]]$lines, $utf8)
Write-Output "$($lines.Count) events written to $OutPath"
