# Seeds fake AI API keys where a developer's real ones tend to live, inside
# the lab VM only. Every key is random and carries AIDRLABCANARY so nothing
# here can be mistaken for a live credential. The script holds no
# key-shaped string; the keys exist only in the VM. It refuses to overwrite
# an existing file (a real Claude Desktop or Cursor config, if run by mistake
# outside the VM); -Force re-seeds the lab.

param([switch] $Force)

$ErrorActionPreference = 'Stop'

function New-FakeKey([string] $Prefix, [int] $Length) {
    $chars = [char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    $body = -join (1..$Length | ForEach-Object { $chars | Get-Random })
    return "$Prefix" + 'AIDRLABCANARY' + $body
}

function Write-Canary([string] $Path, [string] $Text) {
    if ((Test-Path $Path) -and -not $Force) {
        throw "refusing to overwrite existing $Path; this runs in the lab VM only (-Force to re-seed)"
    }
    New-Item -ItemType Directory -Force (Split-Path $Path) | Out-Null
    Set-Content -Path $Path -Value $Text -Encoding utf8
    Write-Output "seeded $Path"
}

$openai    = New-FakeKey ('sk-' + 'proj-') 40
$anthropic = New-FakeKey ('sk-' + 'ant-' + 'api03-') 60
$repos     = Join-Path $env:USERPROFILE 'source\repos'

# Project .env files, the most common home for a key.
Write-Canary "$repos\chat-app\.env" @"
APP_ENV=development
OPENAI_API_KEY=$openai
"@
Write-Canary "$repos\rag-service\.env.local" @"
ANTHROPIC_API_KEY=$anthropic
VECTOR_DB_URL=http://localhost:6333
"@

# Per-user tool config directories.
Write-Canary "$env:USERPROFILE\.openai\config.json" "{ `"api_key`": `"$openai`" }"
Write-Canary "$env:USERPROFILE\.anthropic\config.json" "{ `"api_key`": `"$anthropic`" }"

# AI client config: an MCP server launched with a key in its environment.
$mcp = @"
{
  "mcpServers": {
    "research": {
      "command": "npx",
      "args": ["-y", "example-research-mcp"],
      "env": { "ANTHROPIC_API_KEY": "$anthropic" }
    }
  }
}
"@
Write-Canary "$env:APPDATA\Claude\claude_desktop_config.json" $mcp
Write-Canary "$env:USERPROFILE\.cursor\mcp.json" $mcp

# Ordinary source files, so recursive searches have something to walk.
Write-Canary "$repos\chat-app\app.py" "# TODO: stream responses`nprint('chat-app')"
Write-Canary "$repos\rag-service\index.js" "// TODO: batch the embeddings`nconsole.log('rag-service')"
