# Hunt: AI API key harvesting on a Windows developer endpoint

| | |
|---|---|
| Date | 2026-11-09 |
| ATT&CK | T1552.001, Unsecured Credentials: Credentials In Files (Credential Access) |
| ATLAS | AML.T0055, Unsecured Credentials |
| Data | Sysmon Event ID 1 (process creation) and 11 (file create) |
| Lab | Windows 11 IoT Enterprise LTSC 2024 evaluation VM, Sysmon 15.22, Splunk |
| Outcome | Hypothesis held for command-line searches; one detection; visibility gaps named |
| Detection | [`rules/endpoint/proc_creation_win_ai_api_key_recursive_search.yml`](../../rules/endpoint/proc_creation_win_ai_api_key_recursive_search.yml) |

## Why this hunt

LLMjacking begins with a compromised key. Sysdig has written about LLMjacking,
where a threat actor uses stolen cloud credentials to run model inference on
the victim's account and resell it. The rules already in this repo cover the
cloud side (Bedrock logging and guardrail tampering). This hunt starts one
step earlier, on the endpoint where the keys are stored in plain text. Developer
machines keep Anthropic and OpenAI keys in `.env` files, AI client configs and
MCP server definitions.

## Hypothesis

> If a threat actor on a developer's machine is harvesting AI keys, a shell or
> script interpreter will search `.env` files and AI tool configs for key
> patterns, and process creation logs will show it.

How could this be wrong? A threat actor could collect keys without ever
putting a key string or a config path on a command line. The lab tests that
case on purpose with the script harvester below, and the results note what the
hunt can and cannot see.

## Data needed

- Sysmon Event ID 1 for `CommandLine`, `Image`, `ParentImage`, `User` and
  `CurrentDirectory`.
- Sysmon Event ID 11 for writes to `.env` files and AI tool configs. It
  confirms the canaries and shows when a config is modified.
- File reads are not visible in Sysmon. Seeing a process open a canary file
  takes object access auditing (Windows Security Event 4663) with a SACL on
  the file.

Here is the Sysmon config: [`lab/sysmon-config.xml`](lab/sysmon-config.xml).
It logs every process creation, plus file creates in the AI key locations.

## Lab

Everything is reproducible from [`lab/`](lab/):

1. [`create-vm.ps1`](lab/create-vm.ps1) creates the VirtualBox VM (EFI, TPM
   2.0, Secure Boot, 2 vCPUs, 4 GB, NAT, one shared folder). Windows setup,
   the local account and Guest Additions (which mount the `aidrshare` folder
   as `Z:`) are done by hand. The script leaves the network cable unplugged
   during setup; plug it in when you are done, because an evaluation copy that
   can't activate shuts itself down every hour.
2. Sysmon 15.22, installed with the config above.
3. [`seed-canaries.ps1`](lab/seed-canaries.ps1) puts fake API keys where real
   keys would be: two project `.env` files, `~/.openai`, `~/.anthropic`, the
   Claude Desktop config and a Cursor `mcp.json`. Both AI client configs
   define an MCP server with a key in its environment. Every key is random and
   contains `AIDRLABCANARY`. Keys never leave the VM, and no string in a real
   key's format is in this repo. The script also creates two source files with
   to-do comments for the developer searches to find, and it will not
   overwrite an existing file.
4. [`run-activity.ps1`](lab/run-activity.ps1) runs the attack simulation and
   the developer actions. Each step runs as its own child process, and its
   start and end times are logged.
5. [`export-sysmon.ps1`](lab/export-sysmon.ps1) exports the Sysmon log to JSON
   lines for loading into Splunk as sourcetype `_json`.

### Attack simulation

Atomic Red Team tests for T1552.001, run by hand with built-in Windows
commands, the way the Atomic executors would run them:

| Atomic test | What it does |
|---|---|
| 4, Extracting passwords with findstr | `findstr /si pass` over documents, then `ls -R \| select-string password` |
| 13, List Credential Files via PowerShell | lists the hidden Credential Manager files |
| 14, List Credential Files via Command Prompt | the same with `dir /a:h` |

Test 4 is the generic baseline. The AI key steps adapt it, along with test 26
(a Linux and macOS search for `.env` files that may hold application
credentials), to the keys this hunt is about:

| Step | Command shape |
|---|---|
| Recursive findstr | `findstr /s /i /m /c:"sk-ant-" /c:"sk-proj-" /c:"OPENAI_API_KEY" /c:"ANTHROPIC_API_KEY" *.env *.env.* *.json` |
| Recursive PowerShell | `Get-ChildItem -Recurse -Include .env,.env.*,*.json \| Select-String -Pattern 'sk-ant-','sk-proj-',...` |
| Targeted config read | `type` of the Claude Desktop config, Cursor `mcp.json` and `~/.anthropic` |
| Script harvester | the recursive PowerShell search saved as a `.ps1` file and run with `-File` |

### Developer activity

These are actions a developer would perform with the same files: `findstr
OPENAI_API_KEY .env` in one project, `Select-String` and `Get-Content` on one
`.env` file, a recursive `findstr` for to-do comments, `dir /s /b *.env`,
opening the MCP config in Notepad, and a Defender custom scan of the repos
folder (to simulate a secret scanner walking the same files).

## Hunt searches (SPL)

I loaded the export into Splunk as sourcetype `_json` in index `aidr_lab`, so
the field names stay the same as Sysmon's.

**H1, the hypothesis.** A shell or findstr whose command line includes an AI
key or an AI tool's key file. I broke out the recursion flag to make triage
easier.

```spl
index=aidr_lab sourcetype=_json EventID=1
    (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\findstr.exe")
    (CommandLine="*sk-ant-*" OR CommandLine="*sk-proj-*" OR CommandLine="*OPENAI_API_KEY*"
     OR CommandLine="*ANTHROPIC_API_KEY*" OR CommandLine="*claude_desktop_config*"
     OR CommandLine="*mcp.json*" OR CommandLine="*\\.anthropic\\*" OR CommandLine="*\\.openai\\*"
     OR CommandLine="*\\.cursor\\*")
| eval image=mvindex(split(Image, "\\"), -1)
| eval recursive=if(match(CommandLine, "(?i)(\s/s\s|\s/si|\s/is|-rec|-depth|\s-r\s)"), "yes", "no")
| table UtcTime User image recursive CurrentDirectory CommandLine
| sort UtcTime
```

**H2, the generic baseline.** Atomic tests 4, 13 and 14: a findstr for "pass"
or "password", or a listing of the Credential Manager store.

```spl
index=aidr_lab sourcetype=_json EventID=1
    ((CommandLine="*findstr*" CommandLine="*pass*")
     OR (CommandLine="*select-string*" CommandLine="*password*")
     OR CommandLine="*Microsoft\\Credentials*")
| table UtcTime User Image CommandLine
```

`*pass*` will also catch `-ExecutionPolicy Bypass`, so H2 returns any findstr
launched with that flag. Check the command before counting it as baseline.

**H3, stack the recursive searches.** All recursive file searches that match
the rule's recursion test, counted by parent and child, to show what is normal
before judging what is not.

```spl
index=aidr_lab sourcetype=_json EventID=1
| where match(CommandLine, "(?i)(\s/s\s|\s/si|\s/is|-rec|-depth|\s-r\s)")
| eval parent=mvindex(split(ParentImage, "\\"), -1), image=mvindex(split(Image, "\\"), -1)
| stats count values(CommandLine) as commands by parent image User
| sort count
```

**H4, script files from user folders.** A script interpreter running a script
file from a folder the user can write to. A harvester shows up this way when
its search logic is in the script instead of on the command line.

```spl
index=aidr_lab sourcetype=_json EventID=1
    (Image="*\\powershell.exe" OR Image="*\\pwsh.exe") CommandLine="*-File*"
    (CommandLine="*\\Users\\Public\\*" OR CommandLine="*\\AppData\\Local\\Temp\\*" OR CommandLine="*\\Downloads\\*")
| table UtcTime User ParentImage CommandLine
```

**H5, writes to key locations.** Sysmon Event ID 11 events under the key paths
in the config. In the lab this shows the seeding. On a real host it shows any
process other than an editor or the tool itself writing a key file.

```spl
index=aidr_lab sourcetype=_json EventID=11
| eval image=mvindex(split(Image, "\\"), -1)
| stats count values(TargetFilename) as files by image User
```

## Results

Breakdown of the 115 Sysmon events from one run: 55 process creations, 52
process terminations (the config does not exclude them, so Sysmon logs them by
default), 6 file creates, and 2 Sysmon events for its own state and config. A
search of all 115 events for AIDRLABCANARY found nothing. Hunt results in
Splunk Enterprise 10.4: H1 returned 7 events (3 recursive), H2 4, H3 8 events
in 4 parent and child pairs, H4 1 (the script harvester) and H5 6 file creates
in one row (the seeding PowerShell).

| Lab step | Kind | Surfaced by | Rule |
|---|---|---|---|
| Recursive findstr for key markers | attack | H1 (recursive), H3 | hit, on both `cmd.exe` and `findstr.exe` |
| Recursive `Select-String` for key markers | attack | H1 (recursive), H3 | hit |
| `type` of three AI tool configs | attack | H1 (targeted, not recursive) | miss |
| Script harvester run with `-File` | attack | H4 only | miss |
| Atomic 4, findstr for "pass" | baseline | H2, H3 | miss (no AI key marker) |
| Atomic 13 and 14, Credential Manager listing | baseline | H2 | miss |
| `findstr OPENAI_API_KEY .env` in one project | benign | H1 (not recursive) | no match |
| `Select-String` on one `.env` | benign | H1 (not recursive) | no match |
| `Get-Content .env.local` | benign | none | no match |
| Recursive findstr for to-do comments | benign | H3 | no match |
| `dir /s /b *.env` | benign | H3 | no match |
| Notepad on the MCP config | benign | none | no match |
| Defender custom scan of the repos | benign | none | no match |

Searches run from the command line matched the hypothesis. Two of the
four collection methods left a key marker and a recursion flag on the command
line, and a third, the targeted `type`, named the AI tools' config files. The
script harvester was the only method that did not reveal its purpose.

Lab caveats: one VM, one user, and every command ran from an elevated prompt
(tests 13 and 14 require one), so `IntegrityLevel` is High for every lab step.
A fleet would have many more developer searches than this lab can show. In the
event data, cmd's `%USERNAME%` appears as `%%USERNAME%%`; the searches use
wildcards, so they match either way.

## False positives

- **A developer reading their own `.env`.** One file in one project, no
  recursion. H1 shows it so the hunter sees the contrast, but the rule ignores
  it.
- **Recursive searches without key markers.** Searching for to-do comments or
  `dir /s /b *.env` is common. H3 counts these, but with no key marker they
  don't match the rule.
- **IDE indexers and secret scanners.** They read files inside their own
  process, so no command line shows a key marker. In the lab, the Defender
  scan of the repos simulates them, and it raised nothing.
- **What remains.** An engineer may search a repo or home folder for leaked
  keys with a quick recursive search, and on the command line that looks just
  like the harvester. Triage on who ran it, from which folder, and whether the
  same account touched the keys anywhere else.

## Visibility gaps

- Sysmon has no event for **file reads**. A harvester that reads files inside
  its own process (a `.ps1` file, Python, Node or a compiled tool) leaves
  nothing on the command line. The lab's script harvester does this, and only
  H4's generic search caught it. Object access auditing fills the gap: with a
  SACL on the canary key files, Windows Security Event 4663 logs any process
  that opens them.
- **Encoded commands** get past it: `powershell -EncodedCommand` hides every
  marker from H1 and the rule. The next layer is decoding the base64 at search
  time, or Script Block Logging (4104).
- **Limits of the rule.** Its image list is cmd, PowerShell and findstr, so
  ripgrep (`rg`, recursive by default) and `grep -r` from `bash.exe` or
  `wsl.exe` are not detected. Its four markers also miss other providers' key
  prefixes, and a prefix split across several strings.
- **Exfiltration and use of the keys** (provider API calls from a new
  location) are outside this hunt; the cloud-side rules in this repo start
  there.

## From hunt to detection

The rule is the high-confidence part of H1: a shell or findstr, a key marker
on the command line and a recursion flag. Its recursion test also covers
findstr's combined switches (`/si`, `/is`) and PowerShell's `-rec` and
`-Depth`, which the lab run did not use with a key marker. In the lab it
matches all 3 sweep events and no developer activity. Its fixtures in
`tests/events/6fc08311-8e20-468c-9ea2-2d0b247e5a45/` are real lab events, cut
down to the fields an analyst reads: 3 true positives and 5 false positives
(the one-file `findstr` and `Select-String`, the recursive to-do search, `dir
/s /b *.env` and Notepad opening the MCP config). The combined-switch and
`-rec` forms each have a synthetic true positive, with "synthetic" in the file
name. No fixture tests the image filter alone, because no lab event
had a key marker and a recursion flag on any other process. The targeted
config read and the script harvester stay in the hunt (H1 and H4), where a
person judges them, because a rule for either would mostly alert on
developers.

## References

- MITRE ATT&CK T1552.001: https://attack.mitre.org/techniques/T1552/001/
- MITRE ATLAS AML.T0055, Unsecured Credentials
- Atomic Red Team T1552.001: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md
- Sysdig, LLMjacking: https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/
