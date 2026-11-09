# Creates the hunt lab VM in VirtualBox 7.2: Windows 11 (64-bit), EFI with
# Secure Boot and TPM 2.0, 2 vCPUs capped at 60%, 4 GB RAM, 64 GB dynamic
# disk, NAT with the cable unplugged for setup, and one shared folder for
# moving Sysmon in and the exported events out.
#
# It creates no account and sets no password: boot the ISO and run Windows
# setup by hand.
#
#   .\create-vm.ps1 -IsoPath D:\iso\win11-iot-ltsc-eval.iso -SharePath D:\lab\share

param(
    [Parameter(Mandatory)] [string] $IsoPath,
    [Parameter(Mandatory)] [string] $SharePath,
    [string] $VmName = 'aidr-lab-win11',
    [string] $VBoxManage = "$env:ProgramFiles\Oracle\VirtualBox\VBoxManage.exe"
)

$ErrorActionPreference = 'Stop'

function vbox {
    & $VBoxManage @args
    if ($LASTEXITCODE -ne 0) { throw "VBoxManage $($args -join ' ') failed ($LASTEXITCODE)" }
}

if (-not (Test-Path $IsoPath)) { throw "ISO not found: $IsoPath" }
New-Item -ItemType Directory -Force $SharePath | Out-Null

vbox createvm --name $VmName --ostype Windows11_64 --register
$vmDir = Split-Path (& $VBoxManage showvminfo $VmName --machinereadable |
    Select-String '^CfgFile=' | ForEach-Object { $_.Line.Split('"')[1] })

vbox modifyvm $VmName --firmware=efi --tpm-type=2.0 `
    --cpus=2 --cpu-execution-cap=60 --memory=4096 `
    --graphicscontroller=vboxsvga --vram=128 `
    --nic1=nat --nictype1=82540EM --cable-connected1=off `
    --audio-enabled=off --usb-ohci=off --usb-ehci=off --usb-xhci=off `
    --clipboard-mode=disabled --drag-and-drop=disabled `
    --boot1=dvd --boot2=disk --boot3=none --boot4=none

$disk = Join-Path $vmDir "$VmName.vdi"
vbox createmedium disk --filename $disk --size 65536 --format VDI --variant Standard
vbox storagectl $VmName --name SATA --add sata --controller IntelAhci --portcount 2 --bootable on
vbox storageattach $VmName --storagectl SATA --port 0 --device 0 --type hdd --medium $disk
vbox storageattach $VmName --storagectl SATA --port 1 --device 0 --type dvddrive --medium $IsoPath

vbox modifynvram $VmName inituefivarstore
vbox modifynvram $VmName enrollmssignatures
vbox modifynvram $VmName enrollorclpk
vbox modifynvram $VmName secureboot --enable

vbox sharedfolder add $VmName --name aidrshare --hostpath $SharePath --automount --auto-mount-point=Z:

vbox showvminfo $VmName --machinereadable |
    Select-String '^(name|ostype|firmware|TPMType|SecureBoot|cpus|cpuexecutioncap|memory|nic1|cableconnected1|"SATA-0-0"|"SATA-1-0"|SharedFolder)'
