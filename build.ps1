param (
    [Parameter(Mandatory = $false)]
    [switch] $with_logging = $false,
    [ValidateSet("x86", "x64")]
    [string[]]
    $Arch = @("x86", "x64"),
    [Parameter(Position = 0, Mandatory = $false, ValueFromRemainingArguments = $true)]
    [string[]]
    $ScriptArgs
)

$VERSION = "3.0.7"

function writeErrorTip($msg) {
    Write-Host $msg -BackgroundColor Red -ForegroundColor White
}

[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

$TOOLS_DIR = Join-Path $PSScriptRoot "tools"
$XMAKE_DIR = Join-Path $TOOLS_DIR "xmake"
$XMAKE_EXE = Join-Path $XMAKE_DIR "xmake.exe"

function Get-XmakeVersion([string]$XmakeExePath) {
    if (!(Test-Path $XmakeExePath)) {
        return $null
    }

    try {
        $firstLine = (& $XmakeExePath --version 2>$null | Select-Object -First 1)
        if ($firstLine -match 'xmake v([0-9]+\.[0-9]+\.[0-9]+)') {
            return $Matches[1]
        }
    }
    catch {
        return $null
    }

    return $null
}

if ((Test-Path $PSScriptRoot) -and !(Test-Path $TOOLS_DIR)) {
    Write-Verbose -Message "Creating tools dir..."
    New-Item -Path $TOOLS_DIR -ItemType "directory" | Out-Null
}

$installedVersion = Get-XmakeVersion $XMAKE_EXE
$needInstall = !(Test-Path $XMAKE_EXE) -or ($installedVersion -ne $VERSION)

if ($needInstall) {
    if ($installedVersion) {
        Write-Host "xmake version mismatch: installed=$installedVersion, required=$VERSION. Reinstalling..."
    }

    if (Test-Path $XMAKE_DIR) {
        Remove-Item -Path $XMAKE_DIR -Recurse -Force
    }

    $outfile = Join-Path $TOOLS_DIR "$pid-xmake.zip"
    $x64arch = @('AMD64', 'IA64', 'ARM64')
    $os_arch = if ($env:PROCESSOR_ARCHITECTURE -in $x64arch -or $env:PROCESSOR_ARCHITEW6432 -in $x64arch) { 'win64' } else { 'win32' }
    $candidateUrls = @(
        "https://github.com/xmake-io/xmake/releases/download/v$VERSION/xmake-v$VERSION.$os_arch.zip",
        "https://github.com/xmake-io/xmake/releases/download/v$VERSION/xmake-master.$os_arch.zip"
    )

    $downloaded = $false
    foreach ($url in $candidateUrls) {
        Write-Host "Downloading xmake ($os_arch) from $url..."
        try {
            Invoke-WebRequest $url -OutFile $outfile -UseBasicParsing
            $downloaded = $true
            break
        }
        catch {
            continue
        }
    }

    if (-not $downloaded) {
        writeErrorTip "Download failed!"
        throw "Unable to download xmake v$VERSION for $os_arch"
    }
    
    try {
        Expand-Archive -Path $outfile -DestinationPath $TOOLS_DIR
    }
    catch {
        writeErrorTip "Failed to extract!"
        throw
    }
    finally {
        Remove-Item -Path $outfile
    }
}

foreach ($a in $Arch) {
    $verbose_opt = if ($with_logging) { "--include_logging=y" } else { "--include_logging=n" }
    & $XMAKE_EXE "f" "-a" $a $verbose_opt

    if ($ScriptArgs -and $ScriptArgs.Count -gt 0) {
        & $XMAKE_EXE @ScriptArgs
    }
}