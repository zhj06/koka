param([string]$OutputDirectory = $PSScriptRoot)
$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot 'Program.cs'
$outputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$output = Join-Path $outputDirectory 'koka.exe'
$stagedOutput = Join-Path $outputDirectory 'koka.build.exe'
$manifest = Join-Path $PSScriptRoot 'app.manifest'
$png = Join-Path $PSScriptRoot 'koka.png'
$icon = Join-Path $PSScriptRoot 'koka.ico'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $compiler)) { $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
if (-not (Test-Path $compiler)) { throw 'C# compiler was not found.' }
if (-not (Test-Path $manifest)) { throw 'app.manifest was not found.' }
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
if (Test-Path $png) {
Add-Type -AssemblyName System.Drawing
$image = [System.Drawing.Image]::FromFile($png)
$frames = New-Object System.Collections.Generic.List[byte[]]
try {
    foreach ($size in @(16, 32, 48, 256)) {
        $bitmap = New-Object System.Drawing.Bitmap($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        try {
            $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
            try {
                $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
                $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
                $graphics.DrawImage($image, 0, 0, $size, $size)
                $stream = New-Object System.IO.MemoryStream
                try { $bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png); $frames.Add($stream.ToArray()) } finally { $stream.Dispose() }
            } finally { $graphics.Dispose() }
        } finally { $bitmap.Dispose() }
    }
} finally { $image.Dispose() }
$iconStream = [System.IO.File]::Create($icon)
try {
    $writer = New-Object System.IO.BinaryWriter($iconStream)
    try {
        $writer.Write([UInt16]0); $writer.Write([UInt16]1); $writer.Write([UInt16]$frames.Count)
        $offset = 6 + 16 * $frames.Count
        for ($i = 0; $i -lt $frames.Count; $i++) {
            $size = @(16, 32, 48, 256)[$i]
            $writer.Write([byte]$(if ($size -eq 256) { 0 } else { $size }))
            $writer.Write([byte]$(if ($size -eq 256) { 0 } else { $size }))
            $writer.Write([byte]0); $writer.Write([byte]0); $writer.Write([UInt16]1); $writer.Write([UInt16]32)
            $writer.Write([UInt32]$frames[$i].Length); $writer.Write([UInt32]$offset); $offset += $frames[$i].Length
        }
        foreach ($frame in $frames) { $writer.Write($frame) }
    } finally { $writer.Dispose() }
} finally { $iconStream.Dispose() }
}
if (-not (Test-Path $icon)) { throw 'koka.png or its generated koka.ico was not found.' }
& $compiler /nologo /codepage:65001 /target:winexe /optimize+ "/win32icon:$icon" "/win32manifest:$manifest" "/out:$stagedOutput" /reference:System.dll /reference:System.Core.dll /reference:System.Drawing.dll /reference:System.Windows.Forms.dll /reference:Microsoft.VisualBasic.dll $source
if ($LASTEXITCODE -ne 0) { throw "Build failed with exit code: $LASTEXITCODE" }
try {
    Move-Item -LiteralPath $stagedOutput -Destination $output -Force -ErrorAction Stop
    Write-Host "Created: $output"
} catch {
    $fallback = Join-Path $PSScriptRoot 'koka-new.exe'
    Move-Item -LiteralPath $stagedOutput -Destination $fallback -Force
    Write-Warning "koka.exe is currently in use. Created the updated app as: $fallback. Close koka.exe and replace the old file with this one."
}
