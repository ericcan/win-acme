﻿param (
	[Parameter(Mandatory=$true)]
	[ValidatePattern("^\d+\.\d+.\d+.\d+")]
	[string]
	$ReleaseVersionNumber
)

$PSScriptFilePath = Get-Item $MyInvocation.MyCommand.Path
$RepoRoot = $PSScriptFilePath.Directory.Parent.FullName
$BuildFolder = Join-Path -Path $RepoRoot "build"

# Restore NuGet packages
& dotnet restore $RepoRoot\src\main\wacs.csproj

# Clean solution
& dotnet clean $RepoRoot\src\main\wacs.csproj -c "Release" -r win-x64
& dotnet clean $RepoRoot\src\main\wacs.csproj -c "Release" -r win-x86 
& dotnet clean $RepoRoot\src\main\wacs.csproj -c "ReleasePluggable" -r win-x64
& dotnet clean $RepoRoot\src\main\wacs.csproj -c "ReleasePluggable" -r win-x86 

# Build main
& dotnet publish $RepoRoot\src\main\wacs.csproj -c "Release" -r win-x64 /p:PublishSingleFile=true /p:PublishTrimmed=true
& dotnet publish $RepoRoot\src\main\wacs.csproj -c "Release" -r win-x86 /p:PublishSingleFile=true /p:PublishTrimmed=true
& dotnet publish $RepoRoot\src\main\wacs.csproj -c "ReleasePluggable" -r win-x64 /p:PublishSingleFile=true
& dotnet publish $RepoRoot\src\main\wacs.csproj -c "ReleasePluggable" -r win-x86 /p:PublishSingleFile=true

& dotnet publish $RepoRoot\src\plugin.validation.dns.azure\wacs.validation.dns.azure.csproj -c "Release"
& dotnet publish $RepoRoot\src\plugin.validation.dns.cloudflare\wacs.validation.dns.cloudflare.csproj -c "Release"
& dotnet publish $RepoRoot\src\plugin.validation.dns.dreamhost\wacs.validation.dns.dreamhost.csproj -c "Release"
& dotnet publish $RepoRoot\src\plugin.validation.dns.route53\wacs.validation.dns.luadns.csproj -c "Release"
& dotnet publish $RepoRoot\src\plugin.validation.dns.route53\wacs.validation.dns.route53.csproj -c "Release"

if (-not $?)
{
	throw "The dotnet publish process returned an error code."
}

./create-artifacts.ps1 $RepoRoot $ReleaseVersionNumber