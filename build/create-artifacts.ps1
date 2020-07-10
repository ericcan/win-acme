﻿param (
	[Parameter(Mandatory=$true)]
	[string]
	$Root,
	
	[Parameter(Mandatory=$true)]
	[string]
	$Version,
	
	[Parameter()]
	[string]
	$Password
)

Add-Type -Assembly "system.io.compression.filesystem"
$Temp = "$Root\build\temp\"
$Out = "$Root\build\artifacts\"
if (Test-Path $Temp) 
{
    Remove-Item $Temp -Recurse
}
New-Item $Temp -Type Directory

if (Test-Path $Out) 
{
    Remove-Item $Out -Recurse
}
New-Item $Out -Type Directory

function PlatformRelease
{
	param($ReleaseType, $Platform)

	Remove-Item $Temp\* -recurse
	$PlatformShort = $Platform -Replace "win-", ""
	$Postfix = "trimmed"
	if ($ReleaseType -eq "ReleasePluggable") {
		$Postfix = "pluggable"
	}
	$MainZip = "win-acme.v$Version.$PlatformShort.$Postfix.zip"
	$MainZipPath = "$Out\$MainZip"
	$MainBin = "$Root\src\main\bin\$ReleaseType\netcoreapp3.1\$Platform"
	if (!(Test-Path $MainBin)) 
	{
		$MainBin = "$Root\src\main\bin\Any CPU\$ReleaseType\netcoreapp3.1\$Platform"
	}
	if (Test-Path $MainBin) 
	{
		./sign-exe.ps1 "$MainBin\publish\wacs.exe" "$Root\build\codesigning.pfx" $Password
		Copy-Item "$MainBin\publish\wacs.exe" $Temp
		Copy-Item "$MainBin\settings.json" "$Temp\settings_default.json"
		Copy-Item "$Root\dist\*" $Temp -Recurse
		Set-Content -Path "$Temp\version.txt" -Value "v$Version ($PlatformShort, $ReleaseType)"
		[io.compression.zipfile]::CreateFromDirectory($Temp, $MainZipPath)
	}
}

function PluginRelease
{
	param($Short, $Dir, $Files)

	Remove-Item $Temp\* -recurse
	$PlugZip = "$Dir.v$Version.zip"
	$PlugZipPath = "$Out\$PlugZip"
	$PlugBin = "$Root\src\$Dir\bin\Release\netcoreapp3.1\publish"
	if (!(Test-Path $PlugBin)) 
	{
		$PlugBin = "$Root\src\$Dir\bin\Any CPU\Release\netcoreapp3.1\publish"
	}
	if (Test-Path $PlugBin) 
	{
		foreach ($file in $files) {
			Copy-Item "$PlugBin\$file" $Temp
		}
		[io.compression.zipfile]::CreateFromDirectory($Temp, $PlugZipPath)
	}
}

PlatformRelease "Release" win-x64
PlatformRelease "Release" win-x86
PlatformRelease "ReleasePluggable" win-x64
PlatformRelease "ReleasePluggable" win-x86
PluginRelease dreamhost plugin.validation.dns.dreamhost @(
	"PKISharp.WACS.Plugins.ValidationPlugins.Dreamhost.dll"
)
PluginRelease azure plugin.validation.dns.azure @(
	"Microsoft.Azure.Management.Dns.dll", 
	"Microsoft.Azure.Services.AppAuthentication.dll",
	"Microsoft.IdentityModel.Clients.ActiveDirectory.dll",
	"Microsoft.IdentityModel.Logging.dll",
	"Microsoft.IdentityModel.Tokens.dll",
	"Microsoft.Rest.ClientRuntime.Azure.Authentication.dll",
	"Microsoft.Rest.ClientRuntime.Azure.dll",
	"Microsoft.Rest.ClientRuntime.dll",
	"PKISharp.WACS.Plugins.ValidationPlugins.Azure.dll"
)
PluginRelease route53 plugin.validation.dns.route53 @(
	"AWSSDK.Core.dll", 
	"AWSSDK.Route53.dll",
	"PKISharp.WACS.Plugins.ValidationPlugins.Route53.dll"
)
PluginRelease luadns plugin.validation.dns.luadns @(
	"PKISharp.WACS.Plugins.ValidationPlugins.LuaDns.dll"
)
PluginRelease cloudflare plugin.validation.dns.cloudflare @(
	"FluentCloudflare.dll", 
	"PKISharp.WACS.Plugins.ValidationPlugins.Cloudflare.dll"
)

"Created artifacts:"
dir $Out