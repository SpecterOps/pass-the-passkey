<#
.SYNOPSIS
    Monitors the local computer's Event Log for new WebAuthn assertion responses
    and optionally suspends the browser process.
.PARAMETER Suspend
    Indicates whether to suspend the browser process that initiated
    the authentication request.
.PARAMETER BlockTraffic
    Indicates whether to temporarily block outbound network traffic
    from the browser process during authentication.
#>

#requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter()]
    [switch] $Suspend,

    [Parameter()]
    [switch] $BlockTraffic
)

# Throw errors for uninitialized variables and other common issues
Set-StrictMode -Version Latest

<#
.SYNOPSIS
    Main function to start the WebAuthN assertion response listener.
#>
function Main
{
    # Register the event watcher
    [string] $sourceIdentifier = 'WebAuthN2106'
    [System.Diagnostics.Eventing.Reader.EventLogWatcher] $watcher = New-AssertionEventWatcher
    Register-ObjectEvent -InputObject $watcher -EventName EventRecordWritten -SourceIdentifier $sourceIdentifier

    # Start listening for events
    $watcher.Enabled = $true
    Write-Host 'Listening for WebAuthN assertion response events... Press Ctrl+C to stop.'

    [System.Collections.Generic.List[int]] $suspendedProcessIds = [System.Collections.Generic.List[int]]::new()
    [System.Collections.Generic.List[string]] $blockedProcessPaths = [System.Collections.Generic.List[string]]::new()

    try {
        # Continuous loop to process multiple events
        while ($true) {
            [System.Management.Automation.PSEventArgs] $eventLogEvent = Wait-Event -SourceIdentifier $sourceIdentifier
            [System.Diagnostics.Eventing.Reader.EventLogRecord] $eventLogRecord = $eventLogEvent.SourceEventArgs.EventRecord
            [System.Diagnostics.Process] $process = Get-Process -Id $eventLogRecord.ProcessId

            switch ($eventLogRecord.Id) {
                2106 {
                    if ($Suspend.IsPresent) {
                        # Suspend the browser process after capturing the assertion response
                        Suspend-Process -ProcessId $process.Id
                        $suspendedProcessIds.Add($process.Id)
                    }

                    if ($BlockTraffic.IsPresent -and $Suspend.IsPresent) {
                        # Unblock outbound traffic from the browser process
                        Unblock-ProcessOutboundTraffic -ProcessPath $process.Path
                        $blockedProcessPaths.Remove($process.Path) | Out-Null
                    }

                    # Show the authentication response event (post-authentication)
                    Write-Host "Captured WebAuthn assertion response:"
                    [AuthenticationResponseEvent] $authEvent = [AuthenticationResponseEvent]::new($eventLogRecord)
                    Format-List -InputObject $authEvent
                }
                1103 {
                    if ($BlockTraffic.IsPresent) {
                        # Block outbound traffic from the browser process
                        Block-ProcessOutboundTraffic -ProcessPath $process.Path
                        $blockedProcessPaths.Add($process.Path)
                    }

                    # Show the authentication request event (pre-authentication)
                    Write-Host "Captured WebAuthn assertion request:"
                    [AuthenticationRequestEvent] $authRequestEvent = [AuthenticationRequestEvent]::new($eventLogRecord)
                    Format-List -InputObject $authRequestEvent
                }
                2104 {
                    # Show the CTAP device info event (post-authentication)
                    Write-Host "Captured CTAP device info event:"
                    [CtapDeviceInfoEvent] $ctapEvent = [CtapDeviceInfoEvent]::new($eventLogRecord)
                    Format-List -InputObject $ctapEvent
                }
            }

            # Remove the current event from queue
            Remove-Event -EventIdentifier $eventLogEvent.EventIdentifier
        }
    } finally {
        # Cleanup on exit (Ctrl+C or error)
        Write-Host "`nStopping the event watcher..."
        Unregister-Event -SourceIdentifier $sourceIdentifier
        $watcher.Enabled = $false
        $watcher.Dispose()

        # Resume the browser process after capturing the assertion response
        $suspendedProcessIds | Sort-Object -Unique | ForEach-Object {
            Resume-Process -ProcessId $PSItem -Verbose
        }

        # Unblock any remaining blocked processes
        $blockedProcessPaths | Sort-Object -Unique | ForEach-Object {
            Unblock-ProcessOutboundTraffic -ProcessPath $PSItem -Verbose
        }

        # Remove unprocessed events
        Get-Event -SourceIdentifier $sourceIdentifier -ErrorAction SilentlyContinue | Remove-Event
    }
}

<#
.SYNOPSIS
    Creates an event log watcher for WebAuthN assertion requests and responses.
#>
function New-AssertionEventWatcher
{
    [CmdletBinding()]
    [OutputType([System.Diagnostics.Eventing.Reader.EventLogWatcher])]
    param ()

    # Due to a bug in Windows, the EventData contains newline characters that need to be matched.
    [string] $filterXml = @"
<QueryList>
  <Query Id="0">
    <Select>*[System[EventID=2106] and EventData[Data[@Name='Name']='authenticationResponseJSON`n']]</Select>
  </Query>
  <Query Id="1">
    <Select>*[System[EventID=1103]]</Select>
  </Query>
  <Query Id="2">
    <Select>*[System[EventID=2104]]</Select>
  </Query>
</QueryList>
"@

    [System.Diagnostics.Eventing.Reader.EventLogQuery] $query =
        [System.Diagnostics.Eventing.Reader.EventLogQuery]::new(
            'Microsoft-Windows-WebAuthN/Operational',
            [System.Diagnostics.Eventing.Reader.PathType]::LogName,
            $filterXml
        )

    [System.Diagnostics.Eventing.Reader.EventLogWatcher] $watcher =
        [System.Diagnostics.Eventing.Reader.EventLogWatcher]::new($query)

    return $watcher
}

<#
.SYNOPSIS
    Represents the response from an authenticator for an assertion request.
.DESCRIPTION
    Contains the cryptographic signature proving possession of the credential private key,
    along with authenticator data and user handle.
.LINK
    https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAssertionResponse
#>
class AuthenticatorAssertionResponse
{
    # Contains the JSON-compatible serialization of the client data.
    [string] $clientDataJSON

    # Contains information from the authenticator such as the Relying Party ID Hash,
    # signature counter, user presence and user verification flags.
    [string] $authenticatorData

    # Contains the assertion signature over authenticatorData and clientDataJSON.
    [string] $signature

    # Contains an opaque user identifier.
    [string] $userHandle

    # Extracts the origin URL from the client data JSON.
    [string] GetOrigin()
    {
        [string] $jsonString = ConvertFrom-Base64Url -EncodedInput $this.clientDataJSON
        [psobject] $clientData = $jsonString | ConvertFrom-Json
        return $clientData.origin
    }

    # Converts the assertion response to a compact JSON string.
    [string] ToString()
    {
        return $this | ConvertTo-Json -Compress -Depth 10
    }
}

<#
.SYNOPSIS
    Represents a captured WebAuthn authentication response with context.
.DESCRIPTION
    Contains the authentication response along with metadata about the
    request including timestamp, user, process, and origin information.
#>
class AuthenticationResponseEvent
{
    # The event ID of the authentication response event.
    [int] $EventId

    # The time when the authentication response was captured.
    [datetime] $Time

    # The security identifier of the user who initiated the authentication.
    [System.Security.Principal.SecurityIdentifier] $UserSid

    # The username of the user who initiated the authentication.
    [string] $UserName

    # The process ID that initiated the authentication.
    [int] $ProcessId

    # The name of the process that initiated the authentication.
    [string] $ProcessName

    # The thread ID that initiated the authentication.
    [int] $ThreadId

    # The origin URL of the authentication request.
    [string] $Origin

    # The assertion response payload
    [PublicKeyCredential] $PublicKeyCredential

    AuthenticationResponseEvent([System.Diagnostics.Eventing.Reader.EventRecord] $record)
    {
        $this.EventId   = $record.Id
        $this.Time      = $record.TimeCreated
        $this.UserSid   = $record.UserId
        $this.ProcessId = $record.ProcessId
        $this.ThreadId  = $record.ThreadId

        # Parse JSON payload
        [string] $publicKeyCredentialJson = $record.Properties[1].Value
        $this.PublicKeyCredential = $publicKeyCredentialJson | ConvertFrom-Json
        $this.Origin              = $this.PublicKeyCredential.response.GetOrigin()

        # Translate IDs to names
        $this.ProcessName = [System.Diagnostics.Process]::GetProcessById($this.ProcessId).ProcessName

        try {
            $this.UserName =  $this.UserSid.Translate([System.Security.Principal.NTAccount])
        }
        catch [System.Security.Principal.IdentityNotMappedException] {
            # Ignore user translation errors
        }
    }
}

<#
.SYNOPSIS
    Represents a PublicKeyCredential object.
#>
class PublicKeyCredential
{
    # The credential identifier.
    [string] $id

    # The raw credential identifier.
    [string] $rawId

    # The type of the credential.
    [string] $type

    # The authenticator attachment modality.
    [string] $authenticatorAttachment

    # The authenticator's response.
    [AuthenticatorAssertionResponse] $response

    # The client extension results.
    [psobject] $clientExtensionResults

    # Converts the public key credential to a compact JSON string.
    [string] ToString()
    {
        return $this | ConvertTo-Json -Compress -Depth 10
    }
}

<#
.SYNOPSIS
    Represents a captured WebAuthn authentication request.
#>
class AuthenticationRequestEvent
{
    # The event ID of the authentication response event.
    [int] $EventId

    # The time when the authentication response was captured.
    [datetime] $Time

    # The security identifier of the user who initiated the authentication.
    [System.Security.Principal.SecurityIdentifier] $UserSid

    # The username of the user who initiated the authentication.
    [string] $UserName

    # The process ID that initiated the authentication.
    [int] $ProcessId

    # The name of the process that initiated the authentication.
    [string] $ProcessName

    # The thread ID that initiated the authentication.
    [int] $ThreadId

    # The relying party identifier of the authentication request.
    [string] $RpId

    AuthenticationRequestEvent([System.Diagnostics.Eventing.Reader.EventRecord] $record)
    {
        $this.EventId   = $record.Id
        $this.Time      = $record.TimeCreated
        $this.UserSid   = $record.UserId
        $this.ProcessId = $record.ProcessId
        $this.ThreadId  = $record.ThreadId
        $this.RpId      = $record.Properties[1].Value

        # Translate IDs to names
        $this.ProcessName = [System.Diagnostics.Process]::GetProcessById($this.ProcessId).ProcessName

        try {
            $this.UserName =  $this.UserSid.Translate([System.Security.Principal.NTAccount])
        }
        catch [System.Security.Principal.IdentityNotMappedException] {
            # Ignore user translation errors
        }
    }
}

class CtapDeviceInfoEvent
{
    # The event ID of the authentication response event.
    [int] $EventId

    # The time when the authentication response was captured.
    [datetime] $Time

    # The security identifier of the user who initiated the authentication.
    [System.Security.Principal.SecurityIdentifier] $UserSid

    # The username of the user who initiated the authentication.
    [string] $UserName

    # The process ID that initiated the authentication.
    [int] $ProcessId

    # The name of the process that initiated the authentication.
    [string] $ProcessName

    # The thread ID that initiated the authentication.
    [int] $ThreadId

    # WebAuthn provider name
    [string] $ProviderName

    # Device manufacturer
    [string] $Manufacturer

    # Device product name
    [string] $Product

    # Authenticator Attestation GUID (AAGUID)
    [guid] $AAGuid

    CtapDeviceInfoEvent([System.Diagnostics.Eventing.Reader.EventRecord] $record)
    {
        $this.EventId   = $record.Id
        $this.Time      = $record.TimeCreated
        $this.UserSid   = $record.UserId
        $this.ProcessId = $record.ProcessId
        $this.ThreadId  = $record.ThreadId
        $this.ProviderName = $record.Properties[1].Value
        $this.Manufacturer = $record.Properties[3].Value
        $this.Product      = $record.Properties[4].Value
        $this.AAGuid       = [guid]$record.Properties[5].Value

        # Translate IDs to names
        $this.ProcessName = Get-Process -Id $this.ProcessId -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName

        try {
            $this.UserName =  $this.UserSid.Translate([System.Security.Principal.NTAccount])
        }
        catch [System.Security.Principal.IdentityNotMappedException] {
            # Ignore user translation errors
        }
    }
}

<#
.SYNOPSIS
    Converts a Base64Url encoded string to a UTF-8 string.
.PARAMETER EncodedInput
    The Base64Url encoded input string.
#>
function ConvertFrom-Base64Url
{
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory=$true)]
        [string] $EncodedInput
    )

    [int] $padding = 4 - ($EncodedInput.Length % 4)
    [string] $paddedInput = $EncodedInput

    if ($padding -lt 4) {
        $paddedInput = $EncodedInput + '=' * $padding
    }

    [string] $base64 = $paddedInput.Replace('-', '+').Replace('_', '/')
    return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64))
}

if (-not ('NativeMethods' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class NativeMethods
{
    public const uint PROCESS_SUSPEND_RESUME = 0x0800;

    private const string KERNEL32 = "kernel32.dll";
    private const string NTDLL = "ntdll.dll";

    [DllImport(KERNEL32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport(KERNEL32, SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport(NTDLL)]
    public static extern int NtSuspendProcess(IntPtr hProcess);

    [DllImport(NTDLL)]
    public static extern int NtResumeProcess(IntPtr hProcess);

    [DllImport(NTDLL)]
    public static extern int RtlNtStatusToDosError(int status);
}
'@
}

<#
.SYNOPSIS
    Suspends a process.
.PARAMETER ProcessId
    The ID of the process to suspend.
#>
function Suspend-Process
{
    [CmdletBinding()]
    [OutputType([void])]
    param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [Alias('Id')]
        [uint32] $ProcessId
    )

    process {
        try {
            [IntPtr] $processHandle = [NativeMethods]::OpenProcess([NativeMethods]::PROCESS_SUSPEND_RESUME, $false, $ProcessId)
            if ($processHandle -eq [IntPtr]::Zero) {
                throw [System.ComponentModel.Win32Exception]::new()
            }

            try {
                [int] $status = [NativeMethods]::NtSuspendProcess($processHandle)
                if ($status -ne 0) {
                    # Convert NTSTATUS to Win32 error code
                    [int] $win32Error = [NativeMethods]::RtlNtStatusToDosError($status)
                    throw [System.ComponentModel.Win32Exception]::new($win32Error)
                } else {
                    Write-Verbose "Process $ProcessId suspended."
                }
            } finally {
                [void][NativeMethods]::CloseHandle($processHandle)
            }
        } catch [System.ComponentModel.Win32Exception] {
            Write-Error -Exception $PSItem.Exception -Message "Error suspending process $ProcessId."
        }
    }
}

<#
.SYNOPSIS
    Resumes a suspended process.
.PARAMETER ProcessId
    The ID of the process to resume.
#>
function Resume-Process
{
    [CmdletBinding()]
    [OutputType([void])]
    param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [Alias('Id')]
        [uint32] $ProcessId
    )

    process {
        try {
            [IntPtr] $processHandle = [NativeMethods]::OpenProcess([NativeMethods]::PROCESS_SUSPEND_RESUME, $false, $ProcessId)
            if ($processHandle -eq [IntPtr]::Zero) {
                throw [System.ComponentModel.Win32Exception]::new()
            }

            try {
                [int] $status = [NativeMethods]::NtResumeProcess($processHandle)
                if ($status -ne 0) {
                    # Convert NTSTATUS to Win32 error code
                    [int] $win32Error = [NativeMethods]::RtlNtStatusToDosError($status)
                    throw [System.ComponentModel.Win32Exception]::new($win32Error)
                } else {
                    Write-Verbose "Process $ProcessId resumed."
                }
            } finally {
                [void][NativeMethods]::CloseHandle($processHandle)
            }
        } catch [System.ComponentModel.Win32Exception] {
            Write-Error -Exception $PSItem.Exception -Message "Error resuming process $ProcessId."
        }
    }
}

<#
.SYNOPSIS
    Blocks outbound network traffic for a specific process.
.PARAMETER ProcessPath
    The full path to the executable to block.
#>
function Block-ProcessOutboundTraffic
{
    [CmdletBinding()]
    [OutputType([void])]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string] $ProcessPath
    )

    [string] $ruleName = "WebAuthN Block - $([System.IO.Path]::GetFileName($ProcessPath))"

    try {
        # Remove existing rule if present
        Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

        # Create new blocking rule
        New-NetFirewallRule -DisplayName $ruleName `
            -Direction Outbound `
            -Action Block `
            -Program $ProcessPath `
            -Enabled True `
            -ErrorAction Stop | Out-Null

        Write-Verbose "Blocked outbound traffic for: $ProcessPath"
    }
    catch [System.Exception] {
        Write-Error -Exception $PSItem.Exception -Message "Error blocking outbound traffic for $ProcessPath."
    }
}

<#
.SYNOPSIS
    Unblocks outbound network traffic for a specific process.
.PARAMETER ProcessPath
    The full path to the executable to unblock.
#>
function Unblock-ProcessOutboundTraffic
{
    [CmdletBinding()]
    [OutputType([void])]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string] $ProcessPath
    )

    [string] $ruleName = "WebAuthN Block - $([System.IO.Path]::GetFileName($ProcessPath))"

    try {
        Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
        Write-Verbose "Unblocked outbound traffic for: $ProcessPath"
    }
    catch [System.Exception] {
        Write-Error -Exception $PSItem.Exception -Message "Error unblocking outbound traffic for $ProcessPath."
    }
}

# Start the main listener function
Main
