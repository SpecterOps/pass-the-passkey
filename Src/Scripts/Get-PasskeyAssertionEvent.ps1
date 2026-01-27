<#
.SYNOPSIS
    Fetches recent WebAuthn assertion responses from the local or remote computer's Event Log.
.PARAMETER ComputerName
    Specifies the name of the computer from which to retrieve recent WebAuthN assertion responses.
#>

#requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [Alias('Computer')]
    [ValidateNotNullOrEmpty()]
    [string] $ComputerName
)

# Throw errors for uninitialized variables and other common issues
Set-StrictMode -Version Latest

<#
.SYNOPSIS
    Main function that retrieves recent WebAuthN assertion responses from the Windows Event Log.
#>
function Main
{
        # Max time difference is 10 minutes (600000 ms), which is the Entra ID challenge validity period
    [string] $filterXml = @"
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-WebAuthN/Operational">
    <Select>*[System[EventID=2106 and TimeCreated[timediff(@SystemTime) &lt;= 600000]] and EventData[Data[@Name='Name']='authenticationResponseJSON`n']]</Select>
  </Query>
</QueryList>
"@

    # Pass-through the events as strongly typed objects
    Get-WinEvent -ComputerName:$ComputerName -FilterXml $filterXml |
        Sort-Object -Property TimeCreated |
        ForEach-Object { [AuthenticationResponseEvent]::new($PSItem) } |
        Format-List
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
        $this.Time      = $record.TimeCreated
        $this.UserSid   = $record.UserId
        $this.ProcessId = $record.ProcessId
        $this.ThreadId  = $record.ThreadId

        # Parse JSON payload
        [string] $publicKeyCredentialJson = $record.Properties[1].Value
        $this.PublicKeyCredential = $publicKeyCredentialJson | ConvertFrom-Json
        $this.Origin              = $this.PublicKeyCredential.response.GetOrigin()

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

# Start the main function
Main
