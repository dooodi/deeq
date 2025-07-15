#requires -Modules Az.Accounts

# ------------------------------------------------------------
# Relaunch in a visible ConsoleHost with -NoExit so the window
# stays open when the script finishes. We guard with an env var
# to ensure the block runs only once.
# ------------------------------------------------------------
if (-not $env:WIZARDOCTOPUS_RELAUNCHED) {
    # If we're not already in the standard ConsoleHost or the
    # script wasn't invoked with -NoExit, start a new process.
    if ($Host.Name -ne 'ConsoleHost') {
        $env:WIZARDOCTOPUS_RELAUNCHED = '1'

        # Determine current script path
        $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Definition }

        # Launch a new console window running this script with -NoExit
        Start-Process -FilePath "powershell.exe" -WindowStyle Normal -ArgumentList @("-NoExit","-ExecutionPolicy","Bypass","-File",$scriptPath)

        # Terminate the original instance so only the relaunched
        # copy continues execution.
        exit
    }
}

# =================================================================================
#                        Wizard-Octopus (Multi-Tenant-IOC's-Blocker)
#                                 Azure Login Version
# =================================================================================

# RED DOUBLE-LINE WELCOME BANNER
$bannerLine = ("=" * 79)
Write-Host $bannerLine -ForegroundColor Red
Write-Host $bannerLine -ForegroundColor Red
Write-Host "=                            ===== Wizard Octopus =====                       =" -ForegroundColor Red
Write-Host "=                         Multi-Tenant-IOC's-Blocker (Az Login)               =" -ForegroundColor Red
Write-Host $bannerLine -ForegroundColor Red
Write-Host $bannerLine -ForegroundColor Red
Write-Host "`n"

# ----------------------------------------------------------------------------------
# Function: Get-AzureToken
# ----------------------------------------------------------------------------------
function Get-AzureToken {
    param([string]$TenantId)
    try {
        # Ensure we're in correct context
        $context = Get-AzContext
        if (-not $context -or $context.Tenant.Id -ne $TenantId) {
            Write-Host "Switching to tenant: $TenantId" -ForegroundColor Cyan
            $null = Set-AzContext -TenantId $TenantId
            $context = Get-AzContext
        }
        # Acquire token for Microsoft Defender API
        $token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
            $context.Account,
            $context.Environment,
            $TenantId,
            $null,
            "Never",
            $null,
            "https://api.securitycenter.windows.com"
        ).AccessToken
        return $token
    } catch {
        Write-Host "Error getting Azure token: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# ----------------------------------------------------------------------------------
# Function: Get-TenantList
# ----------------------------------------------------------------------------------
function Get-TenantList {
    try {
        (Get-AzTenant) | Sort-Object Name
    } catch {
        Write-Host "Error retrieving tenant list: $($_.Exception.Message)" -ForegroundColor Red
        @()
    }
}

# ----------------------------------------------------------------------------------
# Function: Select-Tenant
# ----------------------------------------------------------------------------------
function Select-Tenant {
    $tenants = Get-TenantList
    if ($tenants.Count -eq 0) {
        Write-Host "No tenants found. Please ensure you're logged in with Connect-AzAccount." -ForegroundColor Red
        return $null
    }

    Write-Host $bannerLine -ForegroundColor Cyan
    Write-Host "=                           TENANT SELECTION                                =" -ForegroundColor Cyan
    Write-Host $bannerLine -ForegroundColor Cyan
    Write-Host "`nAvailable Tenants:`n" -ForegroundColor Cyan

    for ($i = 0; $i -lt $tenants.Count; $i++) {
        $tenant = $tenants[$i]
        Write-Host "$(($i + 1).ToString().PadLeft(2,' '))). $($tenant.Name) ($($tenant.Id))" -ForegroundColor Green
    }
    Write-Host " 0). Exit`n" -ForegroundColor Red

    while ($true) {
        $choice = Read-Host "Select tenant number (0-$($tenants.Count))"
        if ([int]::TryParse($choice, [ref]$tenantIndex)) {
            if ($tenantIndex -eq 0) { return $null }
            if ($tenantIndex -ge 1 -and $tenantIndex -le $tenants.Count) {
                return $tenants[$tenantIndex - 1]
            }
        }
        Write-Host "Invalid selection. Please try again." -ForegroundColor Yellow
    }
}

# ----------------------------------------------------------------------------------
# Function: Submit-IOC
# ----------------------------------------------------------------------------------
function Submit-IOC {
    param(
        [string]$Token,
        [string]$IndicatorValue,
        [string]$IndicatorType,
        [string]$Action = "Block",
        [string]$Title,
        [string]$Description,
        [string]$Severity = "High"
    )
    $headers = @{ 'Content-Type' = 'application/json'; 'Authorization' = "Bearer $Token" }
    $body = @{ indicatorValue=$IndicatorValue; indicatorType=$IndicatorType; action=$Action; title=$Title; description=$Description; severity=$Severity } | ConvertTo-Json -Depth 3
    try {
        Invoke-RestMethod -Uri 'https://api.securitycenter.windows.com/api/indicators' -Method Post -Headers $headers -Body $body | Out-Null
        Write-Host "IOC submitted successfully: $IndicatorValue" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "Failed to submit IOC: $IndicatorValue - $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# =================================================================================
#                           MAIN SCRIPT LOGIC
# =================================================================================

# Test prerequisites
if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
    Write-Host "Error: Azure PowerShell module (Az.Accounts) is not installed." -ForegroundColor Red
    Write-Host "Please install it using: Install-Module -Name Az.Accounts -Force" -ForegroundColor Yellow
    Read-Host "Press Enter to exit..."
    exit
}

try { if (-not (Get-AzContext)) { Connect-AzAccount | Out-Null } } catch { Write-Host $_ -ForegroundColor Red; Read-Host "Press Enter to exit"; exit }

# Tenant selection
$selectedTenant = Select-Tenant
if (-not $selectedTenant) {
    Write-Host "Exiting..." -ForegroundColor Yellow
    Read-Host "Press Enter to exit..."
    exit
}

# Get token for the selected tenant
$token = Get-AzureToken -TenantId $selectedTenant.Id
if (-not $token) {
    Write-Host "Failed to get Azure token. Exiting..." -ForegroundColor Red
    Read-Host "Press Enter to exit..."
    exit
}

# Ask user for IOC source (unchanged logic)
$iocValue = Read-Host "Enter IOC (e.g., 1.2.3.4)"
$IocType  = Read-Host "Enter IOC type (IpAddress, DomainName, Url, FileSha256, FileSha1, FileMd5)"
$title    = Read-Host "Enter title"
$descr     = Read-Host "Enter description"

Submit-IOC -Token $token -IndicatorValue $iocValue -IndicatorType $IocType -Title $title -Description $descr | Out-Null

# Show final summary (unchanged)
Write-Host "Script completed." -ForegroundColor Cyan
Read-Host "Press Enter to exit..."
# ------------------------------------------------------------
# END OF SCRIPT
# ------------------------------------------------------------