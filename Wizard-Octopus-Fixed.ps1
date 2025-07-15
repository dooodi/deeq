# =================================================================================
# =================================================================================
#                        Wizard-Octopus (Multi-Tenant-IOC's-Blocker)
#                                 Azure Login Version
# =================================================================================
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
# Function: Pause-Script
# ----------------------------------------------------------------------------------
function Pause-Script {
    param([string]$Message = "Press any key to continue...")
    Write-Host $Message -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ----------------------------------------------------------------------------------
# Function: Exit-Script
# ----------------------------------------------------------------------------------
function Exit-Script {
    param([string]$Message = "Script completed.")
    Write-Host $Message -ForegroundColor Green
    Pause-Script "Press any key to exit..."
    exit
}

# ----------------------------------------------------------------------------------
# Function: Get-AzureToken
# ----------------------------------------------------------------------------------
function Get-AzureToken {
    param(
        [string]$TenantId
    )
    
    try {
        # Get access token for Microsoft Defender API
        $context = Get-AzContext
        if (-not $context -or $context.Tenant.Id -ne $TenantId) {
            Write-Host "Switching to tenant: $TenantId" -ForegroundColor Cyan
            $null = Set-AzContext -TenantId $TenantId
        }
        
        # Get token for Microsoft Defender API
        $token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, $context.Environment, $TenantId, $null, "Never", $null, "https://api.securitycenter.windows.com").AccessToken
        
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
        $tenants = Get-AzTenant
        return $tenants
    } catch {
        Write-Host "Error getting tenant list: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# ----------------------------------------------------------------------------------
# Function: Select-Tenant
# ----------------------------------------------------------------------------------
function Select-Tenant {
    $tenants = Get-TenantList
    
    if ($tenants.Count -eq 0) {
        Write-Host "No tenants found." -ForegroundColor Red
        return $null
    }
    
    Write-Host $bannerLine -ForegroundColor Green
    Write-Host "=                            TENANT SELECTION                                 =" -ForegroundColor Green
    Write-Host $bannerLine -ForegroundColor Green
    Write-Host ""
    
    for ($i = 0; $i -lt $tenants.Count; $i++) {
        $tenant = $tenants[$i]
        Write-Host "$($i + 1). $($tenant.Name) ($($tenant.Id))" -ForegroundColor Cyan
    }
    Write-Host "0. Exit" -ForegroundColor Red
    Write-Host ""
    
    do {
        $choice = Read-Host "Select a tenant (0-$($tenants.Count))"
        
        if ($choice -eq "0") {
            return $null
        }
        
        $tenantIndex = [int]$choice - 1
        
        if ($tenantIndex -ge 0 -and $tenantIndex -lt $tenants.Count) {
            return $tenants[$tenantIndex]
        } else {
            Write-Host "Invalid choice. Please try again." -ForegroundColor Red
        }
    } while ($true)
}

# ----------------------------------------------------------------------------------
# Function: Get-UserIOCs
# ----------------------------------------------------------------------------------
function Get-UserIOCs {
    $iocs = @()
    
    Write-Host $bannerLine -ForegroundColor Blue
    Write-Host "=                            MANUAL IOC ENTRY                                =" -ForegroundColor Blue
    Write-Host $bannerLine -ForegroundColor Blue
    Write-Host ""
    Write-Host "Enter IOCs one by one. Type 'done' when finished." -ForegroundColor Yellow
    Write-Host "Supported types: IP, URL, Domain, FileHash" -ForegroundColor Yellow
    Write-Host ""
    
    do {
        $value = Read-Host "Enter IOC value (or 'done' to finish)"
        
        if ($value.ToLower() -eq "done") {
            break
        }
        
        if ([string]::IsNullOrWhiteSpace($value)) {
            continue
        }
        
        # Determine IOC type
        $type = "Unknown"
        if ($value -match '^(\d{1,3}\.){3}\d{1,3}$') {
            $type = "IpAddress"
        } elseif ($value -match '^https?://') {
            $type = "Url"
        } elseif ($value -match '^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$') {
            $type = "FileSha1"  # Simplified, could be MD5, SHA1, or SHA256
        } elseif ($value -match '^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})+$') {
            $type = "DomainName"
        }
        
        if ($type -eq "Unknown") {
            Write-Host "Warning: Could not determine IOC type for '$value'. Please specify manually." -ForegroundColor Yellow
            $type = Read-Host "Enter IOC type (IpAddress, Url, DomainName, FileSha1)"
        }
        
        $title = Read-Host "Enter title for this IOC (optional)"
        if ([string]::IsNullOrWhiteSpace($title)) {
            $title = "Blocked IOC: $value"
        }
        
        $description = Read-Host "Enter description for this IOC (optional)"
        if ([string]::IsNullOrWhiteSpace($description)) {
            $description = "IOC blocked by Wizard Octopus"
        }
        
        $ioc = @{
            Value = $value
            Type = $type
            Title = $title
            Description = $description
        }
        
        $iocs += $ioc
        Write-Host "Added IOC: $value ($type)" -ForegroundColor Green
        
    } while ($true)
    
    return $iocs
}

# ----------------------------------------------------------------------------------
# Function: Read-IOCsFromFile
# ----------------------------------------------------------------------------------
function Read-IOCsFromFile {
    param([string]$FilePath)
    
    $iocs = @()
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    try {
        switch ($extension) {
            ".txt" {
                $lines = Get-Content $FilePath
                foreach ($line in $lines) {
                    $line = $line.Trim()
                    if (-not [string]::IsNullOrWhiteSpace($line) -and -not $line.StartsWith("#")) {
                        # Auto-detect type
                        $type = "Unknown"
                        if ($line -match '^(\d{1,3}\.){3}\d{1,3}$') {
                            $type = "IpAddress"
                        } elseif ($line -match '^https?://') {
                            $type = "Url"
                        } elseif ($line -match '^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$') {
                            $type = "FileSha1"
                        } elseif ($line -match '^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})+$') {
                            $type = "DomainName"
                        }
                        
                        $ioc = @{
                            Value = $line
                            Type = $type
                            Title = "Blocked IOC: $line"
                            Description = "IOC imported from file"
                        }
                        $iocs += $ioc
                    }
                }
            }
            ".json" {
                $jsonContent = Get-Content $FilePath -Raw | ConvertFrom-Json
                foreach ($item in $jsonContent) {
                    $ioc = @{
                        Value = $item.Value
                        Type = $item.Type
                        Title = if ($item.Title) { $item.Title } else { "Blocked IOC: $($item.Value)" }
                        Description = if ($item.Description) { $item.Description } else { "IOC imported from JSON file" }
                    }
                    $iocs += $ioc
                }
            }
            ".xlsx" {
                Write-Host "XLSX import requires the ImportExcel module. Please install it first: Install-Module ImportExcel" -ForegroundColor Yellow
                return @()
            }
            default {
                Write-Host "Unsupported file type: $extension" -ForegroundColor Red
                return @()
            }
        }
        
        Write-Host "Imported $($iocs.Count) IOCs from file." -ForegroundColor Green
        return $iocs
        
    } catch {
        Write-Host "Error reading file: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# ----------------------------------------------------------------------------------
# Function: Test-IOCExists
# ----------------------------------------------------------------------------------
function Test-IOCExists {
    param(
        [string]$Token,
        [string]$IndicatorValue,
        [string]$IndicatorType
    )
    
    $headers = @{
        "Authorization" = "Bearer $Token"
        "Content-Type" = "application/json"
    }
    
    $uri = "https://api.securitycenter.windows.com/api/indicators"
    
    try {
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        
        foreach ($indicator in $response.value) {
            if ($indicator.indicatorValue -eq $IndicatorValue -and $indicator.indicatorType -eq $IndicatorType) {
                return $true
            }
        }
        
        return $false
    } catch {
        Write-Host "Error checking if IOC exists: $($_.Exception.Message)" -ForegroundColor Red
        return $false
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
        [string]$Title,
        [string]$Description,
        [string]$Action = "Block",
        [string]$Severity = "High"
    )
    
    $headers = @{
        "Authorization" = "Bearer $Token"
        "Content-Type" = "application/json"
    }
    
    $body = @{
        indicatorValue = $IndicatorValue
        indicatorType = $IndicatorType
        action = $Action
        title = $Title
        description = $Description
        severity = $Severity
        expirationTime = $null
        generateAlert = $true
    } | ConvertTo-Json
    
    $uri = "https://api.securitycenter.windows.com/api/indicators"
    
    try {
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Post -Body $body
        Write-Host "Successfully submitted IOC: $IndicatorValue" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "Failed to submit IOC '$IndicatorValue': $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# ----------------------------------------------------------------------------------
# Function: Show-FinalSummary
# ----------------------------------------------------------------------------------
function Show-FinalSummary {
    param(
        [int]$TotalIOCs,
        [int]$SubmittedIOCs,
        [int]$SkippedIOCs,
        [int]$FailedIOCs
    )
    
    Write-Host "`n"
    Write-Host $bannerLine -ForegroundColor Green
    Write-Host "=                            SUBMISSION SUMMARY                               =" -ForegroundColor Green
    Write-Host $bannerLine -ForegroundColor Green
    Write-Host ""
    Write-Host "Total IOCs processed: $TotalIOCs" -ForegroundColor Cyan
    Write-Host "Successfully submitted: $SubmittedIOCs" -ForegroundColor Green
    Write-Host "Skipped (already exist): $SkippedIOCs" -ForegroundColor Yellow
    Write-Host "Failed to submit: $FailedIOCs" -ForegroundColor Red
    Write-Host ""
    
    if ($SubmittedIOCs -gt 0) {
        Write-Host "IOC submission completed successfully!" -ForegroundColor Green
    } elseif ($SkippedIOCs -gt 0 -and $FailedIOCs -eq 0) {
        Write-Host "All IOCs already exist in the system." -ForegroundColor Yellow
    } else {
        Write-Host "No IOCs were submitted." -ForegroundColor Red
    }
}

# ----------------------------------------------------------------------------------
# Function: Test-Prerequisites
# ----------------------------------------------------------------------------------
function Test-Prerequisites {
    # Check if Azure PowerShell module is installed
    if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
        Write-Host "Error: Azure PowerShell module (Az.Accounts) is not installed." -ForegroundColor Red
        Write-Host "Please install it using: Install-Module -Name Az.Accounts -Force" -ForegroundColor Yellow
        return $false
    }
    
    # Check if user is logged in to Azure
    try {
        $context = Get-AzContext
        if (-not $context) {
            Write-Host "Error: Not logged in to Azure." -ForegroundColor Red
            Write-Host "Please run 'Connect-AzAccount' to log in." -ForegroundColor Yellow
            return $false
        }
    } catch {
        Write-Host "Error: Not logged in to Azure." -ForegroundColor Red
        Write-Host "Please run 'Connect-AzAccount' to log in." -ForegroundColor Yellow
        return $false
    }
    
    return $true
}

# =================================================================================
#                                 MAIN SCRIPT LOGIC
# =================================================================================

# Test prerequisites
if (-not (Test-Prerequisites)) {
    Write-Host "Prerequisites not met. Please resolve the issues above and run the script again." -ForegroundColor Red
    Pause-Script
    return
}

# Tenant selection
$selectedTenant = Select-Tenant
if (-not $selectedTenant) {
    Write-Host "No tenant selected. Exiting..." -ForegroundColor Yellow
    Pause-Script
    return
}

# Get token for the selected tenant
$token = Get-AzureToken -TenantId $selectedTenant.Id
if (-not $token) {
    Write-Host "Failed to get Azure token. Exiting..." -ForegroundColor Red
    Pause-Script
    return
}

# Ask user for IOC source
Write-Host $bannerLine -ForegroundColor Cyan
Write-Host "=                            IOC SOURCE SELECTION                             =" -ForegroundColor Cyan
Write-Host $bannerLine -ForegroundColor Cyan
Write-Host "`nHow would you like to provide IOCs?" -ForegroundColor Cyan
Write-Host "1. Manual entry" -ForegroundColor Green
Write-Host "2. Import from file (TXT, JSON, XLSX)" -ForegroundColor Green
Write-Host "0. Exit" -ForegroundColor Red
Write-Host ""

$sourceChoice = Read-Host "Enter your choice (0-2)"
$iocs = @()

switch ($sourceChoice) {
    "1" {
        # Manual entry
        $iocs = Get-UserIOCs
    }
    "2" {
        # File import
        $filePath = Read-Host "Enter the full path to the file (TXT, JSON, XLSX)"
        if (-not (Test-Path $filePath)) {
            Write-Host "File not found: $filePath" -ForegroundColor Red
            Pause-Script
            return
        }
        $iocs = Read-IOCsFromFile -FilePath $filePath
    }
    "0" {
        Write-Host "Exiting..." -ForegroundColor Yellow
        Pause-Script
        return
    }
    default {
        Write-Host "Invalid choice. Exiting..." -ForegroundColor Red
        Pause-Script
        return
    }
}

# If no IOCs collected, exit
if ($iocs.Count -eq 0) {
    Write-Host "No IOCs to submit. Exiting..." -ForegroundColor Yellow
    Pause-Script
    return
}

# Submit IOCs
$totalIOCs = $iocs.Count
$submittedIOCs = 0
$skippedIOCs = 0
$failedIOCs = 0

Write-Host "`n"
Write-Host $bannerLine -ForegroundColor Magenta
Write-Host "=                            SUBMITTING IOC's                                  =" -ForegroundColor Magenta
Write-Host $bannerLine -ForegroundColor Magenta
Write-Host ""

foreach ($ioc in $iocs) {
    # Check if IOC already exists
    $exists = Test-IOCExists -Token $token -IndicatorValue $ioc.Value -IndicatorType $ioc.Type
    
    if ($exists) {
        Write-Host "Skipping existing IOC: $($ioc.Value) ($($ioc.Type))" -ForegroundColor Yellow
        $skippedIOCs++
        continue
    }
    
    # Submit the IOC
    $result = Submit-IOC -Token $token `
        -IndicatorValue $ioc.Value `
        -IndicatorType $ioc.Type `
        -Title $ioc.Title `
        -Description $ioc.Description `
        -Action "Block" `
        -Severity "High"
    
    if ($result) {
        $submittedIOCs++
    } else {
        $failedIOCs++
    }
}

# Show final summary
Show-FinalSummary -TotalIOCs $totalIOCs -SubmittedIOCs $submittedIOCs -SkippedIOCs $skippedIOCs -FailedIOCs $failedIOCs

# Exit with pause
Exit-Script "Script execution completed."

# =================================================================================
#                               END OF SCRIPT
# =================================================================================