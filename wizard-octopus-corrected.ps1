# =================================================================================
# =================================================================================
#                        Wizard-Octopus (Multi-Tenant-IOC's-Blocker)
#                                 Azure Login Version
# =================================================================================
# =================================================================================

# Function to pause and wait for user input before exiting
function Wait-ForExit {
    param([string]$Message = "Press any key to exit...")
    Write-Host "`n$Message" -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

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
        Write-Host "No tenants found. Please check your Azure access." -ForegroundColor Red
        return $null
    }
    
    if ($tenants.Count -eq 1) {
        Write-Host "Using tenant: $($tenants[0].Name) ($($tenants[0].Id))" -ForegroundColor Green
        return $tenants[0]
    }
    
    # Multiple tenants - let user choose
    Write-Host $bannerLine -ForegroundColor Green
    Write-Host "=                           TENANT SELECTION                                  =" -ForegroundColor Green
    Write-Host $bannerLine -ForegroundColor Green
    Write-Host ""
    
    for ($i = 0; $i -lt $tenants.Count; $i++) {
        Write-Host "[$($i + 1)] $($tenants[$i].Name) - $($tenants[$i].Id)" -ForegroundColor Cyan
    }
    Write-Host "[0] Exit" -ForegroundColor Red
    Write-Host ""
    
    do {
        $choice = Read-Host "Select tenant (0-$($tenants.Count))"
        
        if ($choice -eq "0") {
            return $null
        }
        
        $choiceNum = [int]$choice
        if ($choiceNum -ge 1 -and $choiceNum -le $tenants.Count) {
            $selectedTenant = $tenants[$choiceNum - 1]
            Write-Host "Selected tenant: $($selectedTenant.Name)" -ForegroundColor Green
            return $selectedTenant
        } else {
            Write-Host "Invalid choice. Please try again." -ForegroundColor Red
        }
    } while ($true)
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
    
    try {
        $headers = @{
            'Authorization' = "Bearer $Token"
            'Content-Type' = 'application/json'
        }
        
        $body = @{
            indicatorValue = $IndicatorValue
            indicatorType = $IndicatorType
            title = $Title
            description = $Description
            action = $Action
            severity = $Severity
            recommendedActions = "Block this indicator"
        } | ConvertTo-Json
        
        $uri = "https://api.securitycenter.windows.com/api/indicators"
        
        Write-Host "Submitting IOC: $IndicatorValue ($IndicatorType)" -ForegroundColor Cyan
        
        $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $body
        
        Write-Host "✓ Successfully submitted: $IndicatorValue" -ForegroundColor Green
        return $true
        
    } catch {
        $errorMessage = $_.Exception.Message
        if ($_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $responseBody = $reader.ReadToEnd()
            $errorMessage += " | Response: $responseBody"
        }
        Write-Host "✗ Failed to submit $IndicatorValue : $errorMessage" -ForegroundColor Red
        return $false
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
    
    try {
        $headers = @{
            'Authorization' = "Bearer $Token"
            'Content-Type' = 'application/json'
        }
        
        $uri = "https://api.securitycenter.windows.com/api/indicators?`$filter=indicatorValue eq '$IndicatorValue'"
        
        $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
        
        return ($response.value.Count -gt 0)
        
    } catch {
        Write-Host "Warning: Could not check if IOC exists: $($_.Exception.Message)" -ForegroundColor Yellow
        return $false
    }
}

# ----------------------------------------------------------------------------------
# Function: Get-UserIOCs
# ----------------------------------------------------------------------------------
function Get-UserIOCs {
    $iocs = @()
    
    Write-Host $bannerLine -ForegroundColor Magenta
    Write-Host "=                           MANUAL IOC ENTRY                                  =" -ForegroundColor Magenta
    Write-Host $bannerLine -ForegroundColor Magenta
    Write-Host ""
    Write-Host "Enter IOCs one by one. Type 'done' when finished." -ForegroundColor Cyan
    Write-Host "Supported types: IpAddress, Url, FileSha1, FileSha256, DomainName" -ForegroundColor Yellow
    Write-Host ""
    
    do {
        $value = Read-Host "Enter IOC value (or 'done' to finish)"
        
        if ($value.ToLower() -eq "done") {
            break
        }
        
        if ([string]::IsNullOrWhiteSpace($value)) {
            continue
        }
        
        # Auto-detect IOC type
        $type = "Unknown"
        if ($value -match "^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$") {
            $type = "IpAddress"
        } elseif ($value -match "^https?://") {
            $type = "Url"
        } elseif ($value -match "^[a-fA-F0-9]{40}$") {
            $type = "FileSha1"
        } elseif ($value -match "^[a-fA-F0-9]{64}$") {
            $type = "FileSha256"
        } elseif ($value -match "^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$") {
            $type = "DomainName"
        }
        
        Write-Host "Detected type: $type" -ForegroundColor Yellow
        $confirmType = Read-Host "Confirm type or enter correct type (IpAddress/Url/FileSha1/FileSha256/DomainName)"
        
        if (-not [string]::IsNullOrWhiteSpace($confirmType)) {
            $type = $confirmType
        }
        
        $title = Read-Host "Enter title (optional)"
        if ([string]::IsNullOrWhiteSpace($title)) {
            $title = "IOC: $value"
        }
        
        $description = Read-Host "Enter description (optional)"
        if ([string]::IsNullOrWhiteSpace($description)) {
            $description = "Suspicious $type indicator: $value"
        }
        
        $iocs += @{
            Value = $value
            Type = $type
            Title = $title
            Description = $description
        }
        
        Write-Host "✓ Added IOC: $value ($type)" -ForegroundColor Green
        Write-Host ""
        
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
                        if ($line -match "^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$") {
                            $type = "IpAddress"
                        } elseif ($line -match "^https?://") {
                            $type = "Url"
                        } elseif ($line -match "^[a-fA-F0-9]{40}$") {
                            $type = "FileSha1"
                        } elseif ($line -match "^[a-fA-F0-9]{64}$") {
                            $type = "FileSha256"
                        } elseif ($line -match "^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$") {
                            $type = "DomainName"
                        }
                        
                        $iocs += @{
                            Value = $line
                            Type = $type
                            Title = "IOC: $line"
                            Description = "Imported $type indicator: $line"
                        }
                    }
                }
            }
            ".json" {
                $jsonContent = Get-Content $FilePath | ConvertFrom-Json
                if ($jsonContent -is [array]) {
                    foreach ($item in $jsonContent) {
                        $iocs += @{
                            Value = $item.value
                            Type = $item.type
                            Title = if ($item.title) { $item.title } else { "IOC: $($item.value)" }
                            Description = if ($item.description) { $item.description } else { "Imported indicator: $($item.value)" }
                        }
                    }
                }
            }
            ".xlsx" {
                Write-Host "Excel import requires ImportExcel module. Attempting to load..." -ForegroundColor Yellow
                try {
                    Import-Module ImportExcel -ErrorAction Stop
                    $excelData = Import-Excel $FilePath
                    foreach ($row in $excelData) {
                        if ($row.Value) {
                            $iocs += @{
                                Value = $row.Value
                                Type = if ($row.Type) { $row.Type } else { "Unknown" }
                                Title = if ($row.Title) { $row.Title } else { "IOC: $($row.Value)" }
                                Description = if ($row.Description) { $row.Description } else { "Imported indicator: $($row.Value)" }
                            }
                        }
                    }
                } catch {
                    Write-Host "Error: ImportExcel module not available. Please install it with: Install-Module ImportExcel" -ForegroundColor Red
                    return @()
                }
            }
            default {
                Write-Host "Unsupported file format: $extension" -ForegroundColor Red
                return @()
            }
        }
    } catch {
        Write-Host "Error reading file: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
    
    Write-Host "Loaded $($iocs.Count) IOCs from file" -ForegroundColor Green
    return $iocs
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
    Write-Host "=                            FINAL SUMMARY                                    =" -ForegroundColor Green
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
    Write-Host "Checking prerequisites..." -ForegroundColor Cyan
    
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
        Write-Host "✓ Azure context found: $($context.Account.Id)" -ForegroundColor Green
    } catch {
        Write-Host "Error: Not logged in to Azure." -ForegroundColor Red
        Write-Host "Please run 'Connect-AzAccount' to log in." -ForegroundColor Yellow
        return $false
    }
    
    Write-Host "✓ All prerequisites met" -ForegroundColor Green
    return $true
}

# =================================================================================
#                                 MAIN SCRIPT LOGIC
# =================================================================================

try {
    # Test prerequisites
    if (-not (Test-Prerequisites)) {
        Wait-ForExit "Prerequisites not met. Press any key to exit..."
        exit 1
    }

    # Tenant selection
    $selectedTenant = Select-Tenant
    if (-not $selectedTenant) {
        Write-Host "No tenant selected. Exiting..." -ForegroundColor Yellow
        Wait-ForExit
        exit 0
    }

    # Get token for the selected tenant
    Write-Host "Getting Azure token for tenant..." -ForegroundColor Cyan
    $token = Get-AzureToken -TenantId $selectedTenant.Id
    if (-not $token) {
        Write-Host "Failed to get Azure token." -ForegroundColor Red
        Wait-ForExit "Press any key to exit..."
        exit 1
    }
    Write-Host "✓ Successfully obtained Azure token" -ForegroundColor Green

    # Ask user for IOC source
    Write-Host "`n$bannerLine" -ForegroundColor Cyan
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
                Wait-ForExit
                exit 1
            }
            $iocs = Read-IOCsFromFile -FilePath $filePath
        }
        "0" {
            Write-Host "Exiting..." -ForegroundColor Yellow
            Wait-ForExit
            exit 0
        }
        default {
            Write-Host "Invalid choice." -ForegroundColor Red
            Wait-ForExit
            exit 1
        }
    }

    # If no IOCs collected, exit
    if ($iocs.Count -eq 0) {
        Write-Host "No IOCs to submit." -ForegroundColor Yellow
        Wait-ForExit
        exit 0
    }

    # Submit IOCs
    $totalIOCs = $iocs.Count
    $submittedIOCs = 0
    $skippedIOCs = 0
    $failedIOCs = 0

    Write-Host "`n$bannerLine" -ForegroundColor Magenta
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

} catch {
    Write-Host "`nUnexpected error occurred: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack trace: $($_.ScriptStackTrace)" -ForegroundColor Red
} finally {
    # Always wait for user input before closing
    Wait-ForExit "`nScript completed. Press any key to exit..."
}

# =================================================================================
#                               END OF SCRIPT
# =================================================================================