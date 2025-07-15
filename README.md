
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
        Write-Host "Error retrieving tenant list: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# ----------------------------------------------------------------------------------
# Function: Select-Tenant
# ----------------------------------------------------------------------------------
function Select-Tenant {
    $tenants = Get-TenantList
    
    if ($tenants.Count -eq 0) {
        Write-Host "No tenants found. Please ensure you're logged in with az login." -ForegroundColor Red
        return $null
    }
    
    Write-Host $bannerLine -ForegroundColor Cyan
    Write-Host "=                           TENANT SELECTION                                =" -ForegroundColor Cyan
    Write-Host $bannerLine -ForegroundColor Cyan
    Write-Host "`nAvailable Tenants:" -ForegroundColor Cyan
    
    for ($i = 0; $i -lt $tenants.Count; $i++) {
        $tenant = $tenants[$i]
        Write-Host "$($i + 1). $($tenant.Name) ($($tenant.Id))" -ForegroundColor Green
    }
    
    Write-Host "0. Exit" -ForegroundColor Red
    Write-Host ""
    
    do {
        $choice = Read-Host "Select tenant number (0-$($tenants.Count))"
        $tenantIndex = $choice -as [int]
        
        if ($tenantIndex -eq 0) {
            return $null
        }
        
        if ($tenantIndex -ge 1 -and $tenantIndex -le $tenants.Count) {
            $selectedTenant = $tenants[$tenantIndex - 1]
            Write-Host "Selected tenant: $($selectedTenant.Name) ($($selectedTenant.Id))" -ForegroundColor Green
            return $selectedTenant
        } else {
            Write-Host "Invalid selection. Please try again." -ForegroundColor Red
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
        [string]$Action = "Block",
        [string]$Title,
        [string]$Description,
        [string]$Severity = "High"
    )

    $headers = @{
        'Content-Type'  = 'application/json'
        'Authorization' = "Bearer $Token"
    }

    $body = @{
        indicatorValue = $IndicatorValue
        indicatorType  = $IndicatorType
        action         = $Action
        title          = $Title
        description    = $Description
        severity       = $Severity
    } | ConvertTo-Json

    try {
        $response = Invoke-RestMethod -Uri 'https://api.securitycenter.windows.com/api/indicators' -Method Post -Headers $headers -Body $body
        Write-Host "IOC submitted successfully: $IndicatorValue" -ForegroundColor Green
        return $response
    } catch {
        Write-Host "Failed to submit IOC: $IndicatorValue" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        return $null
    }
}

# ----------------------------------------------------------------------------------
# Function: Get-UserIOCs
# ----------------------------------------------------------------------------------
function Get-UserIOCs {
    $iocs = @()

    do {
        Write-Host "Select IOC type:" -ForegroundColor Cyan
        Write-Host "1. IP Address (public IPs only)" -ForegroundColor Green
        Write-Host "2. Domain Name" -ForegroundColor Green
        Write-Host "3. File Hash (SHA256)" -ForegroundColor Green
        Write-Host "4. File Hash (SHA1)" -ForegroundColor Green
        Write-Host "5. File Hash (MD5)" -ForegroundColor Green
        Write-Host "6. URL" -ForegroundColor Green
        Write-Host "0. Finish and submit" -ForegroundColor Red

        $choice = Read-Host "Enter your choice (0-6)"

        switch ($choice) {
            "1" {
                Write-Host "IP Address Entry" -ForegroundColor Blue
                $ip     = Read-Host "Enter malicious IP address"
                $title  = Read-Host "Enter title for this IOC"
                $desc   = Read-Host "Enter description"
                if ($ip -and $title -and $desc) {
                    # Repair defanged IOC before adding
                    $repairedIp = Repair-DefangedIOC -DefangedIOC $ip
                    $iocs += @{ Value = $repairedIp; Type = "IpAddress"; Title = $title; Description = $desc }
                    Write-Host "IP address added!" -ForegroundColor Green
                }
            }
            "2" {
                Write-Host "Domain Name Entry" -ForegroundColor Blue
                $domain = Read-Host "Enter malicious domain"
                $title  = Read-Host "Enter title for this IOC"
                $desc   = Read-Host "Enter description"
                if ($domain -and $title -and $desc) {
                    # Repair defanged IOC before adding
                    $repairedDomain = Repair-DefangedIOC -DefangedIOC $domain
                    $iocs += @{ Value = $repairedDomain; Type = "DomainName"; Title = $title; Description = $desc }
                    Write-Host "Domain added!" -ForegroundColor Green
                }
            }
            "3" {
                Write-Host "SHA256 Hash Entry" -ForegroundColor Blue
                $hash   = Read-Host "Enter SHA256 hash"
                $title  = Read-Host "Enter title for this IOC"
                $desc   = Read-Host "Enter description"
                if ($hash -and $title -and $desc) {
                    $iocs += @{ Value = $hash; Type = "FileSha256"; Title = $title; Description = $desc }
                    Write-Host "SHA256 hash added!" -ForegroundColor Green
                }
            }
            "4" {
                Write-Host "SHA1 Hash Entry" -ForegroundColor Blue
                $hash   = Read-Host "Enter SHA1 hash"
                $title  = Read-Host "Enter title for this IOC"
                $desc   = Read-Host "Enter description"
                if ($hash -and $title -and $desc) {
                    $iocs += @{ Value = $hash; Type = "FileSha1"; Title = $title; Description = $desc }
                    Write-Host "SHA1 hash added!" -ForegroundColor Green
                }
            }
            "5" {
                Write-Host "MD5 Hash Entry" -ForegroundColor Blue
                $hash   = Read-Host "Enter MD5 hash"
                $title  = Read-Host "Enter title for this IOC"
                $desc   = Read-Host "Enter description"
                if ($hash -and $title -and $desc) {
                    $iocs += @{ Value = $hash; Type = "FileMd5"; Title = $title; Description = $desc }
                    Write-Host "MD5 hash added!" -ForegroundColor Green
                }
            }
            "6" {
                Write-Host "URL Entry" -ForegroundColor Blue
                $url    = Read-Host "Enter malicious URL"
                $title  = Read-Host "Enter title for this IOC"
                $desc   = Read-Host "Enter description"
                if ($url -and $title -and $desc) {
                    # Repair defanged IOC before adding
                    $repairedUrl = Repair-DefangedIOC -DefangedIOC $url
                    $iocs += @{ Value = $repairedUrl; Type = "Url"; Title = $title; Description = $desc }
                    Write-Host "URL added!" -ForegroundColor Green
                }
            }
            "0" {
                break
            }
            default {
                Write-Host "Invalid choice. Please try again." -ForegroundColor Red
            }
        }
        Write-Host ""
    } while ($choice -ne "0")

    return $iocs
}

# ============================================================================================
# HELPER FUNCTIONS (unchanged from original)
# ============================================================================================

# ----------------------------------------------------------------------------------
# Function: Repair-DefangedIOC
# ----------------------------------------------------------------------------------
function Repair-DefangedIOC {
    param(
        [string]$DefangedIOC
    )
    
    if (-not $DefangedIOC) {
        return $DefangedIOC
    }
    
    # Replace common defanging patterns
    $repairedIOC = $DefangedIOC.Trim()
    
    # Common bracket patterns
    $repairedIOC = $repairedIOC -replace '\[\.?\]', '.'
    $repairedIOC = $repairedIOC -replace '\(\.?\)', '.'
    $repairedIOC = $repairedIOC -replace '\{\.?\}', '.'
    $repairedIOC = $repairedIOC -replace '\[dot\]', '.'
    $repairedIOC = $repairedIOC -replace '\{dot\}', '.'
    $repairedIOC = $repairedIOC -replace '\(dot\)', '.'
    $repairedIOC = $repairedIOC -replace '\[DOT\]', '.'
    $repairedIOC = $repairedIOC -replace '\{DOT\}', '.'
    $repairedIOC = $repairedIOC -replace '\(DOT\)', '.'
    
    # HTTP protocol defanging
    $repairedIOC = $repairedIOC -replace 'hxxp', 'http'
    $repairedIOC = $repairedIOC -replace 'hXXp', 'http'
    $repairedIOC = $repairedIOC -replace 'h[xX]{2}p', 'http'
    $repairedIOC = $repairedIOC -replace 'hXXPs', 'https'
    $repairedIOC = $repairedIOC -replace 'hxxps', 'https'
    $repairedIOC = $repairedIOC -replace 'h[xX]{2}ps', 'https'
    
    # Other common patterns
    $repairedIOC = $repairedIOC -replace '\[@\]', '@'
    $repairedIOC = $repairedIOC -replace '\[:\]', ':'
    $repairedIOC = $repairedIOC -replace '\[/\]', '/'
    $repairedIOC = $repairedIOC -replace '\[/\]', '/'
    $repairedIOC = $repairedIOC -replace 'meow', '.'
    $repairedIOC = $repairedIOC -replace 'DOT', '.'
    $repairedIOC = $repairedIOC -replace ' dot ', '.'
    $repairedIOC = $repairedIOC -replace ' DOT ', '.'
    
    # Additional bracket patterns for colons and slashes
    $repairedIOC = $repairedIOC -replace '\{:\}', ':'
    $repairedIOC = $repairedIOC -replace '\(:\)', ':'
    $repairedIOC = $repairedIOC -replace '\{/\}', '/'
    $repairedIOC = $repairedIOC -replace '\(/\)', '/'
    
    # Remove extra spaces that might be introduced
    $repairedIOC = $repairedIOC -replace '\s+', ' '
    $repairedIOC = $repairedIOC.Trim()
    
    return $repairedIOC
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
        'Content-Type'  = 'application/json'
        'Authorization' = "Bearer $Token"
    }
    
    try {
        # Query existing indicators
        $response = Invoke-RestMethod -Uri 'https://api.securitycenter.windows.com/api/indicators' -Method Get -Headers $headers
        
        # Check if IOC already exists
        $existingIOC = $response.value | Where-Object { 
            $_.indicatorValue -eq $IndicatorValue -and $_.indicatorType -eq $IndicatorType 
        }
        
        return $existingIOC -ne $null
    } catch {
        Write-Host "Warning: Could not check if IOC exists: $IndicatorValue" -ForegroundColor Yellow
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        return $false
    }
}

# ----------------------------------------------------------------------------------
# Function: Parse-TwoColumnLine
# ----------------------------------------------------------------------------------
function Parse-TwoColumnLine {
    param(
        [string]$Line
    )
    
    $line = $Line.Trim()
    
    # Skip empty lines and comments
    if (-not $line -or $line.StartsWith("#")) {
        return $null
    }
    
    # Try to split by comma first, then by tab, then by multiple spaces
    $parts = @()
    
    if ($line.Contains(",")) {
        $parts = $line -split "," | ForEach-Object { $_.Trim() }
    } elseif ($line.Contains("`t")) {
        $parts = $line -split "`t" | ForEach-Object { $_.Trim() }
    } else {
        # Split by multiple spaces (2 or more)
        $parts = $line -split "\s{2,}" | ForEach-Object { $_.Trim() }
    }
    
    # Must have exactly 2 parts
    if ($parts.Count -ne 2) {
        return $null
    }
    
    $indicator = $parts[0].Trim()
    $type = $parts[1].Trim()
    
    # Validate that we have both values
    if (-not $indicator -or -not $type) {
        return $null
    }
    
    return @{
        Indicator = $indicator
        Type = $type
    }
}

# ----------------------------------------------------------------------------------
# Function: Read-ExcelFile
# ----------------------------------------------------------------------------------
function Read-ExcelFile {
    param(
        [string]$FilePath
    )
    
    $iocs = @()
    
    try {
        # Import Excel module if available, otherwise use COM object
        if (Get-Module -ListAvailable -Name ImportExcel) {
            Import-Module ImportExcel -ErrorAction SilentlyContinue
            $excelData = Import-Excel -Path $FilePath -NoHeader
        } else {
            # Use COM object as fallback
            $excel = New-Object -ComObject Excel.Application
            $excel.Visible = $false
            $excel.DisplayAlerts = $false
            
            $workbook = $excel.Workbooks.Open($FilePath)
            $worksheet = $workbook.Worksheets.Item(1)
            
            # Get used range
            $usedRange = $worksheet.UsedRange
            $rowCount = $usedRange.Rows.Count
            $colCount = $usedRange.Columns.Count
            
            $excelData = @()
            for ($row = 1; $row -le $rowCount; $row++) {
                $rowData = @()
                for ($col = 1; $col -le $colCount; $col++) {
                    $cellValue = $worksheet.Cells.Item($row, $col).Text
                    $rowData += $cellValue
                }
                $excelData += ,($rowData -join " ")
            }
            
            $workbook.Close()
            $excel.Quit()
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
        }
        
        # Process Excel data - combine all cells into a single string
        $allText = ""
        foreach ($row in $excelData) {
            if ($row -is [array]) {
                $allText += ($row -join " ") + " "
            } else {
                $allText += $row + " "
            }
        }
        
        # Parse the combined text
        $iocs = Parse-ExcelIOCText -Text $allText -FilePath $FilePath
        
    } catch {
        Write-Host "Error reading Excel file: $FilePath" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
    
    return $iocs
}

# ----------------------------------------------------------------------------------
# Function: Parse-ExcelIOCText
# ----------------------------------------------------------------------------------
function Parse-ExcelIOCText {
    param(
        [string]$Text,
        [string]$FilePath
    )
    
    $iocs = @()
    
    # Split text into tokens
    $tokens = $Text -split '\s+' | Where-Object { $_.Trim() -ne "" }
    
    $currentType = ""
    $typeMapping = @{
        "FileHash-MD5" = "FileMd5"
        "FileHash-SHA1" = "FileSha1"
        "FileHash-SHA256" = "FileSha256"
        "IPv4" = "IpAddress"
        "URL" = "Url"
        "Domain" = "DomainName"
    }
    
    for ($i = 0; $i -lt $tokens.Count; $i++) {
        $token = $tokens[$i].Trim()
        
        # Check if this token is a type indicator
        if ($typeMapping.ContainsKey($token)) {
            $currentType = $typeMapping[$token]
            Write-Host "Found IOC type: $token -> $currentType" -ForegroundColor Cyan
        } elseif ($currentType -ne "" -and $token -ne "") {
            # This is an indicator value
            $originalIndicator = $token
            $repairedIndicator = Repair-DefangedIOC -DefangedIOC $originalIndicator
            
            # Show repair if it was changed
            if ($originalIndicator -ne $repairedIndicator) {
                Write-Host "Repaired defanged IOC: $originalIndicator -> $repairedIndicator" -ForegroundColor Cyan
            }
            
            # Validate the indicator based on type
            $isValid = $true
            switch ($currentType) {
                "FileMd5" { 
                    if ($repairedIndicator -notmatch "^[a-fA-F0-9]{32}$") { $isValid = $false }
                }
                "FileSha1" { 
                    if ($repairedIndicator -notmatch "^[a-fA-F0-9]{40}$") { $isValid = $false }
                }
                "FileSha256" { 
                    if ($repairedIndicator -notmatch "^[a-fA-F0-9]{64}$") { $isValid = $false }
                }
                "IpAddress" { 
                    if ($repairedIndicator -notmatch "^([0-9]{1,3}\.){3}[0-9]{1,3}$") { $isValid = $false }
                }
                "Url" { 
                    if ($repairedIndicator -notmatch "^https?://") { $isValid = $false }
                }
                "DomainName" { 
                    if ($repairedIndicator -notmatch "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$") { $isValid = $false }
                }
            }
            
            if ($isValid) {
                $title = "IOC from Excel file ($currentType)"
                $description = "Imported from $FilePath"
                
                $iocs += @{
                    Value = $repairedIndicator
                    Type = $currentType
                    Title = $title
                    Description = $description
                }
            } else {
                Write-Host "Warning: Invalid $currentType format, skipping: $repairedIndicator" -ForegroundColor Yellow
            }
        }
    }
    
    return $iocs
}

# ----------------------------------------------------------------------------------
# Function: Read-IOCsFromFile
# ----------------------------------------------------------------------------------
function Read-IOCsFromFile {
    param(
        [string]$FilePath
    )
    
    $iocs = @()
    
    if (-not (Test-Path $FilePath)) {
        Write-Host "Error: File not found: $FilePath" -ForegroundColor Red
        return $iocs
    }
    
    try {
        $fileExtension = [System.IO.Path]::GetExtension($FilePath).ToLower()
        
        if ($fileExtension -eq ".xlsx" -or $fileExtension -eq ".xls") {
            # Handle Excel files
            Write-Host "Processing Excel file..." -ForegroundColor Cyan
            $iocs = Read-ExcelFile -FilePath $FilePath
        } elseif ($fileExtension -eq ".json") {
            # Parse JSON file (existing functionality)
            $fileContent = Get-Content -Path $FilePath -Raw
            $jsonData = $fileContent | ConvertFrom-Json
            
            # Support different JSON structures
            $iocArray = @()
            if ($jsonData.IOCs) {
                $iocArray = $jsonData.IOCs
            } elseif ($jsonData -is [array]) {
                $iocArray = $jsonData
            } else {
                Write-Host "Error: Unsupported JSON structure in file: $FilePath" -ForegroundColor Red
                return $iocs
            }
            
            foreach ($item in $iocArray) {
                if ($item.Value -and $item.Type -and $item.Title -and $item.Description) {
                    # Repair defanged IOC before adding
                    $repairedValue = Repair-DefangedIOC -DefangedIOC $item.Value
                    $iocs += @{
                        Value = $repairedValue
                        Type = $item.Type
                        Title = $item.Title
                        Description = $item.Description
                    }
                } else {
                    Write-Host "Warning: Skipping malformed IOC entry in JSON file" -ForegroundColor Yellow
                }
            }
        } else {
            # Parse text file - support both two-column format and single-column format
            $fileContent = Get-Content -Path $FilePath -Raw
            $lines = $fileContent -split "`n" | Where-Object { $_.Trim() -ne "" }
            
            foreach ($line in $lines) {
                $line = $line.Trim()
                
                # Skip empty lines and comments
                if (-not $line -or $line.StartsWith("#")) {
                    continue
                }
                
                # Try to parse as two-column format first
                $parsedLine = Parse-TwoColumnLine -Line $line
                
                if ($parsedLine) {
                    # Two-column format: indicator,type
                    $indicator = $parsedLine.Indicator
                    $type = $parsedLine.Type
                    
                    # Repair defanged IOC
                    $repairedIndicator = Repair-DefangedIOC -DefangedIOC $indicator
                    
                    # Show repair if it was changed
                    if ($indicator -ne $repairedIndicator) {
                        Write-Host "Repaired defanged IOC: $indicator -> $repairedIndicator" -ForegroundColor Cyan
                    }
                    
                    $title = "IOC from file ($type)"
                    $description = "Imported from $FilePath"
                    
                    $iocs += @{
                        Value = $repairedIndicator
                        Type = $type
                        Title = $title
                        Description = $description
                    }
                } else {
                    # Fall back to single-column format with auto-detection
                    $indicator = $line
                    
                    # Repair defanged IOC first
                    $repairedIndicator = Repair-DefangedIOC -DefangedIOC $indicator
                    
                    # Show repair if it was changed
                    if ($indicator -ne $repairedIndicator) {
                        Write-Host "Repaired defanged IOC: $indicator -> $repairedIndicator" -ForegroundColor Cyan
                    }
                    
                    # Auto-detect IOC type based on pattern
                    $iocType = ""
                    $title = "IOC from file"
                    $description = "Imported from $FilePath"
                    
                    if ($repairedIndicator -match "^([0-9]{1,3}\.){3}[0-9]{1,3}$") {
                        $iocType = "IpAddress"
                        $title = "Malicious IP from file"
                    } elseif ($repairedIndicator -match "^[a-fA-F0-9]{64}$") {
                        $iocType = "FileSha256"
                        $title = "Malicious file hash (SHA256) from file"
                    } elseif ($repairedIndicator -match "^[a-fA-F0-9]{40}$") {
                        $iocType = "FileSha1"
                        $title = "Malicious file hash (SHA1) from file"
                    } elseif ($repairedIndicator -match "^[a-fA-F0-9]{32}$") {
                        $iocType = "FileMd5"
                        $title = "Malicious file hash (MD5) from file"
                    } elseif ($repairedIndicator -match "^https?://") {
                        $iocType = "Url"
                        $title = "Malicious URL from file"
                    } elseif ($repairedIndicator -match "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$") {
                        $iocType = "DomainName"
                        $title = "Malicious domain from file"
                    } else {
                        Write-Host "Warning: Could not determine IOC type for: $repairedIndicator" -ForegroundColor Yellow
                        continue
                    }
                    
                    $iocs += @{
                        Value = $repairedIndicator
                        Type = $iocType
                        Title = $title
                        Description = $description
                    }
                }
            }
        }
        
        Write-Host "Successfully loaded $($iocs.Count) IOCs from file: $FilePath" -ForegroundColor Green
        
        # Show summary of loaded IOC types
        $typeGroups = $iocs | Group-Object -Property Type
        Write-Host "IOC Types loaded:" -ForegroundColor Cyan
        foreach ($group in $typeGroups) {
            Write-Host "  - $($group.Name): $($group.Count)" -ForegroundColor White
        }
        
    } catch {
        Write-Host "Error reading file: $FilePath" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
    
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
    Write-Host $bannerLine -ForegroundColor Yellow
    Write-Host "=                           FINAL SUMMARY                                   =" -ForegroundColor Yellow
    Write-Host $bannerLine -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Total IOCs processed: $TotalIOCs" -ForegroundColor White
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
    exit
}

# Tenant selection
$selectedTenant = Select-Tenant
if (-not $selectedTenant) {
    Write-Host "Exiting..." -ForegroundColor Yellow
    exit
}

# Get token for the selected tenant
$token = Get-AzureToken -TenantId $selectedTenant.Id
if (-not $token) {
    Write-Host "Failed to get Azure token. Exiting..." -ForegroundColor Red
    exit
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
            exit
        }
        $iocs = Read-IOCsFromFile -FilePath $filePath
    }
    "0" {
        Write-Host "Exiting..." -ForegroundColor Yellow
        exit
    }
    default {
        Write-Host "Invalid choice. Exiting..." -ForegroundColor Red
        exit
    }
}

# If no IOCs collected, exit
if ($iocs.Count -eq 0) {
    Write-Host "No IOCs to submit. Exiting..." -ForegroundColor Yellow
    exit
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

# =================================================================================
#                               END OF SCRIPT
# =================================================================================
