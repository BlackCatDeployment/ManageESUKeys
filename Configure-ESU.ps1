# // ***************************************************************************
# // Copyright (c) Black Cat Deployment.  All rights reserved.
# //
# // Version:   1.0 (18/06/2020)
# // Developer: Florian Valente
# // 
# // Purpose:   Install and activate ESU key for Win2008/2008R2/7 OS
# // Important: Set $ProxyAddress and $ESUKeyWin7 and $ESUKeyWin2k8 variables before running this script!
# // Usage:     Configure-ESU.ps1
# // ***************************************************************************
$ValidationKeyPath = "HKLM:\SOFTWARE\ESU_Remediation"
$ValidationKeyName = "Result"

try {
    Get-ItemPropertyValue -Path $ValidationKeyPath -Name $ValidationKeyName -ErrorAction Stop
    [System.Environment]::Exit(0)
}
catch {
    # Contine because this script was never run
}


#############
# VARIABLES #
#############
$MSActivationService = "https://activation.sls.microsoft.com/slspc/SLActivate.asmx"
$ProxyAddress = @("<FQDNPROXY1>:<PORTPROXY1>", "<FQDNPROXY2>:<PORTPROXY2>")
$ESUKeyWin7 = "<WINDOWS7_ESU_KEY>"
$ESUKeyWin2k8 = "<WINDOWS2008_ESU_KEY>"


########
# MAIN #
########
$bCompliant = $false

# Get OS type
$OS = Get-WmiObject Win32_OperatingSystem
ForEach ($ObjItem in $OS) {
    $SystemRole = $SystemRole = $ObjItem.ProductType
    Switch ($SystemRole) { 
        1 { $Type = "Desktop" }
        2 { $Type = "UNSUPPORTED" }
        3 { $Type = "Server" }
    }
}

<#NOTE:  Activation IDs from https://techcommunity.microsoft.com/t5/Windows-IT-Pro-Blog/How-to-get-Extended-Security-Updates-for-eligible-Windows/ba-p/917807
    Windows 7 SP1 (Client)
    Year 1 
    77db037b-95c3-48d7-a3ab-a9c6d41093e0 
    Year 2
    0e00c25d-8795-4fb7-9572-3803d91b6880 
    Year 3
    4220f546-f522-46df-8202-4d07afd26454 
    Windows Server 2008/R2 (Server) 
    Year 1 
    553673ed-6ddf-419c-a153-b760283472fd 
    Year 2
    04fa0286-fa74-401e-bbe9-fbfbb158010d 
    Year 3
    16c08c85-0c8b-4009-9b2b-f1f7319e45f9 
#>
If (($OS.version -like '6.0*' -and $Type -eq "Server")) {
    #$OSVersion = "Windows2008" 
    $ESUActivationID ="553673ed-6ddf-419c-a153-b760283472fd"
    $ESUKEY = $ESUKeyWin2k8
    Write-Host "Windows 2008 ESU Key found"
}

If (($OS.version -like '6.1*' -and $Type -eq "Desktop")) {
    #$OSVersion = "Windows7" 
    $ESUActivationID ="77db037b-95c3-48d7-a3ab-a9c6d41093e0"
    $ESUKEY = $ESUKeyWin7
    Write-Host "Windows 7 ESU Key found"
}
                               
If (($OS.version -like '6.1*' -and $Type -eq "Server")) {
    #$OSVersion = "Windows2008R2"
    $ESUActivationID ="553673ed-6ddf-419c-a153-b760283472fd"
    $ESUKEY = $ESUKeyWin2k8
    Write-Host "Windows 2008 R2 ESU Key found"
}

try {
    $partialProductKey = $ESUKEY.Substring($ESUKEY.Length - 5)
}
catch {
    throw "Cannot find a correct ESU Key to activate"
}

# Test prerequisite for accessing MS Activation Service
try {
    # Test connection to MS Activation Service
    try {
        Invoke-WebRequest $MSActivationService | Out-Null
    }
    catch {
        ForEach ($URL in $ProxyAddress) {
            $oProxy = New-Object System.Net.WebProxy($URL)
            $oWebClient = New-Object System.Net.WebClient
            $oWebClient.Proxy = $oProxy
            #$creds = Get-Credential
            #$oWebClient.Proxy.Credentials = $creds

            try {
                $content = $oWebClient.DownloadString($MSActivationService)

                # Enable Proxy
                Write-Host "Temporary enabling Proxy..."

                $sRegKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
                $ProxyEnable = (Get-ItemProperty $sRegKey).'ProxyEnable'
                If ($ProxyEnable -eq 0) {
                    Set-ItemProperty $sRegKey -Name ProxyEnable -Value 1 -Force
                    Set-ItemProperty $sRegKey -Name ProxyServer -Value $URL -Force
                    Set-ItemProperty $sRegKey -Name ProxyOverride -Value "<local>" -Force

                    # Mandatory to enable proxy settings
                    $ie = New-Object -ComObject "InternetExplorer.Application"
                    Start-Sleep 2
                    $ie.Quit()

                    $bProxyConfigured = $true
                }
                break
            }
            catch {
                Write-Host "Proxy $URL unreachable"
            }
        }
    }

    # Final test connection to MS Activation Service
    try {
        Invoke-WebRequest $MSActivationService | Out-Null
        Write-Host "MS Activation Service reachable"
    }
    catch {
        throw "Cannot access to MS Activation Service"
    }


    #This section will determine if endpoint is already compliant & exit the script without trying to activate if compliance is detected.
    #This section checks that the license key was installed.
    Write-Host "Checking ESU Key is installed..."
    $sQuery = 'SELECT ID, Name, OfflineInstallationId, ProductKeyID FROM SoftwareLicensingProduct where PartialProductKey = "{0}"' -f $partialProductKey
    $licensingProductInitial = Get-WmiObject -Query $sQuery
    If (!$licensingProductInitial) {
        #1)  First, install the ESU product key 
        $installESUKey = cscript.exe //nologo c:\windows\system32\slmgr.vbs /ipk $ESUKey #replace ESU_KEY with proper value downloaded from VLS site.
        #check license key
        $licensingProduct = Get-WmiObject -Query $sQuery
	    If (!$licensingProduct) {
		    throw "Cannot install ESU Key"
	    }
    }
    Write-Host "ESU Key installed"


    # This section verifies ESU key activation.
    Write-Host "Checking ESU Key is activated..."
    $sQuery = 'SELECT LicenseStatus FROM SoftwareLicensingProduct where PartialProductKey = "{0}"' -f $partialProductKey
    $licensingProductInitial1 = Get-WmiObject -Query $sQuery
    If (!$licensingProductInitial1.LicenseStatus -eq 1) { 
        #2) Next, activate the ESU Product Key
        $activateESUKey = cscript //nologo c:\windows\system32\slmgr.vbs /ato $ESUActivationID

        #3) Verify the activation was successful.
        $licensingProduct = Get-WmiObject -Query $sQuery
        If (!$licensingProduct.LicenseStatus -eq 1) {
			throw "Cannot activate ESU Key"
		}
    }
    Write-Host "ESU Key activated"
    $bCompliant = $true
}
catch {
    Write-Warning "Error during license activation! $($_.Exception.Message)"
}


# Disable Proxy
If ($bProxyConfigured) {
    Write-Host "Re-disabling Proxy..."
    Remove-ItemProperty $sRegKey -Name ProxyServer -Force
    Remove-ItemProperty $sRegKey -Name ProxyOverride -Force
    Set-ItemProperty $sRegKey -Name ProxyEnable -Value 0
    
    # Mandatory to disable proxy settings
    $ie = New-Object -ComObject "InternetExplorer.Application"
    Start-Sleep 2
    $ie.Quit()
}


If ($bCompliant) {
    New-Item -Path $ValidationKeyPath | Out-Null
    New-ItemProperty -Path $ValidationKeyPath -Name $ValidationKeyName -Value $bCompliant | Out-Null
    [System.Environment]::Exit(0)
}
Else { [System.Environment]::Exit(1) }
