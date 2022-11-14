###################################################
#input from inside Runbook
$servicePrincipalConnection = Get-AutomationConnection -Name "AzureRunAsConnection"       
Connect-AzAccount -ServicePrincipal -TenantId $servicePrincipalConnection.TenantId -ApplicationId $servicePrincipalConnection.ApplicationId -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint 
Set-AzContext -Subscription $servicePrincipalConnection.SubscriptionId

$rgname = "RG02"
$location = "westeurope"
$subnetname = "Subnet02"
$subnetaddressprefix = "10.2.0.0/24"
$vnetname = "VNET01"
$vnetaddressprefix = "10.2.0.0/16"
$pipname = "PIP02"
$nsgname = "NSG02"
$nicname = "NIC02"
$vmname = "VM02"
$vmsize = "Standard_B2ms"
$user = "testuser"
$keyvaultName = "asdfwefawfkey01"
$IsPipNeeded = $false
$IsNsgNeeded = $false

Function Random-String {
	
	[CmdletBinding()]
	Param (
        [int] $length = 16
	)

        Write-Output ( -join ((0x30..0x39) + ( 0x41..0x5A) + ( 0x61..0x7A) | Get-Random -Count $length  | % {[char]$_}) )	
}
$pass = Random-String | ConvertTo-SecureString -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ($user, $pass)

$IsRgAvailable = Get-AzResourceGroup -Name $rgname -ErrorAction SilentlyContinue

if ($IsRgAvailable) {
    Write-Output "$rgname is available and using the same"
}
else {
    Write-Output "$rgname is not available and creating the same"
    New-AzResourceGroup -Name $rgname -Location $location
}


$IsVNETAvailable = Get-AzVirtualNetwork -Name $vnetname -ErrorAction SilentlyContinue

if ($IsVNETAvailable) {
    Write-Output "$vnetname is available and using the same"
    $subnetId = $IsVNETAvailable.Subnets[0].Id
}
else {
    Write-Output "$vnetname is not available and creating the same"
    $subnetconfig = New-AzVirtualNetworkSubnetConfig -Name $subnetname -AddressPrefix $subnetaddressprefix
    $vnet = New-AzVirtualNetwork -Name $vnetname -ResourceGroupName $rgname -Location $location -AddressPrefix $vnetaddressprefix -Subnet $subnetconfig
    $subnetId = $vnet.Subnets[0].Id
}

if ($IsPipNeeded -eq $true) {
    $pip = New-AzPublicIpAddress -Name $pipname -ResourceGroupName $rgname -Location $location -AllocationMethod Dynamic
}

if ($IsNsgNeeded -eq $true) {
$nsgruleconfig = New-AzNetworkSecurityRuleConfig -Name "Rule-22" -Description "rule 22 for ssh" -Access Allow -Protocol * -Direction Inbound -Priority 100 -SourceAddressPrefix Internet -SourcePortRange * -DestinationPortRange 22 -DestinationAddressPrefix *
$nsg = New-AzNetworkSecurityGroup -Name $nsgname -ResourceGroupName $rgname -Location $location -SecurityRules $nsgruleconfig
}


$IsVMAvailable = Get-AzVM -Name $vmname -ResourceGroupName $rgname -ErrorAction SilentlyContinue

if ($IsVMAvailable) {

Write-Output "VM $vmname is available, Not creating new VM..."

}
else {

$keyvaultset = Set-AzKeyVaultSecret -VaultName $keyvaultName -Name "$vmname" -SecretValue $pass

if ($keyvaultset) {

Write-Output "VM $vmname is not available, creating new VM and related resources..."

$nic = New-AzNetworkInterface -Name $nicname -ResourceGroupName $rgname -Location $location -PublicIpAddressId $pip.Id -NetworkSecurityGroupId $nsg.Id -SubnetId $subnetId

$vmconfig = New-AzVMConfig -VMName $vmname -VMSize $vmsize | Set-AzVMOperatingSystem -Linux -ComputerName $vmname -Credential $creds | Set-AzVMSourceImage -PublisherName "Canonical" -Offer "UbuntuServer" -Skus "18.04-LTS" -Version "latest" | Add-AzVMNetworkInterface -Id $nic.Id

New-AzVM -ResourceGroupName $rgname -Location $location -VM $vmconfig
}
}


#############################################################
#input from outside Runbook schedule/manual trigger
Param
(
	[Parameter (Mandatory = $true)]
	[string] $rgname,
	[Parameter (Mandatory = $true)]
	[string] $location,
	[Parameter (Mandatory = $true)]
	[string] $subnetname,
	[Parameter (Mandatory = $true)]
	[string] $subnetaddressprefix,
	[Parameter (Mandatory = $true)]
	[string] $vnetname,
	[Parameter (Mandatory = $true)]
	[string] $vnetaddressprefix,
	[Parameter (Mandatory = $false)]
	[string] $pipname,
	[Parameter (Mandatory = $false)]
	[string] $nsgname,
	[Parameter (Mandatory = $true)]
	[string] $nicname,
	[Parameter (Mandatory = $true)]
	[string] $vmname,
	[Parameter (Mandatory = $true)]
	[string] $vmsize,
	[Parameter (Mandatory = $false)]
	[string] $keyvaultName = "asdfwefawfkey01"
)

$servicePrincipalConnection = Get-AutomationConnection -Name "AzureRunAsConnection"       
Connect-AzAccount -ServicePrincipal -TenantId $servicePrincipalConnection.TenantId -ApplicationId $servicePrincipalConnection.ApplicationId -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint 
Set-AzContext -Subscription $servicePrincipalConnection.SubscriptionId

# $rgname = "RG02"
# $location = "westeurope"
# $subnetname = "Subnet02"
# $subnetaddressprefix = "10.2.0.0/24"
# $vnetname = "VNET01"
# $vnetaddressprefix = "10.2.0.0/16"
# $pipname = "PIP02"
# $nsgname = "NSG02"
# $nicname = "NIC02"
# $vmname = "VM02"
# $vmsize = "Standard_B2ms"
 $user = "testuser"
# $keyvaultName = "asdfwefawfkey01"
$IsPipNeeded = $false
$IsNsgNeeded = $false

Function Random-String {
	
	[CmdletBinding()]
	Param (
        [int] $length = 16
	)

        Write-Output ( -join ((0x30..0x39) + ( 0x41..0x5A) + ( 0x61..0x7A) | Get-Random -Count $length  | % {[char]$_}) )	
}
$pass = Random-String | ConvertTo-SecureString -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ($user, $pass)

$IsRgAvailable = Get-AzResourceGroup -Name $rgname -ErrorAction SilentlyContinue

if ($IsRgAvailable) {
    Write-Output "$rgname is available and using the same"
}
else {
    Write-Output "$rgname is not available and creating the same"
    New-AzResourceGroup -Name $rgname -Location $location
}


$IsVNETAvailable = Get-AzVirtualNetwork -Name $vnetname -ErrorAction SilentlyContinue

if ($IsVNETAvailable) {
    Write-Output "$vnetname is available and using the same"
    $subnetId = $IsVNETAvailable.Subnets[0].Id
}
else {
    Write-Output "$vnetname is not available and creating the same"
    $subnetconfig = New-AzVirtualNetworkSubnetConfig -Name $subnetname -AddressPrefix $subnetaddressprefix
    $vnet = New-AzVirtualNetwork -Name $vnetname -ResourceGroupName $rgname -Location $location -AddressPrefix $vnetaddressprefix -Subnet $subnetconfig
    $subnetId = $vnet.Subnets[0].Id
}

if ($IsPipNeeded -eq $true) {
    $pip = New-AzPublicIpAddress -Name $pipname -ResourceGroupName $rgname -Location $location -AllocationMethod Dynamic
}

if ($IsNsgNeeded -eq $true) {
$nsgruleconfig = New-AzNetworkSecurityRuleConfig -Name "Rule-22" -Description "rule 22 for ssh" -Access Allow -Protocol * -Direction Inbound -Priority 100 -SourceAddressPrefix Internet -SourcePortRange * -DestinationPortRange 22 -DestinationAddressPrefix *
$nsg = New-AzNetworkSecurityGroup -Name $nsgname -ResourceGroupName $rgname -Location $location -SecurityRules $nsgruleconfig
}


$IsVMAvailable = Get-AzVM -Name $vmname -ResourceGroupName $rgname -ErrorAction SilentlyContinue

if ($IsVMAvailable) {

Write-Output "VM $vmname is available, Not creating new VM..."

}
else {

$keyvaultset = Set-AzKeyVaultSecret -VaultName $keyvaultName -Name "$vmname" -SecretValue $pass

if ($keyvaultset) {

Write-Output "VM $vmname is not available, creating new VM and related resources..."

$nic = New-AzNetworkInterface -Name $nicname -ResourceGroupName $rgname -Location $location -PublicIpAddressId $pip.Id -NetworkSecurityGroupId $nsg.Id -SubnetId $subnetId

$vmconfig = New-AzVMConfig -VMName $vmname -VMSize $vmsize | Set-AzVMOperatingSystem -Linux -ComputerName $vmname -Credential $creds | Set-AzVMSourceImage -PublisherName "Canonical" -Offer "UbuntuServer" -Skus "18.04-LTS" -Version "latest" | Add-AzVMNetworkInterface -Id $nic.Id

New-AzVM -ResourceGroupName $rgname -Location $location -VM $vmconfig
}
}


############################################################################
#Input from WebHook

Param
(
	[Parameter (Mandatory = $false)]
	[object] $WEBHOOKDATA
)

$servicePrincipalConnection = Get-AutomationConnection -Name "AzureRunAsConnection"       
Connect-AzAccount -ServicePrincipal -TenantId $servicePrincipalConnection.TenantId -ApplicationId $servicePrincipalConnection.ApplicationId -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint 
Set-AzContext -Subscription $servicePrincipalConnection.SubscriptionId

if($WEBHOOKDATA) {
$vminfo = ConvertFrom-Json -InputObject $WEBHOOKDATA.RequestBody
$rgname = $vminfo.rgname
$location = $vminfo.location
$subnetname = $vminfo.subnetname
$subnetaddressprefix = $vminfo.subnetaddressprefix
$vnetname = $vminfo.vnetname
$vnetaddressprefix = $vminfo.vnetaddressprefix
$pipname = $vminfo.pipname
$nsgname = $vminfo.nsgname
$nicname = $vminfo.nicname
$vmname = $vminfo.vmname
$vmsize = $vminfo.vmsize
$user = "testuser"
$keyvaultName = $vminfo.keyvaultName
$IsPipNeeded = $false
$IsNsgNeeded = $false

Function Random-String {
	
	[CmdletBinding()]
	Param (
        [int] $length = 16
	)

        Write-Output ( -join ((0x30..0x39) + ( 0x41..0x5A) + ( 0x61..0x7A) | Get-Random -Count $length  | % {[char]$_}) )	
}
$pass = Random-String | ConvertTo-SecureString -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ($user, $pass)

$IsRgAvailable = Get-AzResourceGroup -Name $rgname -ErrorAction SilentlyContinue

if ($IsRgAvailable) {
    Write-Output "$rgname is available and using the same"
}
else {
    Write-Output "$rgname is not available and creating the same"
    New-AzResourceGroup -Name $rgname -Location $location
}


$IsVNETAvailable = Get-AzVirtualNetwork -Name $vnetname -ErrorAction SilentlyContinue

if ($IsVNETAvailable) {
    Write-Output "$vnetname is available and using the same"
    $subnetId = $IsVNETAvailable.Subnets[0].Id
}
else {
    Write-Output "$vnetname is not available and creating the same"
    $subnetconfig = New-AzVirtualNetworkSubnetConfig -Name $subnetname -AddressPrefix $subnetaddressprefix
    $vnet = New-AzVirtualNetwork -Name $vnetname -ResourceGroupName $rgname -Location $location -AddressPrefix $vnetaddressprefix -Subnet $subnetconfig
    $subnetId = $vnet.Subnets[0].Id
}

if ($IsPipNeeded -eq $true) {
    $pip = New-AzPublicIpAddress -Name $pipname -ResourceGroupName $rgname -Location $location -AllocationMethod Dynamic
}

if ($IsNsgNeeded -eq $true) {
$nsgruleconfig = New-AzNetworkSecurityRuleConfig -Name "Rule-22" -Description "rule 22 for ssh" -Access Allow -Protocol * -Direction Inbound -Priority 100 -SourceAddressPrefix Internet -SourcePortRange * -DestinationPortRange 22 -DestinationAddressPrefix *
$nsg = New-AzNetworkSecurityGroup -Name $nsgname -ResourceGroupName $rgname -Location $location -SecurityRules $nsgruleconfig
}


$IsVMAvailable = Get-AzVM -Name $vmname -ResourceGroupName $rgname -ErrorAction SilentlyContinue

if ($IsVMAvailable) {

Write-Output "VM $vmname is available, Not creating new VM..."

}
else {

$keyvaultset = Set-AzKeyVaultSecret -VaultName $keyvaultName -Name "$vmname" -SecretValue $pass

if ($keyvaultset) {

Write-Output "VM $vmname is not available, creating new VM and related resources..."

$nic = New-AzNetworkInterface -Name $nicname -ResourceGroupName $rgname -Location $location -PublicIpAddressId $pip.Id -NetworkSecurityGroupId $nsg.Id -SubnetId $subnetId

$vmconfig = New-AzVMConfig -VMName $vmname -VMSize $vmsize | Set-AzVMOperatingSystem -Linux -ComputerName $vmname -Credential $creds | Set-AzVMSourceImage -PublisherName "Canonical" -Offer "UbuntuServer" -Skus "18.04-LTS" -Version "latest" | Add-AzVMNetworkInterface -Id $nic.Id

New-AzVM -ResourceGroupName $rgname -Location $location -VM $vmconfig
}
}
}
else {
	Write-Output "This runbook has not triggered by webhook"
}


################################################################
#Hybrid worker in Automation account to run your jubs in VM
# Create log analytics workspace
#run below command
Set-AzOperationalInsightsIntelligencePack -ResourceGroupName autoaccrg01 -WorkspaceName law001 -IntelligencePackName "AzureAutomation" -Enabled $true

#take workspaceID and WorkspaceKey from log anaytics workspace
$publicsettings = @{"WorkspaceID" = "2a059b15-d184-4c8b-821a-xxxxxxx"}
$protectedsettings = @{"WorkspaceKey" = "ZJZ9WAxxxxxxxxxxxxxxxxXox2au/0ay635OLx28MgogXgClU6bWhxxxxxxxxxxxxxWZAuQ=="}
#create VM
#run below command to install agent in newly created VM
Set-AzVMExtension -ExtensionName "MicrosoftMonitoringAgent" -ResourceGroupName newrg01 -VMName VM01 -Publisher "Microsoft.EnterpriseCloud.Monitoring" -ExtensionType "MicrosoftMonitoringAgent" -TypeHandlerVersion 1.0 -Settings $publicsettings -ProtectedSettings $protectedsettings -Location "west europe"


#RDP to VM
#Take Powershell
    cd "C:\Program Files\Microsoft Monitoring Agent\Agent\AzureAutomation\7.3.1209.0\HybridRegistration"
    Import-Module .\HybridRegistration.psd1
    Add-HybridRunbookWorker -url "" -key "" (Url and key is from automation account, under keys)
#hybrid worker is available in Automation account

######################################################
#VM auto start stop based on Tags

param (

    [Parameter(Mandatory=$true)]  
    [String] $Action,

    [Parameter(Mandatory=$false)]  
    [String] $TagName,

    [Parameter(Mandatory=$false)]
    [String] $TagValue
) 

Connect-AzAccount -Identity
## End of authentication

## Getting all virtual machines

Write-Output "---------------------------- Status ----------------------------"
Write-Output "Getting all virtual machines from all resource groups ..."

try
{
    if ($TagName)
    {                    
        $instances = Get-AzResource -TagName $TagName -TagValue $TagValue -ResourceType "Microsoft.Compute/virtualMachines"
        
        if ($instances)
        {
            $resourceGroupsContent = @()
                                      
            foreach ($instance in $instances)
            {
                $instancePowerState = (((Get-AzVM -ResourceGroupName $($instance.ResourceGroupName) -Name $($instance.Name) -Status).Statuses.Code[1]) -replace "PowerState/", "")

                $resourceGroupContent = New-Object -Type PSObject -Property @{
                    "Resource group name" = $($instance.ResourceGroupName)
                    "Instance name" = $($instance.Name)
                    "Instance type" = (($instance.ResourceType -split "/")[0].Substring(10))
                    "Instance state" = ([System.Threading.Thread]::CurrentThread.CurrentCulture.TextInfo.ToTitleCase($instancePowerState))
                    $TagName = $TagValue
                }

                $resourceGroupsContent += $resourceGroupContent
            }
        }
        else
        {
            #Do nothing
        }
    }       

    $resourceGroupsContent | Format-Table -AutoSize
}
catch
{
    Write-Error -Message $_.Exception
    throw $_.Exception    
}
## End of getting all virtual machines

$runningInstances = ($resourceGroupsContent | Where-Object {$_.("Instance state") -eq "Running" -or $_.("Instance state") -eq "Starting"})
$deallocatedInstances = ($resourceGroupsContent | Where-Object {$_.("Instance state") -eq "Deallocated" -or $_.("Instance state") -eq "Deallocating"})

## Updating virtual machines power state
if (($runningInstances) -and ($Action -eq "Stop"))
{
    Write-Output "--------------------------- Updating ---------------------------"
    Write-Output "Trying to stop virtual machines ..."

    try
    {
        $updateStatuses = @()
         
        foreach ($runningInstance in $runningInstances)
        {
            Write-Output "$($runningInstance.("Instance name")) is shutting down ..."
        
            $startTime = Get-Date -Format G

            $null = Stop-AzVM -ResourceGroupName $($runningInstance.("Resource group name")) -Name $($runningInstance.("Instance name")) -Force
            
            $endTime = Get-Date -Format G

            $updateStatus = New-Object -Type PSObject -Property @{
                "Resource group name" = $($runningInstance.("Resource group name"))
                "Instance name" = $($runningInstance.("Instance name"))
                "Start time" = $startTime
                "End time" = $endTime
            }
            
            $updateStatuses += $updateStatus       
        }

        $updateStatuses | Format-Table -AutoSize
    }
    catch
    {
        Write-Error -Message $_.Exception
        throw $_.Exception    
    }
}
elseif (($deallocatedInstances) -and ($Action -eq "Start"))
{
    Write-Output "--------------------------- Updating ---------------------------"
    Write-Output "Trying to start virtual machines ..."

    try
    {
        $updateStatuses = @()

        foreach ($deallocatedInstance in $deallocatedInstances)
        {                                    
            Write-Output "$($deallocatedInstance.("Instance name")) is starting ..."

            $startTime = Get-Date -Format G

            $null = Start-AzVM -ResourceGroupName $($deallocatedInstance.("Resource group name")) -Name $($deallocatedInstance.("Instance name"))

            $endTime = Get-Date -Format G

            $updateStatus = New-Object -Type PSObject -Property @{
                "Resource group name" = $($deallocatedInstance.("Resource group name"))
                "Instance name" = $($deallocatedInstance.("Instance name"))
                "Start time" = $startTime
                "End time" = $endTime
            }

            $updateStatuses += $updateStatus
        }

        $updateStatuses | Format-Table -AutoSize
    }
    catch
    {
        Write-Error -Message $_.Exception
        throw $_.Exception    
    }
}
#### End of updating virtual machines power state

