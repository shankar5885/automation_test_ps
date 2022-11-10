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
