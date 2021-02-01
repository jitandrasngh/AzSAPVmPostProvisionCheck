Function Get-AzSAPVmPostProvisionCheck {
    <#

    .SYNOPSIS
        

    .DESCRIPTION
        

    .PARAMETER file
        String. Mandatory.
        

    .PARAMETER ExportPath
        String.
        

    .EXAMPLE
        Get-AzSAPVmPostProvisionCheck -File "C:\servers.txt" -ExportPath "C:\Output.xlsx"

    .NOTES
#>

    [Cmdletbinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$File,
        [Parameter(Mandatory = $false)]
        [string]$ExportPath
    )



    # initializing variables
    $input = Get-Content -LiteralPath $file
    $ComputerName = $env:COMPUTERNAME 
    $filepath = 'C:\Temp\SAP_On_Azure_Checks'

    if (-not(Test-Path -Path $filepath)) {
        New-Item -Path $filepath -ItemType Directory -Force
    }

    $css_content = @"
body {
font-family: Verdana, Geneva, Arial, Helvetica, sans-serif;
}
 
#report { width: 835px; }
 
table{
border-collapse: collapse;
border: none;
font: 10pt Verdana, Geneva, Arial, Helvetica, sans-serif;
color: black;
margin-bottom: 10px;
}
 
table td{
font-size: 12px;
padding-left: 0px;
padding-right: 20px;
text-align: left;
border-collapse:collapse;
border: 1px solid black;
}
 
table th {
font-size: 12px;
font-weight: bold;
padding-left: 0px;
padding-right: 20px;
text-align: left;
background: #00b8ff;
border-collapse:collapse;
border: 1px solid black;
}

h2{ clear: both; font-size: 110%; }
 
h3{
clear: both;
font-size: 75%;
margin-left: 20px;
margin-top: 30px;
color:#ebeff2;
}
 
p{ margin-left: 20px; font-size: 12px; }
 
table.list{ float: left; }
 
table.list td:nth-child(1){
font-weight: bold;
border-right: 1px black;
border-collapse:collapse;
border: 1px solid black;
text-align: right;
}
 
table.list td:nth-child(2){ padding-left: 7px; }
table tr:nth-child(even) td:nth-child(even)
table tr:nth-child(odd) td:nth-child(odd)
table tr:nth-child(even) td:nth-child(odd)
table tr:nth-child(odd) td:nth-child(even)
div.column { width: 320px; float: left; }
div.first{ padding-right: 20px; border-right: 1px white solid; }
div.second{ margin-left: 30px; }
table{ margin-left: 20px; }
border-collapse:collapse;
border: 1px solid black;
"@

    Add-Content -Path "$filepath\style.css" -Value $css_content -Force

    Write-Host "CSS File Created Successfully... Executing Inventory Report!!! Please Wait !!!" -ForegroundColor Yellow  
    #ReportDate 
    $ReportDate = Get-Date | Select-Object -Property DateTime, @{N = 'Executed By'; E = { $env:USERNAME } } | ConvertTo-Html -Fragment

    foreach ($erv in $input) {

        $varacc = $false
        $localacc = Get-WmiObject -Class Win32_UserAccount -Filter  "name='adminazure'" -ComputerName $erv
        $OS = Get-CimInstance Win32_OperatingSystem -ComputerName $erv
        $service = Get-Service -Name wuauserv -ComputerName $erv
        $timezone = Invoke-Command -ComputerName $erv -ScriptBlock { Get-TimeZone }
        $software = Get-WmiObject -Class Win32_Product -ComputerName $erv #| where { $_.name -like "*Snare*" -or $_.name -like "*CrowdStrike*" -or $_.name -like "*Red Cloak*"}
        $domainjoinstatus = (Get-WmiObject -Class Win32_ComputerSystem -ComputerName $erv).PartOfDomain
        $drive = Get-WmiObject -Class Win32_logicaldisk -ComputerName $erv -Filter DriveType="3" | select @{n = "Drive letter"; e = { $_.DeviceID } }, @{n = "Size"; e = { $_.Size / 1GB } }, @{n = "Free Space"; e = { $_.FreeSpace / 1GB } }, VolumeName
        $drive = gwmi -Class win32_volume -ComputerName $erv -erroraction Ignore
        $DSubnetsAuthoritive = Invoke-Command -ComputerName $erv -ScriptBlock { Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation -Name "DSubnetsAuthoritive" }
        $DomainSubnets = Invoke-Command -ComputerName $erv -ScriptBlock { Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation -Name "DomainSubnets" }
        $Domainfirewall = Invoke-Command -ComputerName $erv -ScriptBlock { Get-NetFirewallProfile -Name "Domain" }
        $Privatefirewall = Invoke-Command -ComputerName $erv -ScriptBlock { Get-NetFirewallProfile -Name "Private" }
        $Publicfirewall = Invoke-Command -ComputerName $erv -ScriptBlock { Get-NetFirewallProfile -Name "Public" }
        $activation = Get-CimInstance -ClassName SoftwareLicensingProduct -ComputerName $erv | where { $_.PartialProductKey }
        $dns = Invoke-Command -ComputerName $erv -ScriptBlock { Get-NetAdapter | Get-DnsClient -ErrorAction SilentlyContinue }
        $dgate = Get-WMIObject Win32_NetworkAdapterConfiguration -computername "$erv" | where { ($_.IPEnabled -eq $true) -and ($_.Description -notlike "*Microsoft Failover Cluster Virtual Adapter*") } | select Description, DefaultIPGateway
        $localadmin = Invoke-Command -ComputerName $erv -ScriptBlock { Get-LocalGroupMember -Group "Administrators" }
        $Remotedesktopusers = Invoke-Command -ComputerName $erv -ScriptBlock { Get-LocalGroupMember -Group "Remote Desktop Users" }
        $Pagefilesize = get-wmiobject Win32_pagefileusage -ComputerName $erv | select caption, AllocatedBaseSize
        $IP = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $erv | where { $_.DefaultIPGateway -ne $null } | select-object Description, ipaddress
        $Amatric = Invoke-Command -ComputerName $erv -ScriptBlock { Get-NetIPInterface | where { ($_.AddressFamily -like "IPV4") -and ($_.InterfaceAlias -like "*Ethernet*") } }
        #invoke-command -computername $ERV -scriptblock {Send-MailMessage -To "jisin@microsoft.com" -from "hdamecharla@microsoft.com" -SmtpServer smtp.microsoft.com -Subject "$env:COMPUTERNAME-Pcut"}
        $windowspatch = Get-HotFix -ComputerName $erv
        $Drivers = Get-WmiObject Win32_PnPSignedDriver -ComputerName $erv | where { $_.DeviceName -like "*Mellanox*" }
        Enter-PSSession -ComputerName $erv
        $DisableCARetryOnInitialConnect = $null
        $DisableCARetryOnInitialConnect = (Invoke-Command -ComputerName $erv { Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\LanmanWorkStation\Parameters -Name DisableCARetryOnInitialConnect }).DisableCARetryOnInitialConnect
        $NICX = Invoke-Command -ComputerName $erv -ScriptBlock { Get-NetAdapterStatistics }
        $IPaddress = (Resolve-DnsName -Name $erv | where { $_.type -eq 'A' }).IPAddress
        $reverselookup = (Resolve-DnsName $IPaddress).NameHost
        $ervdb = ($erv).ToLower().replace("wap", "wdb")
        $ervdb = $ervdb -replace ".{2}$"
        $ervdb = $ervdb + "01" + ".krft.net"
        $telnet = (Test-NetConnection -ComputerName $ervdb -Port 1433)
        $sqlConn = New-Object System.Data.SqlClient.SqlConnection
        $sqlConn.ConnectionString = â€œServer=$evrdb; Integrated Security=true; Initial Catalog=masterâ€
        $sqlConn.Open()
        $sqlcmd = $sqlConn.CreateCommand()
        $sqlcmd = New-Object System.Data.SqlClient.SqlCommand
        $sqlcmd.Connection = $sqlConn
        $query = â€œSELECT SERVERPROPERTY('productversion'), 
        SERVERPROPERTY ('productlevel'), 
        SERVERPROPERTY ('edition')â€
        $sqlcmd.CommandText = $query
        $adp = New-Object System.Data.SqlClient.SqlDataAdapter $sqlcmd
        $data = New-Object System.Data.DataSet
        $adp.Fill($data) | Out-Null
        $clusterfeature = Get-WindowsFeature -Name "Failover-Clustering" -ComputerName $erv
    
        $ser = [system.directoryservices.directorysearcher]"LDAP://dc=krft,dc=net"
        $ser.Filter = "(&(objectclass=computer)(name=$erv))"
        $res = $ser.FindAll()
    
        if ( $res[0] -eq $null) { 
            $ou = "Not Found in AD"
        }
    
    
        $res[0].path.replace("LDAP://", "").split(",") | where { $_ -like "DC=*" } | % { 
    
            $ou = $null
    
            for ($i = ($res[0].path.replace("LDAP://", "").split(",") ).count; $i -gt 0; --$i) {
                if ($i -eq ($res[0].path.replace("LDAP://", "").split(",") ).count -or $i -eq (($res[0].path.replace("LDAP://", "").split(",") ).count - 1) ) {
    
                    #"in if"
                }
                else {
                    $ou += $( [string]($res[0].path.replace("LDAP://", "").split(",") )[$i - 1].split("=")[-1] + [string]"/")
                }
            }
        }
    
        $ou = "/krft.Net/" + $ou
        $ou = $ou.substring(0, ($ou.Length - ($ou.split("/")[-2]).length - 2) )
    
    
        $windowsdefender = Invoke-Command -computername $erv -scriptblock { (Get-WindowsFeature | where { $_.name -eq "Windows-Defender" }).Installstate } 
    
        if ($windowsdefender -like "*Available*") {
            $windefender = "NOT-INSTALLED"
        }
        else {
            $windefender = "INSTALLED"
        }
    
        if (($localacc).Name -eq "adminazure") {
            $varacc = $true
        }
        if ($DSubnetsAuthoritive -eq 1) {
            $DSubnets = "Enabled"
        }
        else { $DSubnets = "Disabled" }
        if (($Domainfirewall).Enabled -eq 0 ) {
            $fire = $false
        }
        else { $fire = $true }
        if (($Privatefirewall).Enabled -eq 0 ) {
            $fire1 = $false
        }
        else { $fire1 = $true }
        if (($publicfirewall).Enabled -eq 0 ) {
            $fire2 = $false
        }
        else { $fire2 = $true }
        if (($activation).LicenseStatus -eq 1 ) {
            $activate = "Activated"
        }
        else { $activate = "Not Activated" }
    
        If ($reverselookup -ne $null) {
            $reverselookup = "True"
        }
    
        if ($data.Tables -ne $null) {
            $DSNconnection = "Open"
        }
        if ($clusterfeature -ne $null) {
            $clusternames = Invoke-Command -ComputerName $erv { (Get-Cluster).name }
            $clustergroups = Invoke-Command -ComputerName $erv { Get-ClusterGroup }
            $clusterNodes = Invoke-Command -ComputerName $erv { Get-ClusterNode }
        }
    
        $keepalivetime = $null
        $keepaliveinterval = $null
        $keepalivetime = invoke-command -ComputerName $erv -ScriptBlock { (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -Name KeepAliveTime -ErrorAction SilentlyContinue).keepalivetime }
        $keepaliveinterval = invoke-command -ComputerName $erv -ScriptBlock { (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -Name KeepAliveInterval -ErrorAction SilentlyContinue).KeepAliveInterval }
        if ($keepalivetime -ne $null) {
            $keepalivetime = "$keepalivetime"
        }
        Else {
            $keepalivetime = "NA"
        }
    
        if ($keepaliveinterval -ne $null) {
            $keepaliveinterval = "$keepaliveinterval"
        }
        Else {
            $keepaliveinterval = "NA"
        }
    
        $servicesToCheck = @("GxClMgrS(Instance001)", "GxCVD(Instance001)", "GXMMM(Instance001)", "GxFWD(Instance001)", "GxVssProv(Instance001)" )
        $commvaultservice = $null
        $commvaultservice = Get-Service -ComputerName $erv -Name $servicesToCheck -ErrorAction SilentlyContinue
        if ($commvaultservice -eq $null) {
            $Commvaultservicestatus = "NotFound"
        }
        Else {
            $Commvaultservicestatus = "Present"
        }
    
        $hfile = $null
        $hostfile = $null
        $hostfile = Invoke-Command -ComputerName $erv -ScriptBlock { Get-Content -path C:\Windows\System32\Drivers\etc\hosts } |
        where { (!$_.StartsWith("#")) -and $_ -ne "" }
    
        if ($hostfile -ne $null) {
            $hfile = "exist"
        }
        else {
            $hfile = "Not-exist"
        }
    
        $dnssuffixlist = $null
        $dnssuffixlist = Invoke-Command -ComputerName $erv -ScriptBlock { (Get-DnsClientGlobalSetting).SuffixSearchList.count }
    
        $event = $null
        $systemevent = $null
        $event = Get-EventLog System -After (Get-Date).Adddays(-1) | Where { $_.EntryType -eq 'Critical' -or $_.EntryType -eq 'Error' }
        if ($event -eq $null) {
            $Systemevent = "Null"
        }
        Else {
            $Systemevent = "Errors"
        }
    
        $xboxstartuptype = (Get-Service XblAuthManager -ComputerName $erv).StartType
        $xboxservicestatus = (Get-Service XblAuthManager -ComputerName $erv).Status
    
        $arr11 = @()
        foreach ($clustername in $clusternames) {
            $clusterIP = (Resolve-DnsName  $clusternames).IPAddress
            $obj11 = new-object -TypeName PSobject
            $obj11 | Add-Member -MemberType NoteProperty -Name "Server Name" -Value $erv
            $obj11 | Add-Member -MemberType NoteProperty -Name "Clustername" -Value $clustername
            $obj11 | Add-Member -MemberType NoteProperty -Name "ClusterIP" -Value $clusterIP
            $arr11 += $obj11
        }
        #$arr11 | Export-Excel -Path $ExportPath1 -WorksheetName "ClusterConfiguration" -Append
        $clusterpath = Test-Path "\\$erv\C$\Windows\Cluster\Reports"
        if ($clusterpath -eq $true) {
            $clusterreport = [xml]$(Get-Content -Path "\\$erv\C$\Windows\Cluster\Reports\*.xml")
            if ($clusterreport.Report.Channel.Channel.message.level -like 'Warn' -and $clusterreport.Report.Channel.Channel.message.level -like 'Erro*') {
                $clusterstatus = "Error"
            }
            elseif ($clusterreport.Report.Channel.Channel.message.level -like 'Warn') {
                $clusterstatus = "OK with Warning"
            }
            Else {
                $clusterstatus = "OK"
            }
        }
        else {
            $clusterstatus = "NA"
        }
        $crowdstrikepnpversion = (Get-WmiObject Win32_PnPSignedDriver -ComputerName $erv | where { $_.manufacturer -like "*crowd*" }).DriverVersion
        $DiskTimeOutValue = $null
        $DiskTimeOutValue = Invoke-Command -ComputerName $erv -ScriptBlock { (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Disk" -Name TimeOutValue).TimeOutValue
        }
        $array = @()
        $obj = new-object -TypeName PSobject
        $obj | Add-Member -MemberType NoteProperty -Name "Server Name" -Value $erv
        $obj | Add-Member -MemberType NoteProperty -Name "Operating System" -Value $OS.caption
        $obj | Add-Member -MemberType NoteProperty -Name "Operating System Version" -Value $OS.version
        $obj | Add-Member -MemberType NoteProperty -Name "Time Zone" -Value $timezone.DisplayName
        $obj | Add-Member -MemberType NoteProperty -Name "adminazure" -Value $varacc
        $obj | Add-Member -MemberType NoteProperty -Name "DSubnetsAuthoritive" -Value $DSubnets
        $obj | Add-Member -MemberType NoteProperty -Name "DomainSubnets" -Value $DomainSubnets
        $obj | Add-Member -MemberType NoteProperty -Name "Domain joinstatus" -Value $domainjoinstatus
        $obj | Add-Member -MemberType NoteProperty -Name "Domain Firewall" -Value $fire
        $obj | Add-Member -MemberType NoteProperty -Name "Private Firewall" -Value $fire1
        $obj | Add-Member -MemberType NoteProperty -Name "Public Firewall" -Value $fire2
        $obj | Add-Member -MemberType NoteProperty -Name "Server Activation" -Value $activate
        $obj | Add-Member -MemberType NoteProperty -Name "KMS Server" -Value $activation.KeyManagementServiceMachine
        $obj | Add-Member -MemberType NoteProperty -Name "Windows update service startuptype" -Value $service.StartType
        $obj | Add-Member -MemberType NoteProperty -Name "Windows update service status" -Value $service.Status
        $obj | Add-Member -MemberType NoteProperty -name "ReverseLookup" -value $reverselookup
        $obj | Add-Member -MemberType NoteProperty -Name "TelnetConnection" -value $telnet.TcpTestSucceeded
        $obj | Add-Member -MemberType NoteProperty -name "RemoteAddress" -value $telnet.RemoteAddress
        $obj | Add-Member -MemberType NoteProperty -name "DSNConnection" -value $DSNconnection
        $obj | add-member -MemberType NoteProperty -name "OU" -Value "$OU"
        $obj | add-member -MemberType NoteProperty -name "WindowsDefenderStatus" -Value "$windefender"
        $obj | add-member -membertype Noteproperty -name "keepalivetime" -value "$keepalivetime"
        $obj | add-member -membertype Noteproperty -name "keepaliveinterval" -value "$keepaliveinterval"
        $obj | add-member -membertype Noteproperty -name "Commvaultservicestatus" -value "$Commvaultservicestatus"
        $obj | add-member -membertype Noteproperty -name "Hostfile" -value "$hfile"
        $obj | Add-Member -MemberType NoteProperty -name "DNSsuffixcount" -Value "$dnssuffixlist"
        $obj | Add-Member -MemberType NoteProperty -name "SystemEvents" -Value "$Systemevent"
        $obj | Add-Member -MemberType NoteProperty -name "xboxstartuptype" -Value "$xboxstartuptype"
        $obj | Add-Member -MemberType NoteProperty -name "xboxservicestatus" -Value "$xboxservicestatus"
        $obj | Add-Member -MemberType NoteProperty -name "CSPNPdriverVersion" -Value "$crowdstrikepnpversion"
        $obj | Add-Member -MemberType NoteProperty -name "DisableCARetryOnInitialConnect" -Value "$DisableCARetryOnInitialConnect"
        $obj | Add-Member -MemberType NoteProperty -name "DiskTimeOutValue" -Value "$DiskTimeOutValue"
    
        $array += $obj
        $srv_win_html_frag = $obj | ConvertTo-Html -As LIST
        #$array | Export-Excel -Path $ExportPath1 -WorksheetName "OS1" -Append 
    
        $array1 = @()
        foreach ($disk in $drive) {
            $obj1 = new-object -TypeName PSobject
            $obj1 | Add-Member -MemberType NoteProperty -Name "Server Name" -Value $erv
            $obj1 | Add-Member -MemberType NoteProperty -Name "Drive letter" -Value $disk.Name
            $obj1 | Add-Member -MemberType NoteProperty -Name "Total Size" -Value ($disk.Capacity / 1GB)
            $obj1 | Add-Member -MemberType NoteProperty -Name "Free Space" -Value ($disk.FreeSpace / 1GB)
            $obj1 | Add-Member -MemberType NoteProperty -Name "Volume Name" -Value $disk.Label
            $obj1 | Add-Member -MemberType NoteProperty -Name "Blocksize" -Value $disk.blocksize
    
            $array1 += $obj1
        } 
        #$array1 | Export-Excel -Path $ExportPath1 -WorksheetName "Disk Detail" -Append
        $disk_details = $array1 | ConvertTo-Html -Fragment
    
        $array2 = @()
        foreach ($IPs in $IP) {
            $obj2 = new-object -TypeName PSobject
            $obj2 | Add-Member -MemberType NoteProperty -Name "Server Name" -Value $erv
            $obj2 | Add-Member -MemberType NoteProperty -Name "IP Description" -Value $IPs.Description
            if ($ips.ipaddress.count -gt 1) {
                $ipaddress = $null
                for ($i = 0; $i -lt $ips.ipaddress.count ; $i++) {
                    $ipaddress += $ips.ipaddress[$i] + "`n`r"
    
                }
                $obj2 | Add-Member -MemberType NoteProperty -Name "IP Address" -Value $ipaddress
            }
            Else {
                $obj2 | Add-Member -MemberType NoteProperty -Name "IP Address" -Value $IPs.ipaddress
            }
            $array2 += $obj2
        } 
        #$array2 |  Export-Excel -Path $ExportPath1 -WorksheetName "IP" -Append
        $ip_addr_details = $array2 | ConvertTo-Html -Fragment
    
        $array3 = @()
        foreach ($nicdns in $dns) {
            $obj3 = new-object -TypeName PSobject
            $obj3 | Add-Member -MemberType NoteProperty -Name "Server Name" -Value $erv
            $obj3 | Add-Member -MemberType NoteProperty -Name "NIC Name" -Value $nicdns.InterfaceAlias
            $obj3 | Add-Member -MemberType NoteProperty -Name "RegisterThisConnectionsAddress" -Value $nicdns.RegisterThisConnectionsAddress
            $obj3 | Add-Member -MemberType NoteProperty -name "UseSuffixWhenRegistering" -Value $nicdns.UseSuffixWhenRegistering
    
            $array3 += $obj3 
        }
        #$array3 | Export-Excel -Path $ExportPath1 -WorksheetName "NIC Detail" -Append
        $nic_details = $array3 | ConvertTo-Html -Fragment
    
        $arraydgate = @()
        foreach ($gate in $dgate) {
            $objdgate = new-object -TypeName PSobject
            $objdgate | Add-Member -MemberType NoteProperty -Name "Server Name" -Value $erv
            $objdgate | Add-Member -MemberType NoteProperty -Name "Nic Description" -Value $gate.Description
            $objdgate | Add-Member -MemberType NoteProperty -Name "DefaultIPGateway" -Value $gate.DefaultIPGateway
            $arraydgate += $objdgate 
        }
        #$arraydgate | Export-Excel -Path $ExportPath1 -WorksheetName "Nic Gateway" -Append
        $nic_gateway_details = $arraydgate | ConvertTo-Html -Fragment
    
        $arrayamate = @()
        foreach ($Amate in $Amatric) {
            $objamate = new-object -TypeName PSobject
            $objamate | Add-Member -MemberType NoteProperty -Name "Server Name" -Value $erv
            $objamate | Add-Member -MemberType NoteProperty -Name "Interface Alias" -Value $Amate.InterfaceAlias
            $objamate | Add-Member -MemberType NoteProperty -Name "Automatic Metric" -Value $Amate.AutomaticMetric
            $objamate | Add-Member -MemberType NoteProperty -Name "Automatic Metric Value" -Value $Amate.InterfaceMetric
            $arrayamate += $objamate 
        }
        #$arrayamate | Export-Excel -Path $ExportPath1 -WorksheetName "AutomaticMetric" -Append
        $nic_metric_details = $arrayamate | ConvertTo-Html -Fragment
    
        $array4 = @()
        foreach ($admins in $localadmin) {
            $obj4 = new-object -TypeName PSobject
            $obj4 | Add-Member -MemberType NoteProperty -Name "Server Name" -Value $erv
            $obj4 | Add-Member -MemberType NoteProperty -Name "Local Admin Group list" -Value $admins.name 
            $array4 += $obj4 
        }
        #$array4 | Export-Excel -Path $ExportPath1 -WorksheetName "LocalAdmin" -Append
        $srv_lcl_admin_list = $array4 | ConvertTo-Html -Fragment
    
        $array5 = @()
        foreach ($page in $Pagefilesize) {
            $obj5 = new-object -TypeName PSobject
            $obj5 | Add-Member -MemberType NoteProperty -Name "Server Name" -Value $erv
            $obj5 | Add-Member -MemberType NoteProperty -Name "Page File Drive" -Value $page.caption
            $obj5 | Add-Member -MemberType NoteProperty -Name "Page File Size" -Value $page.AllocatedBaseSize 
            $array5 += $obj5 
        }
        #$array5 | Export-Excel -Path $ExportPath1 -WorksheetName "PagefileSetting" -Append
        $srv_pagefile_setting = $array5 | ConvertTo-Html -Fragment
    
        $array6 = @()
        foreach ($name1 in $software) {
    
            $obj6 = new-object -TypeName PSobject
            $obj6 | Add-Member -MemberType NoteProperty -Name "Server Name" -Value $erv
            $obj6 | Add-Member -MemberType NoteProperty -Name "Software Name" -Value $name1.name
            $obj6 | Add-Member -MemberType NoteProperty -Name "Version" -Value $name1.version
    
            $array6 += $obj6
        }
        #$array6 |  Export-Excel -Path $ExportPath1 -WorksheetName "Installed Software" -Append
        $srv_sftw_list = $array6 | ConvertTo-Html -Fragment
    
        $array7 = @()
        foreach ($patch in $windowspatch) {
            $obj7 = new-object -TypeName PSobject
            $obj7 | Add-Member -MemberType NoteProperty -Name "Server Name" -Value $erv
            $obj7 | Add-Member -MemberType NoteProperty -Name "Patch Description" -Value $patch.Description
            $obj7 | Add-Member -MemberType NoteProperty -Name "HotFixID" -Value $patch.HotFixID
            $obj7 | Add-Member -MemberType NoteProperty -Name "InstalledBy" -Value $patch.InstalledBy
            $obj7 | Add-Member -MemberType NoteProperty -Name "InstalledOn" -Value $patch.InstalledOn
    
            $array7 += $obj7
        }
        #$array7 |  Export-Excel -Path $ExportPath1 -WorksheetName "All Patches" -Append
        $srv_patch_list = $array7 | ConvertTo-Html -Fragment

        $array8 = @()
        if ($Drivers -ne $null) {
            foreach ($driver in $drivers) {
                $obj8 = new-object -TypeName PSobject
                $obj8 | Add-Member -MemberType NoteProperty -Name "Server Name" -Value $erv
                $obj8 | Add-Member -MemberType NoteProperty -name "MellanoxDriveName" -Value $driver.DeviceName
                $obj8 | Add-Member -MemberType NoteProperty -Name "Driver Version" -Value $driver.DriverVersion
                $array8 += $obj8
            }
        
        }
        Else {
            $obj8 = new-object -TypeName PSobject
            $obj8 | Add-Member -MemberType NoteProperty -Name "Server Name" -Value $erv
            $obj8 | Add-Member -MemberType NoteProperty -name "MellanoxDriveName" -Value "Mellanox driver is not present"
            $obj8 | Add-Member -MemberType NoteProperty -Name "Driver Version" -Value "Mellanox driver is not present"
            $array8 += $obj8
        }
        #$array8 |  Export-Excel -Path $ExportPath1 -WorksheetName "Mellanoxdriver" -Append
        $srv_mllnx_drvr_ver = $array8 | ConvertTo-Html -Fragment
    
        $array9 = @()
        $recievebuffers = @()
        Foreach ($NIC in $NICX) {
            $recievebuffers = Invoke-Command -ComputerName $erv -ScriptBlock { Get-NetAdapterAdvancedProperty -DisplayName "Receive Buffer Size" }
        }
        Foreach ($recievebuffer in $recievebuffers) {
            $obj9 = new-object -TypeName PSobject
            #$obj9 |Add-Member -MemberType NoteProperty -name "NICName" -Value "$rbuffer.name"
            $obj9 | Add-Member -MemberType NoteProperty -Name "Server Name" -Value $erv
            $obj9 | Add-Member -MemberType NoteProperty -Name "Nicname" -Value $recievebuffer.Name
            $obj9 | Add-Member -MemberType NoteProperty -Name "Receivebuffersize" -Value $recievebuffer.RegistryValue
            $array9 += $obj9
        }
        #$array9 |  Export-Excel -Path $ExportPath1 -WorksheetName "Receivebuffer" -Append
        $nic_recv_buff_size = $array9 | ConvertTo-Html -Fragment
    
        $array10 = @()
        $Sendbuffers = @()
        Foreach ($NIC in $NICX) {
            $Sendbuffers = Invoke-Command -ComputerName $erv -ScriptBlock { Get-NetAdapterAdvancedProperty -DisplayName "Send Buffer Size" }
        }
        Foreach ($Sendbuffer in $Sendbuffers) {
            $obj10 = new-object -TypeName PSobject
            #$obj9 |Add-Member -MemberType NoteProperty -name "NICName" -Value "$rbuffer.name"
            $obj10 | Add-Member -MemberType NoteProperty -Name "Server Name" -Value $erv
            $obj10 | Add-Member -MemberType NoteProperty -Name "Nicname" -Value $Sendbuffer.Name
            $obj10 | Add-Member -MemberType NoteProperty -Name "SendBuffersize" -Value $Sendbuffer.RegistryValue
            $array10 += $obj10
        }
        #$array10 |  Export-Excel -Path $ExportPath1 -WorksheetName "SendBuffer" -Append
        $nic_send_buff_size = $array10 | ConvertTo-Html -Fragment
        # Get Azure Detail
        $azInstanceMetadata = Invoke-RestMethod -Headers @{"Metadata" = "true" } `
            -URI 'http://169.254.169.254/metadata/instance?api-version=2020-09-01' `
            -Method GET

        $az_basic_info = Get-AzInstanceMetaDataBasic -InstanceMetadata $azInstanceMetadata | ConvertTo-Html -Fragment
        $az_os_info = Get-AzInstanceMetaDataOS -InstanceMetadata $azInstanceMetadata | ConvertTo-Html -Fragment
        $az_disk_info = Get-AzInstanceMetaDataDiskDetails -InstanceMetadata $azInstanceMetadata | ConvertTo-Html -Fragment
        $az_network_info = Get-AzInstanceMetaDataNetwork -InstanceMetadata $azInstanceMetadata | ConvertTo-Html -Fragment

        # SAP Checks
        #Registry Setting on relevant for (A)SCS Cluster nodes
        $SAPSCSREGKEY = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters | Select-Object KeepAliveTime, KeepAliveInterval | `
            ConvertTo-Html -Fragment 

        #SAP Kernel
        $SAPKERNEL = (Get-Item '\\krft.net\sapmnt\EAS\SYS\exe\uc\NTAMD64\DISP+WORK.exe').VersionInfo | Select-Object ProductName, ProductVersion, FileName | `
            ConvertTo-Html -Fragment 
                    

        #Cluster Detail - Cluster Service Name
        $Cluster = Get-Cluster | Select-Object Name 

        #Cluster Detail - Cluster Group
        $ClusterGroup = Get-ClusterGroup | Select-Object Name, OwnerNode, State | `
            ConvertTo-Html -Fragment

        #Cluster Detail - Cluster Node
        $ClusterNode = Get-ClusterNode | Select-Object Name, ID, State | `
            ConvertTo-Html -Fragment

        #Cluster Detail - Cluster Network
        $ClusterNetwork = Get-ClusterNetwork | Select-Object Name, State, Metric, Role | `
            ConvertTo-Html -Fragment

        #Cluster Detail - Cluster Resource
        $ClusterResource = Get-ClusterResource | Select-Object Name, State, OwenerGroup, ResourceType | `
            ConvertTo-Html -Fragment

        # Cluster Parameters
        $ClusterParameter = Get-ClusterResource | Get-ClusterParameter | `
            ConvertTo-Html -Fragment
        #$inst = (get-itemproperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server').InstalledInstances

        #SQL Server Name
        $sqlserver = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL" | Select-Object MSSQLSERVER | `
            ConvertTo-Html -Fragment

        #SQL Server Version
        $sqlserverversion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQLServer\CurrentVersion" | Select-Object CurrentVersion | `
            ConvertTo-Html -Fragment              

        #MS ODBC Version
        $msodbcversion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSODBCSQL13\CurrentVersion" | Select-Object Version, PatchLevel | `
            ConvertTo-Html -Fragment

        # Get SAP Environment Variable
        $env = Get-Item -Path Env:*BCP* | select-object Name, value | `
            ConvertTo-Html
        <#
            $routeprint = $null
            $rfilename = "$erv" + "Routeprint"
            $routeprint = Invoke-Command -ComputerName $erv -ScriptBlock { cmd /c Route print }
            $routeprint | out-file  "c:\temp\$rfilename.txt"
    
            $rfiles = gc -path "c:\temp\$rfilename.txt"
            $Rfs = $rfiles.Split("`n")
            foreach ($rf in $Rfs) {
                $rf |  Export-Excel -Path $ExportPath1 -WorksheetName "Route Print" -append
            }
            #>
        Write-Host "Data fetching completed for the server:" $erv -ForegroundColor Yellow
        $htmlBody = @"
<h2><B>Azure VM - SAP Compatability Checks</B><h2>
<h2><B>Report Executed On</B></h2>$ReportDate
<h2><B><p style="color:blue">Azure VM Properties Checks</p>
<h2><B2>Azure VM Basic details</B></h2>$az_basic_info
<h2><B2>Azure VM OS details</B></h2>$az_os_info
<h2><B2>Azure VM Disk details</B></h2>$az_disk_info
<h2><B2>Azure VM Network details</B></h2>$az_network_info
<h2><B2>Windows Server validations</B></h2>$srv_win_html_frag
<h2><B2>Disk Details</B></h2>$disk_details
<h2><B2>IP Address Detials</B></h2>$ip_addr_details
<h2><B2>NIC details</B></h2>$nic_details
<h2><B2>NIC gateway details</B></h2>$nic_gateway_details
<h2><B2>NIC metric details</B></h2>$nic_metric_details
<h2><B2>NIC recieve buffer size</B></h2>$nic_recv_buff_size
<h2><B2>NIC send buffer size</B></h2>$nic_send_buff_size
<h2><B2>Mellanox Driver details</B></h2>$srv_mllnx_drvr_ver
<h2><B2>Local admin list</B></h2>$srv_lcl_admin_list
<h2><B2>Server PageFile settings</B></h2>$srv_pagefile_setting
<h2><B2>Windows Server software list</B></h2>$srv_sftw_list
<h2><B2>Windows Server patch list</B></h2>$srv_patch_list
<h2><B2><p style="color:blue">SAP Application Specific Checks to review SAP Best Parctices</p>
<h2><B>SAP SCS Registry Keys</B></h2>$SAPSCSREGKEY
<h2><B>SAP KERNEL</B></h2>$SAPKERNEL
<h2><B>Cluster Service Name</B></h2>$Cluster
<h2><B>Cluster Group</B></h2>$ClusterGroup
<h2><B>Cluster Node</B></h2>$ClusterNode
<h2><B>Cluster Network</B></h2>$ClusterNetwork
<h2><B>Cluster Resource</B></h2>$ClusterResource
<h2><B>Cluster Parameter</B></h2>$ClusterParameter
<h2><B>SQL Server</B></h2>$sqlserver
<h2><B>SQL Server Version</B></h2>$sqlserverversion
<h2><B>MS ODBC Version</B></h2>$msodbcversion
<h2><B>Environment Variable</B></h2>$env
"@
        $ComputerName = $env:COMPUTERNAME
        ConvertTo-Html -Body $htmlBody -CssUri "$filepath\style.css" `
            -Title "Server Inventory - $ComputerName" | `
            Out-File "$filepath\$ComputerName.html"
    }
    #start comparison block
    #If ($?) { Get-WinDowsComparisonResults }
         
}

#we get instance metadata once. So, let's try simple things
#Because we have properties which need to be expanded, we split them into smaller functions and give
#the ability to output smaller chunks of relevant information. 
#Also, try ad make it easier for people to follow what the code is doing. 
function Get-AzInstanceMetaDataBasic {
    param (
        [PSCustomObject]$InstanceMetadata
    )

    $azInstanceMetadataObject = New-Object -TypeName PSObject

    $azInstanceMetadataObject = ([PSCustomObject]@{
            'Azure Environment' = $InstanceMetadata.compute.azEnvironment;
            'Location'          = $InstanceMetadata.compute.location;
            'Zone'              = $InstanceMetadata.compute.zone;
            'RG Name'           = $InstanceMetadata.compute.resourceGroupName;
            'VmName'            = $InstanceMetadata.compute.name;
            'OS Type'           = $InstanceMetadata.compute.osType;
            'VmSku'             = $InstanceMetadata.compute.vmSize;
            'FaultDomain'       = $InstanceMetadata.compute.platformFaultDomain;
            'UpdateDomain'      = $InstanceMetadata.compute.platformUpdateDomain;
        })
    
    Write-Output -InputObject $azInstanceMetadataObject
}

function Get-AzInstanceMetaDataOS {
    param (
        [PSCustomObject]$InstanceMetadata
    )

    $azInstanceMetadataObject = New-Object -TypeName PSObject
    $osData = $InstanceMetadata.compute.storageProfile.imageReference #offer, publisher, sku, version
    $osAdminUser = $InstanceMetadata.compute.osprofile.adminUsername

    $azInstanceMetadataObject = ([PSCustomObject]@{
            'RG Name'    = $InstanceMetadata.compute.resourceGroupName;
            'VmName'     = $InstanceMetadata.compute.name;
            'OS Type'    = $InstanceMetadata.compute.osType;
            'Offer'      = $osData.offer;
            'Publisher'  = $osData.publisher;
            'Sku'        = $osData.sku;
            'Version'    = $osData.version;
            'Admin User' = $osAdminUser;
        })

    Write-Output -InputObject $azInstanceMetadataObject
}

function Get-AzInstanceMetaDataDiskDetails {
    param (
        [PSCustomObject]$InstanceMetadata
    )

    $azInstanceMetadataObject = @() #[collections.generic.list[object]] doesn't work on VMs? Need to investigaate
    $osDiskData = $InstanceMetadata.compute.storageProfile.osDisk #offer, publisher, sku, version
    $osDataDiskData = $InstanceMetadata.compute.storageProfile.dataDisks
    
    $azInstanceMetadataObject += ([PSCustomObject]@{
            'RG Name'        = $InstanceMetadata.compute.resourceGroupName;
            'VmName'         = $InstanceMetadata.compute.name;
            'DiskName'       = $osDiskData.name
            'Lun'            = "OS";
            'Disk Size (GB)' = $osDiskData.diskSizeGB;
            'Disk Caching'   = $osDiskData.caching;
            'Disk Type'      = $osDiskData.managedDisk.storageAccountType;
            'IsWAEnabled'    = $osDiskData.writeAcceleratorEnabled;
        })
    
    foreach ($dataDisk in $osDataDiskData) {
        $azInstanceMetadataObject += ([PSCustomObject]@{
                'RG Name'        = $InstanceMetadata.compute.resourceGroupName;
                'VmName'         = $InstanceMetadata.compute.name;
                'DiskName'       = $dataDisk.name
                'Lun'            = $dataDisk.lun;
                'Disk Size (GB)' = $dataDisk.diskSizeGB;
                'Disk Caching'   = $dataDisk.caching;
                'Disk Type'      = $dataDisk.managedDisk.storageAccountType;
                'IsWAEnabled'    = $dataDisk.writeAcceleratorEnabled;
            })
    }

    Write-Output -InputObject $azInstanceMetadataObject
}

function Get-AzInstanceMetaDataNetwork {
    param (
        [PSCustomObject]$InstanceMetadata
    )

    $azInstanceMetadataObject = @()
    $azNetworkData = $InstanceMetadata.network.interface.ipv4
    
    <#
        #subnet.address returns an overload definition on windows 2019.
        #so for now we do subnet[0].address to get the CIDR
        OverloadDefinitions
        -------------------
        System.Object&, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089 Address(int )
    #>
    foreach ($ipConfig in $azNetworkData.ipAddress) {
        $privateIP = $ipConfig.privateIPAddress
        $publicIP = $ipConfig.publicIPAddress
        $SubnetCIDR = ""
        #get associated subnet from the list of subnets available from metadata
        for ($i = 0; $i -lt $azNetworkData.subnet.Count; $i++) {
            $SubnetCIDR = $azNetworkData.subnet[$i].address + '/' + 
                            $azNetworkData.subnet[$i].prefix
            
            if(Invoke-IsIPAddressInSubnet -IPAddress $privateIP -SubnetCIDR $SubnetCIDR){
                $azInstanceMetadataObject += ([PSCustomObject]@{
                    'RG Name'           = $InstanceMetadata.compute.resourceGroupName;
                    'VmName'            = $InstanceMetadata.compute.name;
                    'Private IPAddress' = $privateIP;
                    'Public IPAddress'  = $publicIP;
                    'Subnet Prefix'     = $SubnetCIDR
                })
            }else {
                continue
            }
        }
        
    }

    Write-Output -InputObject $azInstanceMetadataObject
}

function Invoke-IsIPAddressInSubnet {
    param (
        [string]$IPAddress,
        [string]$SubnetCIDR
    )
    $status = $false
    <#
     #We will not validate if the IPAddress and the CIDR notation are valid as these are already validated
     #by the azure platform.    
    #>

    $routingPrefix = ($SubnetCIDR -split '/' | Select-Object -First 1)
    $prefixLength =($SubnetCIDR -split '/' | Select-Object -Last 1)
    [IPAddress]$parsedIPAddress = [System.Net.IPAddress]::Parse($IPAddress)
    [IPAddress]$parsedRoutingPrefix = [System.Net.IPAddress]::Parse($routingPrefix)

    [int]$baseAddress = $parsedRoutingPrefix.Address 
    [int]$ipaddressAddress = $parsedIPAddress.Address
    [int]$mask = [System.Net.IPAddress]::HostToNetworkOrder(-1 -shl (32 - [int]($prefixLength))) 
    
    if(($baseAddress -band $mask) -eq ($ipaddressAddress -band $mask)){
        $status = $true
    }else {
        $status = $false
    }
    
    return $status
}