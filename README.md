## AzSAPVmPostProvisionCheck
It is the SAP On Azure Windows/SQL Server config check script.
###Initial Version#0
Version#0 [current version] is a simple SAP On Azure Checks targetting target OS Windows Server & database SQL Server.
The script runs on the local server and collects critical checks that impacts the functioning of SAP On Azure.
The out is html that must be reviewed by the Customer/Partner SAP Team member.

The Checks includes
1. Azure Properties
2. Operating System Checks
3. SQL Server Checks
4. SAP Registry Checks

I am working to enhance the report and will be updated frequently.

### How to use the script
1. Create a servers.txt and add server name to the "servers.txt" file.
2. Execute tha attached script, it will install the function Get-AzSAPVmPostProvisionCheck
3. Execute the syntax 
Get-AzSAPVmPostProvisionCheck -File "C:\servers.txt" -ExportPath "C:\Output"
4. Report will be generated as HTML file under C:\Temp\SAP_On_Azure_Checks on server where script is executed.
