
class SAW {
    [string]$KvName #Azure Key Vault Name
    [string]$KvCName # CName that identifies certificate used to sign into key vault service principle
    [string]$KVSPApplicationId # Service Principle application id that has proper permissions to KV
    [string]$TenantId # Home tenant ID that has GDAP partner relationships to be leveraged
    [string]$AppDisplayName # Automation Application Display, this is the same as the app registration name that will show up in all partner tenants upon consenting
    hidden [string]$PCRefreshToken #used to generate access tokens, this should already be in the keyvault

    hidden [string]$AutomationAppId
    hidden [string]$AutomationAppSecret
    hidden [pscredential]$AppCredential #credential made from AutomationAppId and AutomationAppSecret
    hidden [string]$PartnerAccessToken
    hidden $PartnerCenter
    hidden $CustomerIDs
    hidden $secret #this isn't actually secret and I just use for debugging XD
    
    SAW ([string]$KvName, [string]$KvCName, [string]$KVSPApplicationId, [string]$TenantId, [string]$AppDisplayName) {
        $this.KvName = $KvName
        $this.KvCName = $KvCName
        $this.KVSPApplicationId = $KVSPApplicationId
        $this.TenantId = $TenantId
        $this.AppDisplayName = $AppDisplayName

        $this.initialize()
    }

    SAW () {
        $this.KvName = Read-Host "Enter the key vault name(KvName)"
        $this.KvCName = Read-Host "Enter the key vault certificate name(KvCName)"
        $this.KVSPApplicationId = Read-Host "Enter the key vault service principal application ID(KVSPApplicationId)"
        $this.TenantId = Read-Host "Enter the tenant ID(TenantId)"
        $this.AppDisplayName = Read-Host "Enter the Application Display Name(AppDisplayName)"

        $this.initialize()
    }

    # This function initializes some variables and credentials for the current object pulling from they keyvault 
    hidden initialize() {
        #| ~ ! @ # $ % ^ & * ( ) + [ { ] } | \ ’ < , . > ? / ` " " ; :
        #will match any of these special characters
        $pattern = "\|\~|\!|\@|\#|\$|\%|\^|\&|\*|\(|\)|\+|\[|\{|\]|\}|\||\\|\'|\<|\,|\.|\>|\?|\/|\`"`"|\;|\:\s"

        $params = @(
            @{Name = 'TenantID'; Value = $this.tenantId },
            @{Name = 'AppDisplayName'; Value = $this.AppDisplayName },
            @{Name = 'KVSPApplicationId'; Value = $this.KVSPApplicationId },
            @{Name = 'KvCName'; Value = $this.KvCName },
            @{Name = 'KvName'; Value = $this.KvName }
        )

        #validate variables do not contain special characters
        foreach ($param in $params) {
            # Display a message based on the parameter name
            if ($($param.Value) -match $pattern) {
                Throw "The variable $($param.Name) contains non-alphanumeric characters or is empty."
            } 
        }

        #Trim variables
        $this.KvName = $this.KvName.Trim()
        $this.KvCName = $this.KvCName.Trim()
        $this.KVSPApplicationId = $this.KVSPApplicationId.Trim()
        $this.TenantId = $this.TenantId.Trim()
        $this.AppDisplayName = $this.AppDisplayName.Trim()


        #this makes requests to the keyvault for identifying information that will allow us to generate access tokens for the application
        $this.PCRefreshToken = $this.GetKVSecret("PartnerCenterRefreshToken" )
        $this.AutomationAppId = $this.GetKVSecret("AutomationsAppID") 
        $this.AutomationAppSecret = $this.GetKVSecret("AutomationsAppSecret") 

        $AppCredentialError = ''
        $this.AppCredential = New-Object System.Management.Automation.PSCredential($this.AutomationAppId, ($this.AutomationAppSecret | Convertto-SecureString -AsPlainText -Force)) -ErrorAction Stop -ErrorVariable AppCredentialError
        if ($AppCredentialError) {
            Throw "Failed to create AppCredential: $AppCredentialError"
            return
        }
    }

    <#
    .SYNOPSIS
    Gets a secret from an Azure Key Vault using a background job and a service principal.

    .DESCRIPTION
    This function uses the Azure PowerShell module to get a secret from an Azure Key Vault using a background job and a service principal. It requires the certificate thumbprint, the application ID, and the tenant ID of the service principal, as well as the key vault name and the secret name. It returns the secret as plain text.

    .PARAMETER kvname
    The name of the Azure Key Vault.

    .PARAMETER kvcname
    The name of the certificate used by the service principal.

    .PARAMETER secretname
    The name of the secret to get from the Azure Key Vault.

    .PARAMETER KVSPApplicationId
    The application ID of the service principal.

    .PARAMETER TenantId
    The tenant ID of the service principal.

    .INPUTS
    None. You cannot pipe objects to GetKVSecret.

    .OUTPUTS
    String. The GetKVSecret function returns the secret as plain text.
    #>
    [string] GetKVSecret ( [string]$secretname) {

        # Start a background job to run the script block
        $secretjob = Start-Job -ScriptBlock {
            param($kvname, $kvcname, $secretname, $KVSPApplicationId, $TenantId)

            # Get the certificate thumbprint from the current user's certificate store
            $Thumbprint = (Get-ChildItem cert:\CurrentUser\My\ | Where-Object { $_.Subject -eq $KvCName }).Thumbprint
            # Connect to Azure using the service principal and the certificate
            Connect-AzAccount -ServicePrincipal -CertificateThumbprint $Thumbprint -ApplicationId $KVSPApplicationId -TenantId $TenantId | Out-Null

            # Get the secret from the key vault as plain text
            $secret = (Get-AzKeyVaultSecret -vaultName $KvName -name $secretname -AsPlainText)

            # Disconnect from Azure
            Disconnect-AzAccount | Out-Null

            # Check if the secret is null
            if ($null -eq $secret) {
                # Throw an error if the secret is not found
                Throw "Failed to read secret:'$using:secretname' from Azure Key Vault"
            }
            # Return the secret to the local session
            Return $secret

        } -ArgumentList $this.kvname, $this.kvcname, $secretname, $this.KVSPApplicationId, $this.TenantId 

        # Wait for the job to finish and get the output
        $response = Wait-Job -Job $secretjob | Receive-Job 

        # Return the secret from the job's return value
        return $response
    }


    <# 
    .SYNOPSIS
    Sets a secret in an Azure Key Vault using a service principal.
    .DESCRIPTION
    This function creates a background job that connects to an Azure Key Vault using a service principal with a certificate thumbprint and sets a secret with a specified name and value. It returns the secret object from the job output.
    
    .PARAMETER kvname
    The name of the Azure Key Vault. The default value is the value of the $Script:KvName variable.
    
    .PARAMETER kvcname
    The subject name of the certificate used by the service principal. The default value is the value of the $Script:KvCName variable.
    
    .PARAMETER secretname 
    The name of the secret to set in the Azure Key Vault. This parameter is mandatory.
    
    .PARAMETER secretvalue 
    The value of the secret to set in the Azure Key Vault. This parameter is mandatory.
    
    .PARAMETER KVSPApplicationId 
    The application ID of the service principal. The default value is the value of the $Script:KVSPApplicationId variable.
    
    .PARAMETER TenantId 
    The tenant ID of the Azure subscription. The default value is the value of the $Script:TenantId variable.
    
    .EXAMPLE 
    SetKVSecret -secretname “MySecret” -secretvalue “MyValue”
    
    This example sets a secret named “MySecret” with a value of “MyValue” in the Azure Key Vault using the default values for the other parameters.
    
    .EXAMPLE 
    SetKVSecret -kvname “MyVault” -kvcname “CN=MyCert” -secretname “MySecret” -secretvalue “MyValue” -KVSPApplicationId “12345678-1234-1234-1234-123456789012” -TenantId “87654321-4321-4321-4321-210987654321”
    This example sets a secret named “MySecret” with a value of “MyValue” in the Azure Key Vault named “MyVault” using the specified values for the other parameters.
    
    .INPUTS 
    None. You cannot pipe objects to SetKVSecret.
    #>
    SetKVSecret ([string]$secretname, [string]$secretvalue) {
    
        $secretjob = Start-Job -ScriptBlock {
            param($kvname, $kvcname, $secretname, $secretvalue, $KVSPApplicationId, $TenantId )
    
            #pull thumprint from the local certificate store for authentication
            $Thumbprint = (Get-ChildItem cert:\CurrentUser\My\ | Where-Object { $_.Subject -eq $KvCName }).Thumbprint
            Connect-AzAccount -ServicePrincipal -CertificateThumbprint $Thumbprint -ApplicationId $KVSPApplicationId -TenantId $TenantId 
    
            $secretvaluesecured = ConvertTo-SecureString $secretvalue -AsPlainText -Force
            Set-AzKeyVaultSecret -VaultName $KvName -Name $secretname -SecretValue $secretvaluesecured
    
            Disconnect-AzAccount
    
        } -ArgumentList $this.kvname, $this.kvcname, $secretname, $secretvalue, $this.KVSPApplicationId, $this.TenantId 
    
        Wait-Job -Job $secretjob | Receive-Job 
    }
    

    <#
    .SYNOPSIS
    Gets a Microsoft token for a given tenant ID and scope.

    .DESCRIPTION
    This class function sends a POST request to the Microsoft authentication endpoint and returns a token object that can be used to access Microsoft services.

    .PARAMETER TenantId
    The GUID of the tenant ID. If not specified, the common endpoint is used.

    .PARAMETER Scope
    The scope of the token request. The default value is 'https://graph.microsoft.com/.default', which grants access to the Microsoft Graph API.

    .INPUTS
    None. You cannot pipe objects to GetMicrosoftToken.

    .OUTPUTS
    Object. The GetMicrosoftToken function returns an object that contains the token and other properties, such as token_type, expires_in, and ext_expires_in.

    .EXAMPLE
    $token = $myClass.GetMicrosoftToken ('12345678-1234-1234-1234-123456789012')
    This example gets a token for the tenant ID '12345678-1234-1234-1234-123456789012' and the default scope.

    .EXAMPLE
    $token = $myClass.GetMicrosoftToken ($null, 'https://management.azure.com/.default')
    This example gets a token for the common endpoint and the scope 'https://management.azure.com/.default', which grants access to the Azure Resource Manager API.
    #>
    [Object] GetMicrosoftToken ([guid]$TenantId, [string]$Scope = 'https://graph.microsoft.com/.default') {
        if ($TenantId) {
            $Uri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        }
        else {
            $Uri = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        }
    
        # Define the parameters for the token request
        $Body = @{
            client_id     = $this.AutomationAppId 
            client_secret = $this.AutomationAppSecret
            scope         = $Scope
            refresh_token = $this.PCRefreshToken
            grant_type    = 'refresh_token'
        }
    
        $Params = @{
            Uri             = $Uri
            Method          = 'POST'
            Body            = $Body
            ContentType     = 'application/x-www-form-urlencoded'
            UseBasicParsing = $true
        }
    
        try {
            $AuthResponse = (Invoke-WebRequest @Params).Content | ConvertFrom-Json
        }
        catch {
            throw "Authentication Error Occured $_"
        }
    
        return $AuthResponse
    }


    <#
    .SYNOPSIS
    Gets a partner access token for the current class instance.

    .DESCRIPTION
    This class function checks if the current class instance has a valid partner access token. If not, it calls the GetMicrosoftToken function to get a new token for the partner center API and assigns it to the class instance. It then returns the partner access token as a string.

    .INPUTS
    None. You cannot pipe objects to GetPartnerAccessToken.

    .OUTPUTS
    String. The GetPartnerAccessToken function returns a string that contains the partner access token.

    .EXAMPLE
    $token = $myClass.GetPartnerAccessToken ()
    This example gets a partner access token for the current class instance and assigns it to the $token variable.
    #>
    [string] GetPartnerAccessToken  () {
    
        Write-Host "Generating New Access Token"
        try {
            $PartnerAccessTokenResponse = $this.GetMicrosoftToken($this.tenantID, 'https://api.partnercenter.microsoft.com/user_impersonation')
            $this.PartnerAccessToken = $PartnerAccessTokenResponse.Access_Token
        }
        catch {
            if ($null -eq $this.PartnerAccessToken) {
                throw "Failed to get partner access token"
            }
        }
        Return $this.PartnerAccessToken
    }

    
    <#
    .SYNOPSIS
    Revokes the App Registration API permission for a customer tenant using the PartnerCenter module.

    .DESCRIPTION
    This function uses the PartnerCenter module to revoke the app access for a customer tenant using the given access token, customer tenant ID, and automation app ID. It invokes the revoke API and returns a message indicating the success or failure of the operation.

    .PARAMETER AccessToken
    The access token for the PartnerCenter module.

    .PARAMETER CustomerTenantID
    The customer tenant ID for the app access.

    .PARAMETER AutomationAppID
    The automation app ID for the app access.

    .INPUTS
    None. You cannot pipe objects to RevokeAppAccess.

    .OUTPUTS
    String. The RevokeAppAccess function returns a message indicating the success or failure of the operation.
    #>
    [string] RevokeAppAccess ([string]$CustomerTenantID) {

        if ($null -eq $this.PartnerAccessToken) {
            $this.GetPartnerAccessToken() | Out-Null
        }

        # Construct the revoke URL
    
        $RevokeUrl = "https://api.partnercenter.microsoft.com/v1/customers/$CustomerTenantId/applicationconsents/$($this.AutomationAppId)"
        # Invoke the revoke API with the access token
        try {
            Invoke-RestMethod -Method DELETE `
                -Uri $RevokeUrl `
                -ContentType 'application/json' `
                -Headers @{
                Authorization = "Bearer $($this.PartnerAccessToken)"
                'Accept'      = 'application/json'
            }
            return "App Registration Permissions revoked successfully"
        }
        catch {
            Throw "Failed to revoke access token for customer $CustomerTenantID with error: $_"
        }
    }


   
    <#
    .SYNOPSIS
    Consents to an application on behalf of a customer.

    .DESCRIPTION
    This function uses the Partner Center API to consent to an application on behalf of a customer. It takes the customer tenant ID and an array of application grants as parameters. It returns an object that with the REST API response.

    .PARAMETER CustomerTenantId
    The tenant ID of the customer. This is a GUID that uniquely identifies the customer.

    .PARAMETER Grants
    An array of application grants that specify the permissions and roles for the application. Each grant is a hashmap with enterpriseApplicationId and a scope property defined.

    .INPUTS
    None. You cannot pipe objects to ConsentToApp.

    .OUTPUTS
    System.Object. This function returns an object that contains the secret for the application.

    .EXAMPLE
    PS> $grants = @( 
                    @{ enterpriseApplicationId = "00000003-0000-0000-c000-000000000000"; scope = "Directory.Read.All,Directory.AccessAsUser.All"},
                    @{ enterpriseApplicationId = "00000002-0000-0ff1-ce00-000000000000"; scope = "Exchange.Manage" }
                )
    PS> $myobj.ConsentToApp($CustomerTenantID, $grants)
    #>
    [Object] ConsentToApp ([string]$CustomerTenantId, $grants) {
        $headers = @{
            Authorization = "Bearer $($this.GetPartnerAccessToken())"
            'Accept'      = 'application/json'
        }

        # Consent to required applications
        $uri = "https://api.partnercenter.microsoft.com/v1/customers/$CustomerTenantId/applicationconsents"
        $body = @{
            applicationGrants = $grants
            applicationId     = $this.AutomationAppId
            displayName       = $this.AppDisplayName
        } | ConvertTo-Json

        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method POST -Body $body -ContentType 'application/json'
        $this.secret = $response

        return $response
    }

    <#
    .SYNOPSIS
    Gets all the customer IDs from the Partner Center

    .DESCRIPTION
    This function uses the Partner Center module to connect to the Partner Center API and retrieve the customer IDs of all the customers associated with the partner. It runs the query in a background job and returns the customer IDs as an array of strings. This function remembers the result of the response and does not make additional calls to partner center after the first.

    .PARAMETER PartnerAccessToken
    The access token for the Partner Center API. This can be obtained by using the GetPartnerAccessToken function.

    .INPUTS
    None. You cannot pipe objects to this function.

    .OUTPUTS
    System.String[]. This function returns an array of strings that contain the customer IDs.

    #>
    [String[]] GetAllCustomerIds() {
        if ($null -ne $this.CustomerIDs) {
            return $this.CustomerIDs 
        }

        # Start a background job to run the script block
        $pcjob = Start-Job -ScriptBlock {
            param($PartnerAccessToken)

            Connect-PartnerCenter -AccessToken $PartnerAccessToken | Out-Null
        
            $Customers = (Get-PartnerCustomer).CustomerId

            Disconnect-PartnerCenter | Out-Null
        
            # Return the secret to the local session
            Return $Customers
        
        } -ArgumentList $this.GetPartnerAccessToken()
        
        # Wait for the job to finish and get the output
        $this.CustomerIDs = Wait-Job -Job $pcjob | Receive-Job 

        return $this.CustomerIDs
    }
}





