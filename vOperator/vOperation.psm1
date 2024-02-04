####################################################################################

############## Obsolete functions, will be replaced with new functions later on
Function Convert-hvAPIFilter {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, HelpMessage = "Your accesstoken to Horizon Connetion Server")]
        [ValidateNotNullOrEmpty()]
        [securestring]$accessToken,
        [Parameter(Mandatory = $true, HelpMessage = "Horizon Connection Server FQDN")]
        [ValidateScript({ $_ -notlike "https://*" })]
        [string]$hvURI,
        [Parameter(Mandatory = $true, HelpMessage = "Enter the restmethod you want to use for example /external/v1/audit-events")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ $_ -like "/*" })]
        [String]$restMethod,
        [Parameter(Mandatory = $false, HelpMessage = "Used for URI query for example some rest method are /inventory/v1/desktop-pools/{id} then you will enter the /ID here")]
        #[ValidateScript({ $_ -like "/*" })]
        [String]$ID,
        [Parameter(Mandatory = $false, HelpMessage = "Used when some restmethods adds extra url at the end for example of the URI string /inventory/v2/desktop-pools/{id}/action/schedule-push-image")]
        [ValidateScript({ $_ -like "/*" })]
        [String]$urlExtra,
        [Parameter(Mandatory = $false, HelpMessage = "Pass your filter or filters here")]
        [Array]$Filter,
        [Parameter(Mandatory = $false, HelpMessage = "Enter filter type, for example And. This is case sensitiv")]
        [ValidateSet("Equals", "NotEquals", "Contains", "StartsWith", "Between", "Not", "And", "Or")]
        [String]$FilterType,
        [Parameter(Mandatory = $false, HelpMessage = "How you want to sort something either ASC or DESC (Case sensitiv), SortBy must be used combined with this")]
        [ValidateSet("ASC", "DESC")]
        [String]$OrderBy = "ASC",
        [Parameter(Mandatory = $false, HelpMessage = "Sort by property in return data from the REST API call")]
        [String]$SortBy,
        [Parameter(Mandatory = $false, HelpMessage = "How many result you want to show on each page, default 500")]
        [int]$PageSize = 500,
        [Parameter(Mandatory = $false, HelpMessage = "Use this if you want to use pagination")]
        [Switch]$Pagination = $false,
        [Parameter(Mandatory = $false, HelpMessage = "What type of filter you want to use")]
        [ValidateSet("ID", "IDFilter", "Filter", "uriFilter")]
        [String]$Type,
        [Parameter(Mandatory = $false, HelpMessage = "If you want to use filter in the URI example https://FQDN/rest/inventory/v1/global-sessions?user_id")]
        [ValidateScript({ $_ -notlike "*=*" })]
        [String]$uriFilterName,
        [Parameter(Mandatory = $false, HelpMessage = "If you want to use filter in the URI, enter value here example https://FQDN/rest/inventory/v1/global-sessions?user_id=YOURVALUE")]
        [String]$uriFilterValue
    )

    try {
        # Importing translation of the returncodes from the rest API
        #$ReturnCodeTranslation = (Import-tSetting -Category "Horizon" -Setting "API_ReturnCode" -All).ReturnValue

        #Building first state or URI for rest
        $firstURI = "https://$hvURI/rest" + $restMethod

        # If SortBy are populated it will add it to the URI you also need to use order_by. This should be last in the URI
        if (-Not([string]::IsNullOrEmpty($SortBy))) {
            $SortOrder = "&sort_by=$SortBy&order_by=$OrderBy"
        }

        # If filter type is used then it will format URI to work with filter
        if (-Not([string]::IsNullOrEmpty($FilterType))) {
            # Adding filter to API Call
            $FilterHashtable = [ordered]@{
                'type'    = $FilterType
                'filters' = [array]$Filter
            }
        
            # Making sure that the depth of the filter is correct
            $FilterJson = $FilterHashtable | ConvertTo-Json -Compress -Depth 5 -WarningVariable FilterJsonWarning
        
            # Making sure that the JSON depth are right, if not it will increase the depth to be correct
            if ($FilterJsonWarning) {
                $Depth = 6
                while ($FilterJsonWarning) {
                    $Depth++
                    $FilterJson = $FilterHashtable | ConvertTo-Json -Depth $Depth -Compress -WarningVariable FilterJsonWarning
                }
            }
            
            # Building filter string to URI
            $uriFilter = "filter=" + $FilterJson
        }
        # If ID is used it will format URI to work with ID
        elseif ($Type -eq "ID") {
            # If somethings is in $ID it will convert the secondURI in the correct way
            $secondURI = $firstURI + $ID + "?"
        }
        elseif ($Type -eq "uriFilter") {
            $secondURI = $firstURI + "?" + $uriFilterName + "=" + $uriFilterValue
        }
        else {
            # If ID is empty this will be the secondURI convertation
            $secondURI = $firstURI + "?"
        }

        if ($Pagination -eq $true) {
            Switch ($Type) {
                uriFilter {
                    $finalURI = $firstURI + "?" + $uriFilterName + "=" + $uriFilterValue + "&" + "page="
                }
                Filter {
                    $finalURI = $firstURI + "?" + $uriFilter + "&" + "page="
                }
                IDFilter {
                    $finalURI = $firstURI + "?" + $uriFilterName + "=" + $uriFilterValue + "&" + "page="
                }
                ID {
                    $finalURI = $secondURI + "page="
                }
                default {
                    $finalURI = $secondURI + "page="
                }
            }

            # Looking how many pages it should be and making sure that it search trough each page
            $Page = 0
            do {
                $Page++
                if ($Type -eq "IDFilter") {
                    $pageURI = $finalURI + $Page + "&size=$PageSize" + "&" + $uriFilter
                }
                else {
                    $pageURI = $finalURI + $Page + "&size=$PageSize" + $SortOrder
                }
                $APICall = Invoke-RestMethod -Uri $pageURI -Method Get -ContentType "application/json" -Authentication Bearer -Token $accessToken -StatusCodeVariable "StatusCode" -ResponseHeadersVariable "responsHeader" -HttpVersion 3.0
            } while ($responsHeader.HAS_MORE_RECORDS -eq $true)
        }
        else {
            $finalURI = $secondURI + $urlExtra + $SortOrder
            $APICall = Invoke-RestMethod -Uri $finalURI -Method Get -ContentType "application/json" -Authentication Bearer -Token $accessToken -StatusCodeVariable "StatusCode" -ResponseHeadersVariable "responsHeader" -HttpVersion 3.0
        }

        # Retriving the results
        if ($StatusCode -eq 200 -and $null -ne $APICall) {
            return Get-ReturnMessageTemplate -ReturnType Success -Message "Success, did retrive all data from REST API Call against $finalURI" -ReturnValue $APICall
            Break
        }
        else {
            return Get-ReturnMessageTemplate -ReturnType Error -Message "$($ReturnCodeTranslation.$($StatusCode).translate), ErrorCode: $StatusCode" -ReturnValue $StatusCode
            Break
        }
    }
    catch {
        return Get-ReturnMessageTemplate -ReturnType Error -Message "$($PSItem.Exception.Message)"
        break
    }
}
################################################################################

Function Get-ReturnMessageTemplate {
    <#
        .SYNOPSIS
        Return messages and value in the correct format

        .DESCRIPTION
        This function will return value and messages in the correct format for vOperator to use.

        .PARAMETER ReturnType

        .PARAMETER Message

        .PARAMETER ReturnValue

        .EXAMPLE

        .LINK

        .NOTES
        Author:         Robin Stolpe
        Private:        robin@stolpe.io
        Twitter / X:    https://twitter.com/rstolpes
        Website:        https://stolpe.io
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, HelpMessage = "What kind of message do you want template for")]
        [ValidateSet("Error", "Success", "Warning", "Information")]
        [string]$ReturnType,
        [Parameter(Mandatory = $false, HelpMessage = "Message that you want to return")]
        $Message = "N/A",
        [Parameter(Mandatory = $false, HelpMessage = "Return value that you want to present for the user, not return message.")]
        $ReturnValue = "N/A"
    )

    Switch ($ReturnType) {
        Error {
            return [PSCustomObject]@{
                ReturnCode  = 1
                Severity    = "Error"
                Icon        = "xmark"
                IconColor   = "red"
                Color       = 'red'
                Duration    = "4000"
                Message     = $Message
                ReturnValue = $ReturnValue
            }
            Break
        }
        Success {
            return [PSCustomObject]@{
                ReturnCode  = 0
                Severity    = "Success"
                Icon        = "Check"
                IconColor   = "green"
                Color       = 'green'
                Duration    = "4000"
                Message     = $Message
                ReturnValue = $ReturnValue
            }
            Break
        }
        Warning {
            return [PSCustomObject]@{
                ReturnCode  = 2
                Severity    = "Warning"
                Icon        = "TriangleExclamation"
                IconColor   = "yellow"
                Color       = 'yellow'
                Duration    = "4000"
                Message     = $Message
                ReturnValue = $ReturnValue
            }
            Break
        }
        Information {
            return [PSCustomObject]@{
                ReturnCode  = 3
                Severity    = "Info"
                Icon        = "CircleInfo"
                IconColor   = "blue"
                Color       = 'blue'
                Duration    = "4000"
                Message     = $Message
                ReturnValue = $ReturnValue
            }
            Break
        }
    }
}
Function Disconnect-hvSrv {
    <#
        .SYNOPSIS
        Disconnect Horizon connection against the API on the Connection Server

        .DESCRIPTION

        .PARAMETER hvURI

        .PARAMETER accessToken

        .PARAMETER refreshToken

        .EXAMPLE

        .LINK

        .NOTES
        Author:         Robin Stolpe
        Private:        robin@stolpe.io
        Twitter / X:    https://twitter.com/rstolpes
        Website:        https://stolpe.io
    #>
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, HelpMessage = "Connection Server FQDN")]
        [ValidateScript({ $_ -notlike "https://*" })]
        [string]$hvURI,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, HelpMessage = "AccessToken to Horizon")]
        [ValidateNotNullOrEmpty()]
        [securestring]$accessToken,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, HelpMessage = "Refresh token from Horizon")]
        [ValidateNotNullOrEmpty()]
        $refreshToken
    )

    try {
        $Body = [ordered]@{
            'refresh_token' = $refreshToken
        }

        $Connection = Invoke-RestMethod -Uri "https://$hvURI/rest/logout" -Method Post -Body ($Body | ConvertTo-Json) -ContentType "application/json" -StatusCodeVariable "StatusCode" -ResponseHeadersVariable "ResponseHeaders" -HttpVersion 3.0
        return Get-ReturnMessageTemplate -ReturnType Success -Message "Disconnected from VMWare Horizon $hvURI"
        Break
    }
    catch {
        return Get-ReturnMessageTemplate -ReturnType Error -Message "$($PSItem.Exception.Message)" -ReturnValue "$($PSItem.Exception.Message)"
        Break
    }
}
Function Get-hvVM {
    <#
        .SYNOPSIS
        This function will return either all VMs that exists in the Horizon POD or a singel machine.

        .DESCRIPTION
        If you don't use -VM "MACHINENAME" you will get all machines

        .PARAMETER hvURI

        .PARAMETER accessToken

        .PARAMETER FilterName

        .PARAMETER FilterValue

        .EXAMPLE

        .LINK

        .NOTES
        Author:         Robin Stolpe
        Private:        robin@stolpe.io
        Twitter / X:    https://twitter.com/rstolpes
        Website:        https://stolpe.io
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, HelpMessage = "Connection Server FQDN")]
        [ValidateScript({ $_ -notlike "https://*" })]
        [string]$hvURI,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, HelpMessage = "AccessToken to Horizon")]
        [ValidateNotNullOrEmpty()]
        [SecureString]$accessToken,
        [Parameter(Mandatory = $false, HelpMessage = "Filter on")]
        [string]$FilterName = "name",
        [Parameter(Mandatory = $false, HelpMessage = "Value for filter")]
        [string]$FilterValue
    )

    try {
        if ([string]::IsNullOrEmpty($FilterValue)) {
            $APICall = Convert-hvAPIFilter -hvURI $hvURI -accessToken $accessToken -SortBy "name" -restMethod "/inventory/v5/machines" -Pagination
            $LogText = "all VMs"
        }
        else {
            [array]$filtersAPI = [ordered]@{
                'type'  = 'Equals'
                'name'  = $FilterName
                'value' = $FilterValue
            }

            $APICall = Convert-hvAPIFilter -Filter $filtersAPI -FilterType And -hvURI $hvURI -accessToken $accessToken -SortBy "name" -restMethod "/inventory/v5/machines" -Pagination -Type Filter
            $LogText = "VM $FilterName $FilterValue"
        }
        if ($APICall.ReturnCode -eq 0 -and $APICall.ReturnValue.Count -gt 0) {
            return Get-ReturnMessageTemplate -ReturnType Success -Message "Information about $LogText have been collected." -ReturnValue $($APICall.ReturnValue)
            Break
        }
        else {
            return Get-ReturnMessageTemplate -ReturnType Error -Message "Information about $LogText could not be collected." -ReturnValue $APICall
            Break
        }
    }
    catch {
        return Get-ReturnMessageTemplate -ReturnType Error -Message "$($PSItem.Exception.Message)" -ReturnValue "$($PSItem.Exception)"
        break
    }
}
Function Set-hvVMUserAssignment {
    <#
        .SYNOPSIS
        Assign or Unassign user to persistent VM in Horizon

        .DESCRIPTION

        .PARAMETER accessToken
        Horizon Access token

        .PARAMETER UserName
        Enter Username of the user that you want to change assignment for, if you running this script on a non Windows machine please enter SID instead of username.

        .PARAMETER hvURI
        Enter URI for the Horizon Connection Server, the hole FQDN. Don't use https://

        .PARAMETER VM
        Plain name of the VM you want to assign or unassign user on.

        .PARAMETER Action
        Enter what kind of action you want to execute. Valide inputs are "unassign", "assign"

        .EXAMPLE

        .LINK

        .NOTES
        Author:         Robin Stolpe
        Private:        robin@stolpe.io
        Twitter / X:    https://twitter.com/rstolpes
        Website:        https://stolpe.io
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName, HelpMessage = "AccessToken to Horizon")]
        [ValidateNotNullOrEmpty()]
        [SecureString]$accessToken,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName, HelpMessage = "Connection Server FQDN, don't enter https://")]
        [ValidateScript({ $_ -notlike "https://*" })]
        [String]$hvURI,
        [Parameter(Mandatory = $true, HelpMessage = "Name of the VM you want to get assign or unassign user against")]
        [ValidateNotNullOrEmpty()]
        [String]$VM,
        [Parameter(Mandatory = $true, HelpMessage = "Enter what you want to do here, valid input is unassign or assign")]
        [ValidateSet("unassign", "assign")]
        [String]$Action,
        [Parameter(Mandatory = $true, HelpMessage = "Enter username of the user or users you want to make changes for, if your running this script on no Windows machine please enter SID instead of username.")]
        [ValidateNotNullOrEmpty()]
        [String]$UserName
    )
    
    try {
        Switch ($Action) {
            assign {
                [string]$urlAction = "assign-users"
            }
            unassign {
                [string]$urlAction = "unassign-users"
            }
        }

        # Get VM information from Horizon
        $GetVMInfo = Get-hvVM -FilterName name -FilterValue $VM -accessToken $accessToken -hvURI $hvURI
        if ($GetVMInfo.ReturnCode -eq 0) {
            $VMInfo = $GetVMInfo.ReturnValue
            [String]$VMID = "$($VMInfo.Id)"
        }

        if ($PSVersionTable.Platform -like "Win32NT") {
            # Convert UserName to SID
            $UserSID = $(Get-ADUser -Filter "sAMAccountName -eq '$UserName'" | select-object -ExpandProperty SID).value
        }
        else {
            $UserSID = $UserName 
        }
        
        # Creating Body
        [string]$RAWBody = $UserSID
        $Body = "[$($RAWBody | ConvertTo-Json)]"
    
        $APICall = Invoke-RestMethod -Uri "https://$hvURI/rest/inventory/v1/machines/$VMID/action/$urlAction" -Method POST -Body $Body -Authentication Bearer -Token $accessToken -ContentType "application/json" -StatusCodeVariable "StatusCode" -HttpVersion 3.0
            
        if ($StatusCode -eq 200 -and $APICall.Status_Code -eq 200) {
            return Get-ReturnMessageTemplate -ReturnType Success -Message "$UserName are now $Action to $VM" -ReturnValue $APICall
            Break
        }
        else {
            return Get-ReturnMessageTemplate -ReturnType Error -Message "Could not $Action on VM $VM for user $UserName, API Status Code: $StatusCode Call Status Code: $($APICall.Status_Code)" -ReturnValue "API Status Code: $StatusCode Call Status Code: $($APICall.Status_Code)"
            Break
        }
    }
    catch {
        return Get-ReturnMessageTemplate -ReturnType Error -Message "$($PSItem.Exception.Message)" -ReturnValue "$($PSItem.Exception.Message)"
        Break
    }
}
Function Get-hvDesktopPool {
    <#
        .SYNOPSIS
        This function let you get a specific Desktop Pool

        .DESCRIPTION

        .PARAMETER hvURI

        .PARAMETER accessToken

        .PARAMETER FilterValue

        .PARAMETER FilterName

        .EXAMPLE

        .LINK

        .NOTES
        Author:         Robin Stolpe
        Private:        robin@stolpe.io
        Twitter / X:    https://twitter.com/rstolpes
        Website:        https://stolpe.io
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, HelpMessage = "Connection Server FQDN")]
        [ValidateScript({ $_ -notlike "https://*" })]
        [string]$hvURI,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, HelpMessage = "AccessToken to Horizon")]
        [ValidateNotNullOrEmpty()]
        [SecureString]$accessToken,
        [Parameter(Mandatory = $false, HelpMessage = "Name of the pool")]
        [ValidateNotNullOrEmpty()]
        [string]$FilterValue,
        [Parameter(Mandatory = $false, HelpMessage = "What you want to search for")]
        [ValidateSet("name", "display_name", "id", "global_desktop_entitlement_id")]
        [string]$FilterName = "name"
    )

    try {
        if ($ID -eq $false) {
            #/inventory/v7/desktop-pools/{id}
        }
        elseif ([string]::IsNullOrEmpty($FilterValue)) {
            $APICall = Convert-hvAPIFilter -hvURI $hvURI -accessToken $accessToken -SortBy "name" -restMethod "/inventory/v7/desktop-pools" -Pagination
        }
        else {
            [array]$filtersAPI = [ordered]@{
                'type'  = 'Equals'
                'name'  = $FilterName
                'value' = $FilterValue
            }
            $APICall = Convert-hvAPIFilter -Filter $filtersAPI -FilterType And -hvURI $hvURI -accessToken $accessToken -SortBy "name" -restMethod "/inventory/v7/desktop-pools" -Pagination -Type Filter
        }

        if ($APICall.ReturnCode -eq 0 -and $APICall.ReturnValue.Count -gt 0) {
            return Get-ReturnMessageTemplate -ReturnType Success -Message "All information about Desktop Pool $FilterValue has been collected" -ReturnValue $APICall.ReturnValue
            Break
        }
        else {
            return Get-ReturnMessageTemplate -ReturnType Error -Message "Could not find any Desktop Pool with the $FilterName $FilterValue" -ReturnValue $APICall.ReturnValue
            Break
        }
    }
    catch {
        return Get-ReturnMessageTemplate -ReturnType Error -Message "Get-NewhvDesktopPool $($PSItem.Exception.Message)"
        break
    }
}
Function Set-hvVMPool {
    <#
        .SYNOPSIS

        .DESCRIPTION

        .PARAMETER hvURI

        .PARAMETER accessToken

        .PARAMETER VM

        .PARAMETER DesktopPool

        .PARAMETER Action

        .EXAMPLE

        .LINK

        .NOTES
        Author:         Robin Stolpe
        Private:        robin@stolpe.io
        Twitter / X:    https://twitter.com/rstolpes
        Website:        https://stolpe.io
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, HelpMessage = "Enter FQDN to one Connection Server")]
        [ValidateNotNullOrEmpty()]
        [string]$hvURI,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, HelpMessage = "Access token for authentication")]
        [ValidateNotNullOrEmpty()]
        [SecureString]$accessToken,
        [Parameter(Mandatory = $true, HelpMessage = "Name of the VM")]
        [ValidateNotNullOrEmpty()]
        [string]$VM,
        [Parameter(Mandatory = $true, HelpMessage = "Name of Horizon Pool")]
        [ValidateNotNullOrEmpty()]
        [string]$DesktopPool,
        [Parameter(Mandatory = $true, HelpMessage = "Select what you want to do, add or remove machine from pool")]
        [ValidateSet("Add", "Remove")]
        [string]$Action,
        [Parameter(Mandatory = $false, HelpMessage = "if you use this you need to enter VM ID in VM parameter and Pool ID in DesktopPool parameter")]
        [Switch]$UseID = $false
    )

    try {
        if ($UseID -eq $false) {
            # Check so the Desktop Pool exists and extract the ID
            $CheckDesktopPool = Get-hvDesktopPool -FilterValue $DesktopPool -hvURI $hvURI -accessToken $accessToken
            if ($CheckDesktopPool.ReturnCode -eq 0) {
                if ($Null -ne $CheckDesktopPool) {
                    [String]$DesktopPoolID = $($CheckDesktopPool.ReturnValue).Id
                }
                else {
                    return Get-ReturnMessageTemplate -ReturnType Error -Message "Could not find any Desktop Pool with the name $DesktopPool"
                    Break
                }
            }
            else {
                return $CheckDesktopPool
                Break
            }

            # Collecting virutal center ID
            $GetVirtualCenter = Get-hvVirtualCenter -hvURI $hvURI -accessToken $accessToken
            if ($GetVirtualCenter.ReturnCode -eq 0) {
                [String]$vCenterID = $($GetVirtualCenter.ReturnValue.id -as [string])
            }
            else {
                return $GetVirtualCenter
                Break
            }

            # Collecting all VMs from virtual center and grabbing the correct one.
            $GetVirtualCenterVMs = Get-hvVirtualCenterVM -VM $VM -VirtualCenterID $vCenterID -hvURI $hvURI -accessToken $accessToken
            if ($GetVirtualCenterVMs.ReturnCode -eq 0) {
                [String]$VMID = $($GetVirtualCenterVMs.ReturnValue).Id
            }
            else {
                return $GetVirtualCenterVMs
                Break
            }
        }
        else {
            $DesktopPoolID = $DesktopPool
            $VMID = $VM
        }


        # Adding VM to pool
        $Body = "[$($VMID | ConvertTo-Json)]"
        if ($Action -like "Add") {
            $APICall = Invoke-RestMethod -Uri "https://$hvURI/rest/inventory/v1/desktop-pools/$DesktopPoolID/action/add-machines" -Method Post -Body $Body -ContentType "application/json" -Authentication Bearer -Token $accessToken -HttpVersion 3.0 -StatusCodeVariable "StatusCode"
        }
        else {
            $APICall = Invoke-RestMethod -Uri "https://$hvURI/rest/inventory/v1/desktop-pools/$DesktopPoolID/action/remove-machines" -Method Post -Body $Body -ContentType "application/json" -Authentication Bearer -Token $accessToken -HttpVersion 3.0 -StatusCodeVariable "StatusCode"
        }

        if ($APICall.status_code -notlike "4*") {
            return Get-ReturnMessageTemplate -ReturnType Success -Message "VM $VM is now $($Action) to/from VMWare Horizon pool $DesktopPool" -ReturnValue $APICall
            Break
        }
        else {
            return Get-ReturnMessageTemplate -ReturnType Error -Message "Could not $($Action) VM $VM to/from VMWare Horizon pool $DesktopPool, StatusCode: $($APICall.status_code)" -ReturnValue $APICall
            Break
        }
    }
    catch {
        return Get-ReturnMessageTemplate -ReturnType Error -Message "$($PSItem.Exception.Message)" -ReturnValue "$($PSItem.Exception.Message)"
        Break
    }
}
Function Convert-hvAPI {
    <#
    This function will format API url for Horizon to the proper format.
    It's for calls with two filters in the url string

    ### Type IDurlfilter ###
    With one urlfilter parameter used -ID , -urlfilter , urlvalue
    https://FQDN/rest/external/v2/base-vms/YOURID?vcenter_id=YOURVALUE

    With two urlfilter, parameter used -ID , -urlfilter , urlvalue -urlfilter2 -urlvalue2
    https://FQDN/rest/external/v2/base-vms/YOURID?vcenter_id=YOURVALUE&datacenter_id=YOURVALUE

    ### Type urlfilter ###
    With one urlfilter
    https://FQDN/rest/external/v2/base-snapshots?vcenter_id=YOURVALUE&page=1&size=10&filter=FILTER&sort_by=id&order_by=ASC

    With two urlfilter
    https://FQDN/rest/external/v2/base-snapshots?vcenter_id=YOURVALUE&base_vm_id=YOURVALUE&page=1&size=10&filter=FILTER&sort_by=id&order_by=ASC

    And if it's not with a filter
    Example command:
    Convert-hvAPI -hvURI FQDN -accessToken ACCESSTOKEN -restMethod "/external/v1/virtual-machines" -uriFilterName "vcenter_id" -uriFilterValue $VirtualCenterID -Type urlfilter -Pagination
    Example url:
    https://FQDN/rest/external/v1/virtual-machines?vcenter_id=VIRTUALCENTERID&page=1&size=10&sort_by=id&order_by=ASC
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, HelpMessage = "Your accesstoken to Horizon Connetion Server")]
        [ValidateNotNullOrEmpty()]
        [securestring]$accessToken,
        [Parameter(Mandatory = $true, HelpMessage = "Horizon Connection Server FQDN")]
        [ValidateScript({ $_ -notlike "https://*" })]
        [string]$hvURI,
        [Parameter(Mandatory = $true, HelpMessage = "Enter the restmethod you want to use for example /external/v1/audit-events")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ $_ -like "/*" })]
        [String]$restMethod,
        [Parameter(Mandatory = $false, HelpMessage = "What type of url you want to convert it to")]
        [ValidateSet("UrlFilter", "IDUrlFilter", "ID")]
        [String]$Type,
        [Parameter(Mandatory = $false, HelpMessage = "Pass your filter or filters here")]
        [Array]$Filter,
        [Parameter(Mandatory = $false, HelpMessage = "Enter filter type, for example And. This is case sensitiv")]
        [ValidateSet("Equals", "NotEquals", "Contains", "StartsWith", "Between", "Not", "And", "Or")]
        [String]$FilterType,
        [Parameter(Mandatory = $false, HelpMessage = "How you want to sort something either ASC or DESC (Case sensitiv), SortBy must be used combined with this")]
        [ValidateSet("ASC", "DESC")]
        [String]$OrderBy = "ASC",
        [Parameter(Mandatory = $false, HelpMessage = "Sort by property in return data from the REST API call")]
        [String]$SortBy,
        [Parameter(Mandatory = $false, HelpMessage = "IDUrlFilter, only used")]
        [String]$ID,
        [Parameter(Mandatory = $false, HelpMessage = "How many result you want to show on each page, default 500")]
        [int]$PageSize = 100,
        [Parameter(Mandatory = $false, HelpMessage = "Use this if you want to use pagination")]
        [Switch]$Pagination = $false,
        [Parameter(Mandatory = $false, HelpMessage = "If you want to use filter in the URI example https://FQDN/rest/inventory/v1/global-sessions?user_id it's the user_id")]
        [ValidateScript({ $_ -notlike "*=*" })]
        [String]$uriFilterName,
        [Parameter(Mandatory = $false, HelpMessage = "If you want to use filter in the URI, enter value here example https://FQDN/rest/inventory/v1/global-sessions?user_id=YOURVALUE")]
        [String]$uriFilterValue,
        [Parameter(Mandatory = $false, HelpMessage = "Second URL filter, If you want to use filter in the URI example https://FQDN/rest/inventory/v1/global-sessions?user_id it's the user_id")]
        [ValidateScript({ $_ -notlike "*=*" })]
        [String]$uriFilterName2,
        [Parameter(Mandatory = $false, HelpMessage = "Second URL filter, If you want to use filter in the URI, enter value here example https://FQDN/rest/inventory/v1/global-sessions?user_id=YOURVALUE")]
        [String]$uriFilterValue2
    )

    try {
        # Importing translation of the returncodes from the rest API
        #$ReturnCodeTranslation = (Import-tSetting -Category "Horizon" -Setting "Return_Code" -All).ReturnValue

        #Building first state or URI for rest
        $firstURI = "https://$hvURI/rest" + $restMethod

        # If SortBy are populated it will add it to the URI you also need to use order_by. This should be last in the URI
        if (-Not([string]::IsNullOrEmpty($SortBy))) {
            $SortOrder = "&sort_by=$SortBy&order_by=$OrderBy"
        }

        # If filter type is used then it will format URI to work with filter
        if (-Not([string]::IsNullOrEmpty($FilterType))) {
            # Adding filter to API Call
            $FilterHashtable = [ordered]@{
                'type'    = $FilterType
                'filters' = [array]$Filter
            }
        
            # Making sure that the depth of the filter is correct
            $FilterJson = $FilterHashtable | ConvertTo-Json -Compress -Depth 5 -WarningVariable FilterJsonWarning
        
            # Making sure that the JSON depth are right, if not it will increase the depth to be correct
            if ($FilterJsonWarning) {
                $Depth = 6
                while ($FilterJsonWarning) {
                    $Depth++
                    $FilterJson = $FilterHashtable | ConvertTo-Json -Depth $Depth -Compress -WarningVariable FilterJsonWarning
                }
            }
            
            # Building filter string to URI
            $uriFilter = "filter=" + $FilterJson
        }
        else {
            Switch ($Type) {
                urlfilter {
                    if (-Not([string]::IsNullOrEmpty($uriFilterName2))) {
                        $secondURI = $firstURI + "?" + $uriFilterName + "=" + $uriFilterValue + "&" + $uriFilterName2 + "=" + $uriFilterValue2
                    }
                    else {
                        $secondURI = $firstURI + "?" + $uriFilterName + "=" + $uriFilterValue
                    }
                }
                IDUrlFilter {
                    if (-Not([string]::IsNullOrEmpty($uriFilterName2))) {
                        $secondURI = $firstURI + "/$($ID)" + "?" + $uriFilterName + "=" + $uriFilterValue + "&" + $uriFilterName2 + "=" + $uriFilterValue2
                    }
                    else {
                        $secondURI = $firstURI + "/$($ID)" + "?" + $uriFilterName + "=" + $uriFilterValue
                    }
                }
            }
        }

        if ($Pagination -eq $true) {
            Switch ($Type) {
                urlfilter {
                    if (-Not([string]::IsNullOrEmpty($uriFilterName2))) {
                        $finalURI = $firstURI + "?" + $uriFilterName + "=" + $uriFilterValue + "&" + $uriFilterName2 + "=" + $uriFilterValue2 + "&" + "page="
                    }
                    else {
                        $finalURI = $firstURI + "?" + $uriFilterName + "=" + $uriFilterValue + "&" + "page="
                    }
                }
            }

            # Looking how many pages it should be and making sure that it search trough each page
            $Page = 0
            do {
                $Page++
                if (-Not([string]::IsNullOrEmpty($FilterType))) {
                    $pageURI = $finalURI + $Page + "&size=$PageSize" + "&" + $uriFilter + $SortOrder
                }
                else {
                    $pageURI = $finalURI + $Page + "&size=$PageSize" + $SortOrder
                }

                $APICall = Invoke-RestMethod -Uri $pageURI -Method Get -ContentType "application/json" -Authentication Bearer -Token $accessToken -StatusCodeVariable "StatusCode" -ResponseHeadersVariable "responsHeader" -HttpVersion 3.0
            } while ($responsHeader.HAS_MORE_RECORDS -eq $true)
        }
        else {
            $finalURI = $secondURI + $SortOrder
            $APICall = Invoke-RestMethod -Uri $finalURI -Method Get -ContentType "application/json" -Authentication Bearer -Token $accessToken -StatusCodeVariable "StatusCode" -ResponseHeadersVariable "responsHeader" -HttpVersion 3.0
        }

        # Retriving the results
        if ($StatusCode -eq 200 -and $null -ne $APICall) {
            return Get-ReturnMessageTemplate -ReturnType Success -Message "Success, did retrive all data from REST API Call against $finalURI" -ReturnValue $APICall
            Break
        }
        else {
            return Get-ReturnMessageTemplate -ReturnType Error -Message "$($ReturnCodeTranslation.$($StatusCode).translate), ErrorCode: $StatusCode" -ReturnValue $StatusCode
            Break
        }
    }
    catch {
        return Get-ReturnMessageTemplate -ReturnType Error -Message "$($PSItem.Exception.Message)"
        break
    }
}
Function Connect-hvSrv {
    <#
        .SYNOPSIS
        Connect to Horizon Connection Server

        .DESCRIPTION
        With this function you can connect to Horizon Connection Servers and it will return the accessToken and refresh token.
        If the connection server that this function trys to connect to is down, maintaince or similar it will try to connect to an other Connection server at the same POD.
        You can either connect to one specific POD or set All parameter to true then it will randomly connect to some connection server at any of your PODs.

        .PARAMETER POD
        Specify what POD you want to connect to.

        .PARAMETER All
        You can set this to either $true or $false, if you set this to $true it will try to connect to a random connection server at a random POD.

        .EXAMPLE

        .LINK

        .NOTES
        Author:         Robin Stolpe
        Private:        robin@stolpe.io
        Twitter / X:    https://twitter.com/rstolpes
        Website:        https://stolpe.io
    #>

    [CmdletBinding()]
    Param(
        <#[Parameter(Mandatory = $false, HelpMessage = "What POD you want to get connection servers from, don't combine this with All bool")]
        [String]$POD,
        [Parameter(Mandatory = $false, HelpMessage = "Use this if you want to get try to connect to any one of your connection servers in all of your PODs")]
        [bool]$All = $false,#>
        [Parameter(Mandatory = $true, HelpMessage = "This should only be used if it's a new setup with the JSONFile hvEnvironment script")]
        [String]$hvFQDN,
        [Parameter(Mandatory = $true, HelpMessage = "Credentials to connect to Horizon Connection Server")]
        [pscredential]$Cred,
        [Parameter(Mandatory = $true, HelpMessage = "Domain name, not doman.xx it should only be domain")]
        [String]$Domain
    )

    try {
        # Importing settings
        #$SystemSettings = (Import-tSetting -Category "System" -Setting "Settings" -All).ReturnValue
       
        <#
        # Get a horizon connection server that's working
        if ([String]::IsNullOrEmpty($hvFQDN)) {
            $hvServer = Get-hvServer -POD $POD -All $All
        }
        #>

        if ($hvServer.ReturnCode -eq 0 -and [String]::IsNullOrEmpty($hvFQDN) -or (-Not[String]::IsNullOrEmpty($hvFQDN))) {
            <#if (-Not[String]::IsNullOrEmpty($hvFQDN)) {
            $hvInfo = "N/A"
            $hvFQDN = $hvFQDN
            }
            else {
                $hvInfo = $hvServer.ReturnValue
                [String]$hvFQDN = "$($hvInfo.fqdn)"
            }#>

            $Body = [ordered]@{
                'domain'   = $($Domain)
                'username' = $($Cred.UserName)
                'password' = $($Cred.GetNetworkCredential().Password)
            }

            $APICall = Invoke-RestMethod -Uri "https://$hvFQDN/rest/login" -Method Post -Body ($Body | ConvertTo-Json) -ContentType "application/json" -StatusCodeVariable "StatusCode" -ResponseHeadersVariable "ResponseHeader" -HttpVersion 3.0

            if ($StatusCode -eq 200) {
                #$Pod_Name = $(Convert-WhiteSpaceToDot -String $hvInfo.pod_name)
                #$hvName = $(Convert-WhiteSpaceToDot -String $hvInfo.name)
                return [PSCustomObject]@{
                    ReturnCode   = 0
                    accessToken  = ConvertTo-SecureString $APICall.access_token -AsPlainText -Force
                    refreshToken = $APICall.refresh_token
                    #hvName       = $hvName
                    hvURI        = $hvFQDN
                    #POD_Name     = $Pod_Name
                    connectTime  = Get-Date
                    Message      = "Connection established to Horizon Connection Server $hvName with FQDN $hvFQDN in the POD $Pod_Name"
                }
                Break
            }
            else {
                return Get-ReturnMessageTemplate -ReturnType Error -Message "Could not connect to the Horizon Connection Server, ErrorCode: $StatusCode" -ReturnValue "$($StatusCode)"
                Break
            }
        }
        else {
            return $hvServer
            Break
        }
    }
    catch {
        return Get-ReturnMessageTemplate -ReturnType Error -Message "$($PSItem.Exception.Message)" -ReturnValue "$($PSItem.Exception.Message)"
        Break
    }
}
Function Get-hvVirtualCenter {
    <#
    This function will collect information about all Virtual Centers from the POD
    If you fill out $VirtualCenterID you will only get information about that specific Virtual Center
    if you don't fill it out you will get information about all Virtual Centers
    #>
    <#
        .SYNOPSIS

        .DESCRIPTION

        .PARAMETER hvURI

        .PARAMETER accessToken

        .PARAMETER VirtualCenterID

        .EXAMPLE

        .LINK

        .NOTES
        Author:         Robin Stolpe
        Private:        robin@stolpe.io
        Twitter / X:    https://twitter.com/rstolpes
        Website:        https://stolpe.io
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, HelpMessage = "Enter FQDN to one Connection Server")]
        [ValidateNotNullOrEmpty()]
        [string]$hvURI,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, HelpMessage = "Access token for authentication")]
        [ValidateNotNullOrEmpty()]
        [SecureString]$accessToken,
        [Parameter(Mandatory = $false, HelpMessage = "What Virtual Center you want to get information about")]
        [string]$VirtualCenterID
    )

    try {
        if ([string]::IsNullOrEmpty($VirtualCenterID)) {
            $APICall = Invoke-RestMethod -Uri "https://$hvURI/rest/config/v4/virtual-centers" -Method Get -Body $Body -Authentication Bearer -Token $accessToken -ContentType "application/json" -StatusCodeVariable "StatusCode" -HttpVersion 3.0
            $LogText = "all Virtual Centers"
        }
        else {
            $APICall = Invoke-RestMethod -Uri "https://$hvURI/rest/config/v4/virtual-centers/$VirtualCenterID" -Method Get -Body $Body -Authentication Bearer -Token $accessToken -ContentType "application/json" -StatusCodeVariable "StatusCode" -HttpVersion 3.0
            $LogText = "Virtual Center with ID $VirtualCenterID"
        }
        if ($StatusCode -eq 200) {
            return Get-ReturnMessageTemplate -ReturnType Success -Message "Information about$LogText has been collected." -ReturnValue $APICall
            Break
        }
        else {
            return Get-ReturnMessageTemplate -ReturnType Error -Message "Could not collect information about $LogText from VMWare Horizon Connection Server $hvURI, StatusCode: $StatusCode" -ReturnValue "StatusCode: $StatusCode"
            Break
        }
    }
    catch {
        return Get-ReturnMessageTemplate -ReturnType Error -Message "$($PSItem.Exception.Message)"
        break
    }
}
Function Get-hvVirtualCenterVM {
    <#
        .SYNOPSIS
        This function will get all virtual centers for the POD

        .DESCRIPTION

        .PARAMETER hvURI

        .PARAMETER accessToken

        .PARAMETER VM

        .PARAMETER VirtualCenterID

        .EXAMPLE

        .LINK

        .NOTES
        Author:         Robin Stolpe
        Private:        robin@stolpe.io
        Twitter / X:    https://twitter.com/rstolpes
        Website:        https://stolpe.io
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, HelpMessage = "Enter FQDN to one Connection Server")]
        [ValidateNotNullOrEmpty()]
        [string]$hvURI,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, HelpMessage = "Access token for authentication")]
        [ValidateNotNullOrEmpty()]
        [SecureString]$accessToken,
        [Parameter(Mandatory = $false, HelpMessage = "Name of the VM")]
        [String]$VM,
        [Parameter(Mandatory = $true, HelpMessage = "ID for the virtual center")]
        [String]$VirtualCenterID
    )

    try {

        $APICall = Convert-hvAPI -hvURI $hvURI -accessToken $accessToken -restMethod "/external/v1/virtual-machines" -uriFilterName "vcenter_id" -uriFilterValue $VirtualCenterID -Type urlfilter -Pagination

        if ($APICall.ReturnCode -eq 0 -and $null -ne $APICall.ReturnValue) {
            $VerifyVM = $($APICall.ReturnValue | Where-Object { $_.name -like "$($VM)" })
            if ($Null -ne $VerifyVM) {
                return Get-ReturnMessageTemplate -ReturnType Success -Message "Information about VM $VM have been collected from Virtual Center ID $VirtualCenterID" -ReturnValue $VerifyVM
                Break
            }
            else {
                return Get-ReturnMessageTemplate -ReturnType Error -Message "Could not find any VM with the name $VM in Virtual Center ID $VirtualCenterID" -ReturnValue $APICall.ReturnValue
                Break
            }
        }
        else {
            return Get-ReturnMessageTemplate -ReturnType Error -Message "Could not collect VMs from Vritual Center ID $VirtualCenterID, StatusCode: $StatusCode" -ReturnValue "StatusCode: $StatusCode"
            Break
        }
    }
    catch {
        return Get-ReturnMessageTemplate -ReturnType Error -Message "$($PSItem.Exception.Message)" -ReturnValue "$($PSItem.Exception)"
        Break
    }
}