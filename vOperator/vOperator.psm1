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
        Author:         Robin Widmark
        Mail:           robin@widmark.dev
        Website/Blog:   https://widmark.dev
        X:              https://x.com/widmark_robin
        Mastodon:       https://mastodon.social/@rwidmark
		YouTube:		https://www.youtube.com/@rwidmark
        Linkedin:       https://www.linkedin.com/in/rwidmark/
        GitHub:         https://github.com/rwidmark
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
        Author:         Robin Widmark
        Mail:           robin@widmark.dev
        Website/Blog:   https://widmark.dev
        X:              https://x.com/widmark_robin
        Mastodon:       https://mastodon.social/@rwidmark
		YouTube:		https://www.youtube.com/@rwidmark
        Linkedin:       https://www.linkedin.com/in/rwidmark/
        GitHub:         https://github.com/rwidmark
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
        Author:         Robin Widmark
        Mail:           robin@widmark.dev
        Website/Blog:   https://widmark.dev
        X:              https://x.com/widmark_robin
        Mastodon:       https://mastodon.social/@rwidmark
		YouTube:		https://www.youtube.com/@rwidmark
        Linkedin:       https://www.linkedin.com/in/rwidmark/
        GitHub:         https://github.com/rwidmark
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
        if ($APICall.ReturnCode -eq 0 -and $APICall.ReturnValue.Count -gt 0 -and $null -ne $APICall.ReturnValue.id) {
            return Get-ReturnMessageTemplate -ReturnType Success -Message "Information about $LogText have been collected." -ReturnValue $($APICall.ReturnValue)
            Break
        }
        else {
            return Get-ReturnMessageTemplate -ReturnType Error -Message "Information about $LogText could not be collected." -ReturnValue $($APICall.ReturnValue)
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
        Author:         Robin Widmark
        Mail:           robin@widmark.dev
        Website/Blog:   https://widmark.dev
        X:              https://x.com/widmark_robin
        Mastodon:       https://mastodon.social/@rwidmark
		YouTube:		https://www.youtube.com/@rwidmark
        Linkedin:       https://www.linkedin.com/in/rwidmark/
        GitHub:         https://github.com/rwidmark
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
        Author:         Robin Widmark
        Mail:           robin@widmark.dev
        Website/Blog:   https://widmark.dev
        X:              https://x.com/widmark_robin
        Mastodon:       https://mastodon.social/@rwidmark
		YouTube:		https://www.youtube.com/@rwidmark
        Linkedin:       https://www.linkedin.com/in/rwidmark/
        GitHub:         https://github.com/rwidmark
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
        Author:         Robin Widmark
        Mail:           robin@widmark.dev
        Website/Blog:   https://widmark.dev
        X:              https://x.com/widmark_robin
        Mastodon:       https://mastodon.social/@rwidmark
		YouTube:		https://www.youtube.com/@rwidmark
        Linkedin:       https://www.linkedin.com/in/rwidmark/
        GitHub:         https://github.com/rwidmark
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
        Author:         Robin Widmark
        Mail:           robin@widmark.dev
        Website/Blog:   https://widmark.dev
        X:              https://x.com/widmark_robin
        Mastodon:       https://mastodon.social/@rwidmark
		YouTube:		https://www.youtube.com/@rwidmark
        Linkedin:       https://www.linkedin.com/in/rwidmark/
        GitHub:         https://github.com/rwidmark
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
        Author:         Robin Widmark
        Mail:           robin@widmark.dev
        Website/Blog:   https://widmark.dev
        X:              https://x.com/widmark_robin
        Mastodon:       https://mastodon.social/@rwidmark
		YouTube:		https://www.youtube.com/@rwidmark
        Linkedin:       https://www.linkedin.com/in/rwidmark/
        GitHub:         https://github.com/rwidmark
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
        Author:         Robin Widmark
        Mail:           robin@widmark.dev
        Website/Blog:   https://widmark.dev
        X:              https://x.com/widmark_robin
        Mastodon:       https://mastodon.social/@rwidmark
		YouTube:		https://www.youtube.com/@rwidmark
        Linkedin:       https://www.linkedin.com/in/rwidmark/
        GitHub:         https://github.com/rwidmark
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
Function Send-hvVMAction {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName, HelpMessage = "AccessToken to Horizon")]
        [ValidateNotNullOrEmpty()]
        [SecureString]$accessToken,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName, HelpMessage = "Connection Server FQDN")]
        [ValidateScript({ $_ -notlike "https://*" })]
        [string]$hvURI,
        [Parameter(Mandatory = $true, HelpMessage = "Name of the VM")]
        [ValidateNotNullOrEmpty()]
        [string]$VM,
        [Parameter(Mandatory = $true, HelpMessage = "What you want to do")]
        [ValidateSet("enter-maintenance", "exit-maintenance", "reset", "recover", "rebuild", "restart", "archive")]
        [string]$Action,
        [Parameter(Mandatory = $false, HelpMessage = "Force action, only works with enter-maintenance, restart, reset and recover")]
        [switch]$Force = $false
    )

    try {
        $GetVM = Get-hvVM -accessToken $accessToken -hvURI $hvURI -FilterValue "$($VM)"
        if ($GetVM.ReturnCode -eq 0) {
            [String]$VMID = $($GetVM.ReturnValue.Id)
        }
        else {
            return $GetVM
            Break
        }

        if ($Force -eq $true -and $Action -notlike "exit-maintenance" -and $Action -notlike "archive" -and $Action -notlike "rebuild") {
            $endUrl = "?force=true"
        }
        else {
            $endUrl = ""
        }

        $Body = "[$($VMID  | ConvertTo-Json -Compress)]"

        $APICall = Invoke-RestMethod -Uri "https://$($hvURI)/rest/inventory/v1/machines/action/$($Action)/$($endUrl)" -Method POST -Body $Body -Authentication Bearer -Token $accessToken -ContentType "application/json" -StatusCodeVariable "StatusCode" -HttpVersion 3.0
        if ($StatusCode -eq 200 -and $APICall.Status_Code -eq 200) {
            return Get-ReturnMessageTemplate -ReturnType Success -Message "VM $VM has now $Action"
            Break
        }
        else {
            return Get-ReturnMessageTemplate -ReturnType Error -Message "Could not $Action for VM $VM, API Status Code: $StatusCode Call Status Code: $($APICall.Status_Code)" -ReturnValue $APICall
            Break
        }
    }
    catch {
        return Get-ReturnMessageTemplate -ReturnType Error -Message "$($PSItem.Exception.Message)"
        break
    }
}
Function Get-hvVirtualMachineAge {
    <#
        .SYNOPSIS
        Collect all VMs from a specific pool that are available and older than a specific time

        .DESCRIPTION


        .PARAMETER hvURI
        FQDN to one Connection Server in the POD

        .PARAMETER accessToken
        Access token for authentication.
        You can collect it by using Connect-hvSrv

        .PARAMETER State
        What state you want to filter VM on, if you don't use this parameter it will filter on AVAILABLE

        .PARAMETER PoolName
        Name of the pool you want to collect VMs from

        .PARAMETER Days
        Collect VMs that are older than this amount of days, default is 0.
        You can combined this with Hours and Minutes, at least one of the parameters days, hours or minutes need to be used.

        .PARAMETER Hours
        Collect VMs that are older than this amount of hours, default is 0.
        You can combined this with Days and Minutes, at least one of the parameters days, hours or minutes need to be used.

        .PARAMETER Minutes
        Collect VMs that are older than this amount of minutes, default is 0.
        You can combined this with Days and Hours, at least one of the parameters days, hours or minutes need to be used.

        .PARAMETER Collect
        If you use this switch it will collect all VMs that are older than the time you have specified and return them as a object.
        Collect switch can't be used together with Confirm switch.

        .PARAMETER Confirm
        If you use this switch it will ask you if you really want to delete the VMs that are older than the time you have specified before it deletes them.
        Confirm switch can't be used together with Collect switch.

        .EXAMPLE
        .LINK

        .NOTES
        Author:         Robin Widmark
        Mail:           robin@widmark.dev
        Website/Blog:   https://widmark.dev
        X:              https://x.com/widmark_robin
        Mastodon:       https://mastodon.social/@rwidmark
		YouTube:		https://www.youtube.com/@rwidmark
        Linkedin:       https://www.linkedin.com/in/rwidmark/
        GitHub:         https://github.com/rwidmark
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, HelpMessage = "Enter FQDN to one Connection Server")]
        [ValidateNotNullOrEmpty()]
        [string]$hvURI,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, HelpMessage = "Access token for authentication")]
        [ValidateNotNullOrEmpty()]
        [SecureString]$accessToken,
        [Parameter(Mandatory = $false, HelpMessage = "Filter on state of the VM")]
        [ValidateSet("AVAILABLE", "ASSIGNED", "UNASSIGNED", "ARCHIVED")]
        [string]$State = "AVAILABLE",
        [Parameter(Mandatory = $false, HelpMessage = "Name of the pool")]
        [string]$PoolName,
        [Parameter(Mandatory = $false, HelpMessage = "How old in days should the VM be")]
        [int]$Days = 0,
        [Parameter(Mandatory = $false, HelpMessage = "How old in hours should the VM be")]
        [int]$Hours = 0,
        [Parameter(Mandatory = $false, HelpMessage = "How old in minutes should the VM be")]
        [int]$Minutes = 0,
        [Parameter(Mandatory = $false, HelpMessage = "Collecting all VMs, not deleting them")]
        [switch]$Collect = $false,
        [Parameter(Mandatory = $false, HelpMessage = "Make sure that you really want to delete the VMs before it deletes them")]
        [switch]$Confirm = $false
    )

    try {
        if ($Days -eq 0 -and $Hours -eq 0 -and $Minutes -eq 0) {
            return Get-ReturnMessageTemplate -ReturnType Error -Message "You need to enter a value for Days, Hours or Minutes"
            Break
        }

        if ($Confirm -eq $true -and $Collect -eq $true) {
            return Get-ReturnMessageTemplate -ReturnType Error -Message "You can't use Confirm and Delete at the same time"
            Break
        }

        $textTimePeriod = "$(if ($Days -gt 0) { "$($Days) days " })$(if ($Hours -gt 0) { "$($Hours) hours " })$(if ($Minutes -gt 0) { "$($Minutes) minutes" })"

        # Collecting all information about the pool
        $GetPoolInfo = Get-hvDesktopPool -hvURI $hvURI -accessToken $accessToken -FilterValue $PoolName
        if ($GetPoolInfo.ReturnCode -eq 0) {
            # Collecting all VMs from the pool
            $GetPoolVM = Get-hvVM -hvURI $hvURI -accessToken $accessToken -FilterName "desktop_pool_id" -FilterValue $($GetPoolInfo.ReturnValue.Id)

            # Filter VMs to the on that are not in use by any user
            $AvailableVMs = $GetPoolVM.ReturnValue | Where-Object { $_.state -eq $State }

            # Get todays date
            $Today = Get-Date

            # Filter out VMs according to the parameters
            $FilterAge = foreach ($_vm in $AvailableVMs) {
                $VMAge = [datetimeoffset]::FromUnixTimeMilliseconds($_vm.managed_machine_data.create_time).DateTime
                $ConvertAge = New-TimeSpan -Start $VMAge -End $Today
                if ($ConvertAge.Days -ge $Days -and $ConvertAge.Hours -ge $Hours -and $ConvertAge.Minutes -ge $Minutes) {
                    $_vm
                }
            }

            if ($FilterAge.Count -eq 0) {
                return Get-ReturnMessageTemplate -ReturnType Success -Message "There are no VMs that are older than $($textTimePeriod)in pool $($PoolName)" -ReturnValue $FilterAge
                Break
            }
            else {
                if ($Collect -eq $true) {
                    return Get-ReturnMessageTemplate -ReturnType Success -Message "All VMs that are older than $($textTimePeriod)from $($PoolName) have been collected" -ReturnValue $FilterAge
                    Break
                }
                elseif ($Confirm -eq $true) {
                    $UserAnswer = Read-Host "Do you really want to delete all VMs that are older than $($textTimePeriod)from $($PoolName)? (y/n)"
                    if ($UserAnswer -eq "y") {
                        $ReturnValue = foreach ($_vm in $FilterAge) {
                            $DeleteVM = Remove-hvVM -hvURI $hvURI -accessToken $accessToken -VM $_vm.name
                            if ($DeleteVM.ReturnCode -eq 0) {
                                $DeleteVM.Message
                            }
                            else {
                                $DeleteVM.ReturnValue
                            }
                        }
                        return Get-ReturnMessageTemplate -ReturnType Success -Message "All VMs that was older then $($textTimePeriod)have been deleted from $($PoolName)" -ReturnValue $ReturnValue
                    }
                    elseif ($UserAnswer -eq "n") {
                        return Get-ReturnMessageTemplate -ReturnType Success -Message "You have chosen not to delete any VMs"
                        Break
                    }
                    else {
                        return Get-ReturnMessageTemplate -ReturnType Error -Message "You need to enter y or n"
                        Break
                    }

                }
                else {
                    $ReturnValue = foreach ($_vm in $FilterAge) {
                        $DeleteVM = Remove-hvVM -hvURI $hvURI -accessToken $accessToken -VM $_vm.name
                        if ($DeleteVM.ReturnCode -eq 0) {
                            $DeleteVM.Message
                        }
                        else {
                            $DeleteVM.ReturnValue
                        }
                    }
                    return Get-ReturnMessageTemplate -ReturnType Success -Message "All VMs that was older then $($textTimePeriod)have been deleted from $($PoolName)" -ReturnValue $ReturnValue
                }
            }
        }
        else {
            return $GetPoolInfo
            Break
        }
    }
    catch {
        return Get-ReturnMessageTemplate -ReturnType Error -Message "$($PSItem.Exception.Message)" -ReturnValue "$($PSItem.Exception)"
        Break
    }
}
Function Get-hvDataStorePath {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, HelpMessage = "Enter FQDN to one Connection Server")]
        [ValidateNotNullOrEmpty()]
        [string]$hvURI,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, HelpMessage = "Access token for authentication")]
        [ValidateNotNullOrEmpty()]
        [SecureString]$accessToken,
        [Parameter(Mandatory = $true, HelpMessage = "Virtual Center ID")]
        [ValidateNotNullOrEmpty()]
        [string]$vCenterID,
        [Parameter(Mandatory = $true, HelpMessage = "Datastore ID")]
        [ValidateNotNullOrEmpty()]
        [string]$DatastoreID
    )

    try {
        $APICall = Invoke-RestMethod -Uri "https://$($hvURI)/rest/external/v1/datastore-paths?vcenter_id=$($vCenterID)&datastore_id=$($DatastoreID)" -Method Get -Authentication Bearer -Token $accessToken -ContentType "application/json" -StatusCodeVariable "StatusCode" -HttpVersion 3.0
        if ($StatusCode -eq 200) {
            return Get-ReturnMessageTemplate -ReturnType Success -Message "Information about datastore path has been collected." -ReturnValue $APICall
            Break
        }
        else {
            return Get-ReturnMessageTemplate -ReturnType Error -Message "Could not collect information about Datastore Path, StatusCode: $StatusCode"
            Break
        }
    }
    catch {
        return Get-ReturnMessageTemplate -ReturnType Error -Message "$($PSItem.Exception.Message)" -ReturnValue "$($PSItem.Exception)"
        Break    
    }
}
Function Remove-hvVM {
    <#
        .SYNOPSIS
        .DESCRIPTION
        .PARAMETER hvURI
        .PARAMETER accessToken
        .PARAMETER VM
        .PARAMETER VirtualCenterID
        .EXAMPLE
        .LINK
        .NOTES
        Author:         Robin Widmark
        Mail:           robin@widmark.dev
        Website/Blog:   https://widmark.dev
        X:              https://x.com/widmark_robin
        Mastodon:       https://mastodon.social/@rwidmark
		YouTube:		https://www.youtube.com/@rwidmark
        Linkedin:       https://www.linkedin.com/in/rwidmark/
        GitHub:         https://github.com/rwidmark
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, HelpMessage = "Enter FQDN to one Connection Server")]
        [ValidateNotNullOrEmpty()]
        [string]$hvURI,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, HelpMessage = "Access token for authentication")]
        [ValidateNotNullOrEmpty()]
        [SecureString]$accessToken,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, HelpMessage = "Name of the VM")]
        [ValidateNotNullOrEmpty()]
        [string]$VM
    )

    try {

        $VerifyVM = Get-hvVM -hvURI $hvURI -accessToken $accessToken -FilterValue $VM
        if ($VerifyVM.ReturnCode -eq 0) {
            $VMID = $($VerifyVM.ReturnValue.id -as [string])
        }
        else {
            return $VerifyVM
            Break
        }

        $Body = [ordered]@{
            'allow_delete_from_multi_desktop_pools' = $false
            "delete_from_disk"                      = $true
            "force_logoff_session"                  = $true
        }

        $APICall = Invoke-RestMethod -Uri "https://$($hvURI)/rest/inventory/v1/machines/$($VMID)" -Method Delete -Body ($Body | ConvertTO-JSON) -ContentType "application/json" -Authentication Bearer -Token $accessToken -HttpVersion 3.0 -StatusCodeVariable "StatusCode"

        if ($StatusCode -eq 204) {
            return Get-ReturnMessageTemplate -ReturnType Success -Message "VM $($VM) have been deleted from VMWare Horizon, this can take some time."
            Break 
        }
        else {
            return Get-ReturnMessageTemplate -ReturnType Error -Message "Something went wrong when trying to delete VM $($VM), Status Code $($StatusCode)" -ReturnValue $APICall
            Break
        }
    }
    catch {
        return Get-ReturnMessageTemplate -ReturnType Error -Message "$($PSItem.Exception.Message)" -ReturnValue "$($PSItem.Exception)"
        Break
    }
}