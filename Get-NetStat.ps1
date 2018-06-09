<#
.SYNOPSIS
    Generate an object oriented NetStat report.
    
.DESCRIPTION
    Generate an object oriented NetStat report.
    
.NOTES
    Author: JBear
#>

param(

    [Parameter(Mandatory=$true)]
    [String[]]$Computername,

    [Parameter(DontShow)]
    [Int]$j = 0,

    [Parameter(DontShow)]
    [Int]$k = 0
)

function Job-NetStat {

    foreach($Computer in $Computername) {

        Write-Progress -Activity "Generating Ports and Protocols Data..." -Status ("Percent Complete:" + "{0:N0}" -f ((($j++) / $Computername.count) * 100) + "%") -CurrentOperation "Processing $($Computer)..." -PercentComplete ((($k++) / $Computername.count) * 100)

        if(!([String]::IsNullOrWhiteSpace($Computer))) {

            if(Test-Connection -ComputerName $Computer -Count 1 -Quiet) {

                $NetStat = Invoke-Command -ComputerName $Computer -ScriptBlock {

                    (NetStat -abo) 
                }

                $NetStat = $NetStat[4..$NetStat.Count] | ConvertFrom-String | Select P2, P3, P4, P5, P6

                $i = [Int]-1

                foreach($Obj in $NetStat) {

                    $i++

                    if($obj.P2 -ccontains "TCP" -or $obj.P2 -ccontains "UDP") {
    
                        if($($NetStat[ $i+1 ]).P2 -ne "TCP" -or $NetStat[ $i+1 ].P2 -ne "UDP") {
        
                            if($($NetStat[ $i+1 ]).P2 -eq "Can") {

                                $ProcInfo = "Not Identifed"
                                $Service = "Not Identifed"
                            }

                            else {

                                if($($NetStat[ $i+1 ]).P2 -notlike "*.exe" -or $($NetStat[ $i+1 ]).P2 -ne "TCP" -or $($NetStat[ $i+1 ]).P2 -ne "UDP") {
                        
                                    if($($NetStat[$i+2]).P2 -ne "TCP" -and $($NetStat[$i+2]).P2 -ne "UDP") {

                                        $ProcInfo = $($NetStat[$i+2]).P2
                                        $service= $($NetStat[$i+1]).P2
                                    }

                                    else {
                        
                                        $ProcInfo = $($NetStat[$i+1]).P2
                                        $Service = "Not Identifed"
                                    }
                                }

                                else {
                        
                                    $ProcInfo = $($NetStat[$i+1]).P2
                                    $Service = "Not Identified"
                                }
                            }
                        }

                        if($Obj.P5 -contains "LISTENING" -or $Obj.P5 -contains "TIME_WAIT" -or $Obj.P5 -contains "CLOSE_WAIT" -or $Obj.P5 -contains "ESTABLISHED" -or $Obj.P5 -eq $null) {
                
                            $State = $Obj.P5
                            $ID = $Obj.P6
                        }

                        else {

                            $State = $null
                            $ID = $Obj.P5
                        }

                        [PSCustomObject] @{

                            Protocol = $Obj.P2
                            LocalAddress = $Obj.P3
                            ForeignAddress = $Obj.P4
                            State = $State
                            PID = $ID
                            Computername = $Computer
                            ProcessName = $ProcInfo
                            ServiceName = $Service
                        }
                    }
                }
            }
        }
    }
}

#Call main function
Job-Netstat | Select Computername, LocalAddress, ForeignAddress, State, PID, ProcessName, ServiceName
