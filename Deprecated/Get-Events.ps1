function get-EventViewer {
                Write-Output "List of custom views on the machine"
                Write-Output ""
                Get-ChildItem "C:\ProgramData\Microsoft\Event Viewer\Views" -Filter *.xml | % { select-xml -Path $_.FullName -xpath "//Name" } | Select-Object -ExpandProperty Node | Select-Object -ExpandProperty InnerXml
 
                Write-Output ""
                $view_name = Read-Host "Enter the name of custom view to execute"
 
 
                # Get the file name of the view
                $ViewFile = Get-ChildItem "C:\ProgramData\Microsoft\Event Viewer\Views" -Filter *.xml | where-object { (Select-Xml -Path $_.FullName -xpath "//Name").Node.InnerXml -eq $view_name }
 
                Get-WinEvent -FilterXml ([xml]((Select-Xml -Path $ViewFile.FullName -XPath "//QueryList").node.OuterXml))
}
