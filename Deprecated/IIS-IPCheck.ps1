﻿MachineName = "localhost"
IIsObjectPath = "IIS://" & MachineName & "/w3svc"

WScript.Echo "Checking : " & IISObjectPath

Set IIsObject = GetObject(IIsObjectPath)
for each obj in IISObject
    if (Obj.Class = "IIsWebServer") then
        BindingPath = IIsObjectPath & "/" & Obj.Name

        Set IIsObjectIP = GetObject(BindingPath)
        wScript.Echo BindingPath & " - " & IISObjectIP.ServerComment

        ValueList = IISObjectIP.Get("ServerBindings")
                ValueString = ""
        For ValueIndex = 0 To UBound(ValueList)
            value = ValueList(ValueIndex)
            Values = split(value, ":")
            IP = values(0)
            if (IP = "") then
                IP = "(All Unassigned)"
            end if 
            TCP = values(1)
            if (TCP = "") then
                TCP = "80"
            end if 
            HostHeader = values(2)

            if (HostHeader <> "") then
                    wScript.Echo "    IP = " & IP & " TCP/IP Port = " & TCP & ", HostHeader = " & HostHeader
            else
                    wScript.Echo "    IP = " & IP & " TCP/IP Port = " & TCP 
            end if
                Next                                     
        wScript.Echo ""
        set IISObjectIP = Nothing
    end if
next
set IISObject = Nothing