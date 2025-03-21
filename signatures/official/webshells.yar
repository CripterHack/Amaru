/*
 * Amaru Official Webshell Detection Rules
 * Description: Rules for detecting common web shells
 * Author: Amaru Contributors
 * License: GPL-2.0
 */

rule WebShell_PHP_Generic {
    meta:
        description = "Detects generic PHP webshell indicators"
        author = "Amaru Project"
        reference = "https://www.virustotal.com/"
        confidence = "medium"
        severity = "high"
    
    strings:
        $func1 = "eval(" nocase wide ascii
        $func2 = "exec(" nocase wide ascii
        $func3 = "passthru(" nocase wide ascii
        $func4 = "system(" nocase wide ascii
        $func5 = "shell_exec(" nocase wide ascii
        $func6 = "popen(" nocase wide ascii
        $func7 = "proc_open(" nocase wide ascii
        $func8 = "pcntl_exec(" nocase wide ascii
        $func9 = "base64_decode(" nocase wide ascii
        $func10 = "assert(" nocase wide ascii
        
        $param1 = "$_GET" nocase wide ascii
        $param2 = "$_POST" nocase wide ascii
        $param3 = "$_REQUEST" nocase wide ascii
        $param4 = "$_COOKIE" nocase wide ascii
        
        $cmd1 = "cmd" nocase wide ascii
        $cmd2 = "command" nocase wide ascii
        $cmd3 = "exec" nocase wide ascii
        $cmd4 = "shell" nocase wide ascii
        $cmd5 = "c" nocase wide ascii
        
        $sus1 = "password" nocase wide ascii
        $sus2 = "login" nocase wide ascii
        $sus3 = "shell" nocase wide ascii
        $sus4 = "upload" nocase wide ascii
        $sus5 = "backdoor" nocase wide ascii
        
    condition:
        (uint32(0) == 0x68703F3C or uint32(0) == 0x7068703C) and // PHP header
        filesize < 1MB and 
        ((2 of ($func*) and 1 of ($param*) and 1 of ($cmd*)) or
         (3 of ($func*) and 1 of ($sus*)) or
         (1 of ($func*) and 2 of ($param*) and 1 of ($cmd*) and 1 of ($sus*)))
}

rule WebShell_ASP_Generic {
    meta:
        description = "Detects generic ASP webshell indicators"
        author = "Amaru Project"
        reference = "https://www.virustotal.com/"
        confidence = "medium"
        severity = "high"
    
    strings:
        $func1 = "Response.Write" nocase wide ascii
        $func2 = "CreateObject" nocase wide ascii
        $func3 = "WScript.Shell" nocase wide ascii
        $func4 = "Shell.Application" nocase wide ascii
        $func5 = "Scripting.FileSystemObject" nocase wide ascii
        $func6 = "ADODB.Connection" nocase wide ascii
        $func7 = "ADODB.Stream" nocase wide ascii
        $func8 = "Process" nocase wide ascii
        $func9 = "eval" nocase wide ascii
        $func10 = "Execute" nocase wide ascii
        
        $param1 = "Request.Form" nocase wide ascii
        $param2 = "Request.QueryString" nocase wide ascii
        $param3 = "Request.Cookies" nocase wide ascii
        $param4 = "Request" nocase wide ascii
        
        $cmd1 = "cmd.exe" nocase wide ascii
        $cmd2 = "cmd /c" nocase wide ascii
        $cmd3 = "powershell" nocase wide ascii
        $cmd4 = "run" nocase wide ascii
        $cmd5 = "exec" nocase wide ascii
        
        $sus1 = "password" nocase wide ascii
        $sus2 = "login" nocase wide ascii
        $sus3 = "shell" nocase wide ascii
        $sus4 = "upload" nocase wide ascii
        $sus5 = "backdoor" nocase wide ascii
        
    condition:
        (uint16(0) == 0x253C or uint16(0) == 0x2540) and // ASP header
        filesize < 1MB and 
        ((2 of ($func*) and 1 of ($param*) and 1 of ($cmd*)) or
         (3 of ($func*) and 1 of ($sus*)) or
         (1 of ($func*) and 2 of ($param*) and 1 of ($cmd*) and 1 of ($sus*)))
}

rule WebShell_JSP_Generic {
    meta:
        description = "Detects generic JSP webshell indicators"
        author = "Amaru Project"
        reference = "https://www.virustotal.com/"
        confidence = "medium"
        severity = "high"
    
    strings:
        $func1 = "Runtime.getRuntime" nocase wide ascii
        $func2 = "ProcessBuilder" nocase wide ascii
        $func3 = "exec(" nocase wide ascii
        $func4 = "getOutputStream" nocase wide ascii
        $func5 = "getInputStream" nocase wide ascii
        $func6 = "getErrorStream" nocase wide ascii
        $func7 = "executeQuery" nocase wide ascii
        $func8 = "createStatement" nocase wide ascii
        
        $param1 = "request.getParameter" nocase wide ascii
        $param2 = "request.getHeader" nocase wide ascii
        $param3 = "request.getCookie" nocase wide ascii
        $param4 = "request.getQueryString" nocase wide ascii
        
        $cmd1 = "cmd.exe" nocase wide ascii
        $cmd2 = "/bin/sh" nocase wide ascii
        $cmd3 = "/bin/bash" nocase wide ascii
        $cmd4 = "command" nocase wide ascii
        $cmd5 = "cmd" nocase wide ascii
        
        $sus1 = "password" nocase wide ascii
        $sus2 = "login" nocase wide ascii
        $sus3 = "shell" nocase wide ascii
        $sus4 = "upload" nocase wide ascii
        $sus5 = "backdoor" nocase wide ascii
        
    condition:
        (uint32(0) == 0x736A3C25 or uint32(0) == 0x7073253C) and // JSP header
        filesize < 1MB and 
        ((2 of ($func*) and 1 of ($param*) and 1 of ($cmd*)) or
         (3 of ($func*) and 1 of ($sus*)) or
         (1 of ($func*) and 2 of ($param*) and 1 of ($cmd*) and 1 of ($sus*)))
}

rule WebShell_China_Chopper {
    meta:
        description = "Detects China Chopper webshell"
        author = "Amaru Project"
        reference = "https://www.us-cert.gov/ncas/alerts/TA15-314A"
        confidence = "high"
        severity = "high"
    
    strings:
        $asp = "<%eval request" nocase wide ascii
        $aspx = "<%@ Page Language=\"Jscript\"%><%eval" nocase wide ascii
        $php = "<?php @eval($_POST" nocase wide ascii
        $php2 = "<?php @eval($" nocase wide ascii
        $chopper1 = "z0" nocase wide ascii
        $chopper2 = "z1" nocase wide ascii
        $chopper3 = "z2" nocase wide ascii
        $chopper4 = "z3" nocase wide ascii
        
    condition:
        filesize < 10KB and 
        (any of ($asp, $aspx, $php, $php2) or
         (2 of ($chopper*) and (1 of ($asp, $aspx, $php, $php2))))
} 