//! Embedded wordlists
//!
//! Built-in common password lists for quick cracking without external files.

/// Common password lists embedded in the binary
pub struct EmbeddedWordlists;

impl EmbeddedWordlists {
    /// Top 100 most common passwords
    pub fn top_100() -> Vec<&'static str> {
        vec![
            "123456", "password", "12345678", "qwerty", "123456789",
            "12345", "1234", "111111", "1234567", "dragon",
            "123123", "baseball", "abc123", "football", "monkey",
            "letmein", "shadow", "master", "666666", "qwertyuiop",
            "123321", "mustang", "1234567890", "michael", "654321",
            "superman", "1qaz2wsx", "7777777", "fuckyou", "121212",
            "000000", "qazwsx", "123qwe", "killer", "trustno1",
            "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter",
            "buster", "soccer", "harley", "batman", "andrew",
            "tigger", "sunshine", "iloveyou", "2000", "charlie",
            "robert", "thomas", "hockey", "ranger", "daniel",
            "starwars", "klaster", "112233", "george", "computer",
            "michelle", "jessica", "pepper", "1111", "zxcvbn",
            "555555", "11111111", "131313", "freedom", "777777",
            "pass", "maggie", "159753", "aaaaaa", "ginger",
            "princess", "joshua", "cheese", "amanda", "summer",
            "love", "ashley", "nicole", "chelsea", "biteme",
            "matthew", "access", "yankees", "987654321", "dallas",
            "austin", "thunder", "taylor", "matrix", "mobilemail",
            "mom", "monitor", "monitoring", "montana", "moon",
        ]
    }

    /// Top 1000 most common passwords
    pub fn top_1000() -> Vec<&'static str> {
        let mut list = Self::top_100().to_vec();
        list.extend(vec![
            // 101-200
            "moscow", "master1", "diamond", "1q2w3e4r", "hello",
            "admin", "password1", "welcome", "test", "test1",
            "testing", "pass123", "qwerty1", "qwerty123", "abcd1234",
            "password123", "admin123", "root", "toor", "alpine",
            "changeme", "default", "letmein1", "secret", "login",
            "passw0rd", "pa55word", "p@ssw0rd", "P@ssw0rd", "Password1",
            "Password123", "Admin123", "Welcome1", "Welcome123", "Test123",
            "Qwerty123", "Asdf1234", "Zxcv1234", "1234qwer", "qwer1234",
            "1q2w3e", "q1w2e3", "q1w2e3r4", "1qaz", "2wsx",
            "3edc", "4rfv", "5tgb", "6yhn", "7ujm",
            // 201-300
            "8ik", "9ol", "0p", "qazwsxedc", "qweasdzxc",
            "1qazxsw2", "zaq1xsw2", "!qaz2wsx", "qaz123", "wsx234",
            "abc", "abcd", "abcde", "abcdef", "abcdefg",
            "1234abcd", "abcd123", "test123", "test1234", "user",
            "user1", "user123", "guest", "guest123", "demo",
            "demo123", "support", "support1", "help", "temp",
            "temp123", "backup", "service", "system", "server",
            "network", "security", "secure", "private", "public",
            "database", "oracle", "mysql", "postgres", "sql",
            "ftp", "sftp", "ssh", "mail", "email",
            // 301-400
            "web", "www", "http", "https", "proxy",
            "firewall", "router", "switch", "cisco", "juniper",
            "linksys", "netgear", "dlink", "tplink", "asus",
            "apple", "samsung", "nokia", "sony", "lg",
            "hp", "dell", "lenovo", "intel", "amd",
            "nvidia", "microsoft", "windows", "linux", "unix",
            "ubuntu", "debian", "centos", "redhat", "fedora",
            "android", "ios", "mobile", "phone", "tablet",
            "laptop", "desktop", "pc", "mac", "imac",
            "macbook", "iphone", "ipad", "ipod", "itunes",
            // 401-500 (common words)
            "spring", "summer", "autumn", "fall", "winter",
            "january", "february", "march", "april", "may",
            "june", "july", "august", "september", "october",
            "november", "december", "monday", "tuesday", "wednesday",
            "thursday", "friday", "saturday", "sunday", "today",
            "yesterday", "tomorrow", "morning", "afternoon", "evening",
            "night", "day", "week", "month", "year",
            "red", "blue", "green", "yellow", "orange",
            "purple", "pink", "black", "white", "gray",
            "grey", "brown", "gold", "silver", "bronze",
            // 501-600 (names)
            "james", "john", "david", "william", "richard",
            "joseph", "charles", "christopher", "anthony", "mark",
            "steven", "paul", "kevin", "brian", "timothy",
            "ronald", "jason", "jeffrey", "ryan", "gary",
            "mary", "patricia", "elizabeth", "barbara", "jennifer",
            "linda", "susan", "margaret", "dorothy", "sarah",
            "karen", "nancy", "betty", "helen", "sandra",
            "donna", "emily", "carol", "ruth", "sharon",
            "michelle", "laura", "kimberly", "deborah", "stephanie",
            "rebecca", "sharon", "cynthia", "kathleen", "amy",
            // 601-700 (sports/teams)
            "baseball", "basketball", "football", "soccer", "hockey",
            "tennis", "golf", "boxing", "wrestling", "swimming",
            "running", "cycling", "skiing", "snowboard", "surfing",
            "yankees", "redsox", "cubs", "dodgers", "giants",
            "lakers", "celtics", "bulls", "heat", "warriors",
            "cowboys", "patriots", "packers", "steelers", "eagles",
            "chelsea", "arsenal", "liverpool", "manchester", "barcelona",
            "realmadrid", "juventus", "bayern", "psg", "inter",
            "ferrari", "lamborghini", "porsche", "bmw", "mercedes",
            "audi", "honda", "toyota", "ford", "chevy",
            // 701-800 (keyboard patterns)
            "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890",
            "qweasd", "asdzxc", "qazwsxedc", "1q2w3e4r5t",
            "zaq12wsx", "xsw23edc", "cde34rfv", "vfr45tgb",
            "bgt56yhn", "nhy67ujm", "mju78ik", "ik89ol",
            "poiuytrewq", "lkjhgfdsa", "mnbvcxz", "0987654321",
            "asdqwe123", "zxcasd123", "qweasd123", "qwerty12",
            "asdfgh12", "zxcvbn12", "qwerty1234", "asdfgh1234",
            "zxcvbn1234", "qaz123wsx", "wsx123edc", "edc123rfv",
            "123qweasd", "123asdzxc", "456qweasd", "789qweasd",
            "qweasd456", "qweasd789", "asd123fgh", "zxc123vbn",
            // 801-900 (with special chars)
            "password!", "password!!", "password1!", "password@",
            "password#", "password$", "password123!", "admin!",
            "admin123!", "welcome!", "welcome1!", "test!",
            "test123!", "qwerty!", "qwerty123!", "123456!",
            "123456789!", "abc123!", "letmein!", "monkey!",
            "dragon!", "master!", "sunshine!", "princess!",
            "P@ssword", "P@ssword1", "P@ssword123", "p@ss",
            "p@ssw0rd!", "P@ssw0rd!", "P@$$w0rd", "p@$$",
            "!@#$%", "!@#$%^", "!@#$%^&", "!@#$%^&*",
            "qwe!@#", "asd!@#", "zxc!@#", "123!@#",
            // 901-1000 (years and dates)
            "2020", "2021", "2022", "2023", "2024",
            "2025", "2019", "2018", "2017", "2016",
            "2015", "2010", "2000", "1999", "1990",
            "1980", "1970", "0101", "0102", "0103",
            "0104", "0105", "0106", "0107", "0108",
            "0109", "0110", "0111", "0112", "0113",
            "0114", "0115", "0116", "0117", "0118",
            "0119", "0120", "0121", "0122", "0123",
            "0124", "0125", "0126", "0127", "0128",
            "0129", "0130", "0131", "password2020",
        ]);
        list
    }

    /// Common default credentials (username:password format)
    pub fn default_credentials() -> Vec<(&'static str, &'static str)> {
        vec![
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "admin123"),
            ("admin", "123456"),
            ("admin", ""),
            ("administrator", "administrator"),
            ("administrator", "password"),
            ("root", "root"),
            ("root", "toor"),
            ("root", "password"),
            ("root", "123456"),
            ("root", "alpine"),
            ("user", "user"),
            ("user", "password"),
            ("guest", "guest"),
            ("guest", "password"),
            ("test", "test"),
            ("test", "test123"),
            ("demo", "demo"),
            ("oracle", "oracle"),
            ("postgres", "postgres"),
            ("mysql", "mysql"),
            ("tomcat", "tomcat"),
            ("manager", "manager"),
            ("cisco", "cisco"),
            ("admin", "cisco"),
            ("admin", "default"),
            ("support", "support"),
            ("operator", "operator"),
            ("ftp", "ftp"),
            ("anonymous", ""),
            ("anonymous", "anonymous"),
            ("pi", "raspberry"),
            ("ubuntu", "ubuntu"),
            ("vagrant", "vagrant"),
            ("default", "default"),
            ("service", "service"),
            ("www-data", "www-data"),
            ("nagios", "nagios"),
            ("zabbix", "zabbix"),
        ]
    }

    /// Common WiFi passwords
    pub fn wifi_passwords() -> Vec<&'static str> {
        vec![
            "password", "12345678", "123456789", "1234567890",
            "password1", "password123", "qwertyuiop", "letmein",
            "welcome", "abc12345", "trustno1", "iloveyou",
            "sunshine", "princess", "football", "baseball",
            "dragon", "monkey", "shadow", "master",
            "qwerty123", "1q2w3e4r", "welcome1", "login",
            "starwars", "whatever", "passw0rd", "zaq1zaq1",
            "qazwsx", "computer", "internet", "wireless",
            "network", "admin123", "wifi1234", "wifipass",
            "guest123", "default1", "changeme", "11111111",
            "00000000", "88888888", "homewifi", "mywifi",
        ]
    }

    /// Leaked password patterns
    pub fn leaked_patterns() -> Vec<&'static str> {
        vec![
            // RockYou patterns
            "123456", "12345", "123456789", "password", "iloveyou",
            "princess", "1234567", "rockyou", "12345678", "abc123",
            // LinkedIn patterns
            "linkedin", "linked", "work2012", "job123",
            // Adobe patterns
            "adobe123", "photoshop", "123adobe", "macromedia",
            // MySpace patterns
            "myspace1", "myspace", "blink182", "greenday",
        ]
    }

    /// Number sequences
    pub fn number_sequences() -> Vec<&'static str> {
        vec![
            "0", "1", "12", "123", "1234", "12345", "123456",
            "1234567", "12345678", "123456789", "1234567890",
            "0123456789", "9876543210", "0000", "1111", "2222",
            "3333", "4444", "5555", "6666", "7777", "8888", "9999",
            "00000", "11111", "00000000", "11111111", "12121212",
            "123123", "321321", "111222", "222333", "333444",
            "123321", "112233", "332211", "121212", "131313",
            "141414", "151515", "161616", "171717", "181818",
            "191919", "202020", "212121", "696969", "999999",
        ]
    }

    /// Common IT/tech passwords
    pub fn tech_passwords() -> Vec<&'static str> {
        vec![
            "admin", "root", "password", "pass", "test",
            "guest", "master", "changeme", "default", "login",
            "sysadmin", "superuser", "administrator", "operator",
            "backup", "oracle", "mysql", "postgres", "database",
            "server", "network", "security", "firewall", "cisco",
            "juniper", "linux", "unix", "windows", "vmware",
            "docker", "kubernetes", "aws", "azure", "cloud",
            "devops", "jenkins", "ansible", "terraform", "git",
        ]
    }

    /// Get all embedded passwords as a single list
    pub fn all() -> Vec<&'static str> {
        let mut all = Self::top_1000();
        all.extend(Self::wifi_passwords());
        all.extend(Self::number_sequences());
        all.extend(Self::tech_passwords());
        all.extend(Self::leaked_patterns());
        // Deduplicate
        all.sort();
        all.dedup();
        all
    }

    /// Get total count of embedded passwords
    pub fn total_count() -> usize {
        Self::all().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_top_100_count() {
        assert_eq!(EmbeddedWordlists::top_100().len(), 100);
    }

    #[test]
    fn test_top_100_contains_common() {
        let list = EmbeddedWordlists::top_100();
        assert!(list.contains(&"password"));
        assert!(list.contains(&"123456"));
        assert!(list.contains(&"qwerty"));
    }

    #[test]
    fn test_default_credentials() {
        let creds = EmbeddedWordlists::default_credentials();
        assert!(creds.contains(&("admin", "admin")));
        assert!(creds.contains(&("root", "root")));
    }

    #[test]
    fn test_all_deduplicated() {
        let all = EmbeddedWordlists::all();
        let mut sorted = all.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(all.len(), sorted.len());
    }
}
