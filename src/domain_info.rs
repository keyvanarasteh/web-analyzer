use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ── WHOIS server database ───────────────────────────────────────────────────

const WHOIS_SERVERS: &[(&str, &str)] = &[
    // Core gTLDs
    ("com", "whois.verisign-grs.com"),
    ("net", "whois.verisign-grs.com"),
    ("org", "whois.pir.org"),
    ("edu", "whois.educause.edu"),
    ("gov", "whois.dotgov.gov"),
    ("mil", "whois.nic.mil"),
    ("int", "whois.iana.org"),
    ("info", "whois.afilias.net"),
    ("biz", "whois.biz"),
    ("name", "whois.nic.name"),
    ("pro", "whois.nic.pro"),
    ("aero", "whois.aero"),
    ("coop", "whois.nic.coop"),
    ("museum", "whois.museum"),
    ("arpa", "whois.iana.org"),
    
    // New Highly Active gTLDs
    ("xyz", "whois.nic.xyz"),
    ("top", "whois.nic.top"),
    ("club", "whois.nic.club"),
    ("vip", "whois.nic.vip"),
    ("app", "whois.nic.google"),
    ("dev", "whois.nic.google"),
    ("shop", "whois.nic.shop"),
    ("store", "whois.nic.store"),
    ("site", "whois.nic.site"),
    ("online", "whois.nic.online"),
    ("tech", "whois.nic.tech"),
    ("ai", "whois.nic.ai"),
    ("io", "whois.nic.io"),
    ("me", "whois.nic.me"),
    ("tv", "whois.nic.tv"),
    ("cc", "whois.nic.cc"),
    ("website", "whois.nic.website"),
    ("space", "whois.nic.space"),
    ("press", "whois.nic.press"),
    ("design", "whois.nic.design"),
    ("agency", "whois.nic.agency"),
    ("photography", "whois.nic.photography"),
    ("email", "whois.nic.email"),
    ("network", "whois.nic.network"),
    ("today", "whois.nic.today"),
    ("icu", "whois.nic.icu"),
    ("wang", "whois.nic.wang"),
    ("win", "whois.nic.win"),
    ("mobi", "whois.nic.mobi"),
    ("asia", "whois.nic.asia"),
    ("tel", "whois.nic.tel"),
    ("cloud", "whois.nic.cloud"),
    ("global", "whois.nic.global"),
    ("host", "whois.nic.host"),
    ("link", "whois.nic.link"),

    // ccTLDs (Country Codes)
    ("ac", "whois.nic.ac"),
    ("ae", "whois.aeda.net.ae"),
    ("am", "whois.amnic.net"),
    ("at", "whois.nic.at"),
    ("au", "whois.auda.org.au"), // covers com.au
    ("be", "whois.dns.be"),
    ("br", "whois.registro.br"), // covers com.br
    ("by", "whois.cctld.by"),
    ("ca", "whois.cira.ca"),
    ("ch", "whois.nic.ch"),
    ("cl", "whois.nic.cl"),
    ("cn", "whois.cnnic.cn"), // covers com.cn
    ("co", "whois.nic.co"),
    ("cz", "whois.nic.cz"),
    ("de", "whois.denic.de"),
    ("dk", "whois.dk-hostmaster.dk"),
    ("dz", "whois.nic.dz"),
    ("es", "whois.nic.es"),
    ("eu", "whois.eu"),
    ("fi", "whois.fi"),
    ("fr", "whois.nic.fr"),
    ("hk", "whois.hkirc.hk"),
    ("hr", "whois.dns.hr"),
    ("hu", "whois.nic.hu"),
    ("id", "whois.pandi.or.id"), // covers co.id
    ("ie", "whois.iedr.ie"),
    ("il", "whois.isoc.org.il"), // covers co.il
    ("in", "whois.registry.in"), // covers co.in
    ("ir", "whois.nic.ir"),
    ("is", "whois.isnic.is"),
    ("it", "whois.nic.it"),
    ("jp", "whois.jprs.jp"), // covers co.jp
    ("kr", "whois.kr"), // covers co.kr
    ("kz", "whois.nic.kz"),
    ("lt", "whois.domreg.lt"),
    ("lu", "whois.dns.lu"),
    ("lv", "whois.nic.lv"),
    ("ma", "whois.registre.ma"),
    ("mx", "whois.mx"), // covers com.mx
    ("nl", "whois.domain-registry.nl"),
    ("no", "whois.norid.no"),
    ("nz", "whois.srs.net.nz"), // covers co.nz
    ("pt", "whois.dns.pt"),
    ("pl", "whois.dns.pl"), // covers com.pl
    ("ro", "whois.rotld.ro"),
    ("rs", "whois.rnids.rs"),
    ("ru", "whois.tcinet.ru"),
    ("se", "whois.iis.se"),
    ("sg", "whois.sgnic.sg"), // covers com.sg
    ("si", "whois.register.si"),
    ("sk", "whois.sk-nic.sk"),
    ("su", "whois.tcinet.ru"),
    ("th", "whois.thnic.co.th"), // covers co.th
    ("tr", "whois.trabis.gov.tr"), // Covers com.tr, org.tr, etc.
    ("tw", "whois.twnic.net.tw"), // covers com.tw
    ("ua", "whois.ua"), // covers com.ua
    ("uk", "whois.nic.uk"), // Covers co.uk, org.uk
    ("us", "whois.nic.us"),
    ("za", "whois.registry.net.za"), // covers co.za
];

/// Common ports for scanning
const COMMON_PORTS: &[(u16, &str)] = &[
    (7, "Echo"), (9, "Discard"), (11, "Systat"), (13, "Daytime"), (17, "QOTD"), (19, "Chargen"),
    (20, "FTP-Data"), (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"), (26, "RSFTP"),
    (37, "Time"), (42, "WINS"), (43, "WHOIS"), (49, "TACACS"), (53, "DNS"), (69, "TFTP"),
    (79, "Finger"), (80, "HTTP"), (81, "HTTP-Alt"), (82, "XFER"), (88, "Kerberos"),
    (106, "POP3PW"), (110, "POP3"), (111, "RPCBind"), (113, "Ident"), (119, "NNTP"),
    (135, "MSRPC"), (139, "NetBIOS-SSN"), (143, "IMAP"), (144, "NeWS"), (161, "SNMP"),
    (179, "BGP"), (199, "SMUX"), (211, "Texas.net"), (212, "ANET"), (222, "RSH-Spam"),
    (254, "ClearCase"), (255, "BGP"), (256, "RAP"), (259, "ESRO-Gen"), (264, "BGMP"),
    (280, "HTTP-Mgmt"), (311, "OSX-Server"), (389, "LDAP"), (407, "Timbuktu"), (427, "SLP"),
    (443, "HTTPS"), (444, "SNPP"), (445, "Microsoft-DS"), (464, "kpasswd"), (465, "SMTPS"),
    (500, "ISAKMP"), (512, "Exec"), (513, "Login"), (514, "Shell"), (515, "Printer"),
    (524, "NCP"), (541, "NetWall"), (543, "klogin"), (544, "kshell"), (545, "tk-remote"),
    (548, "AFP"), (554, "RTSP"), (587, "Submission"), (593, "HTTP-RPC-EPMAP"), (631, "IPP"),
    (636, "LDAPS"), (646, "LDP"), (749, "Kerberos-Admin"), (808, "CCProxy-HTTP"), (873, "Rsync"),
    (902, "VMware-Auth"), (989, "FTPS-Data"), (990, "FTPS"), (992, "Telnet-SSL"), (993, "IMAPS"),
    (995, "POP3S"), (1025, "NFS-or-IIS"), (1026, "LSA"), (1027, "IIS"), (1028, "WinRM"),
    (1080, "SOCKS"), (1099, "RMI-Registry"), (1194, "OpenVPN"), (1433, "MSSQL"),
    (1434, "MSSQL-Mgmt"), (1521, "Oracle"), (1524, "Ingres-Lock"), (1720, "H.323"),
    (1723, "PPTP"), (1883, "MQTT"), (2000, "Cisco-SCCP"), (2049, "NFS"), (2082, "cPanel"),
    (2083, "cPanel-SSL"), (2086, "WHM"), (2087, "WHM-SSL"), (2095, "Webmail"),
    (2096, "Webmail-SSL"), (2181, "ZooKeeper"), (2222, "DirectAdmin"), (2375, "Docker"),
    (2376, "Docker-SSL"), (2601, "Zebra"), (2602, "Rippled"), (2604, "OSPF"), (2605, "BGP"),
    (3128, "Squid"), (3268, "LDAP-GC"), (3269, "LDAPS-GC"), (3306, "MySQL"), (3389, "RDP"),
    (3690, "SVN"), (4000, "Diablo"), (4040, "Chef/Subsonic"), (4242, "Rubrics"),
    (4333, "mSQL"), (4444, "Metasploit-Bind"), (4500, "IPSec-NAT-T"), (4567, "Sinatra"),
    (4899, "Radmin"), (5000, "UPnP"), (5001, "Iperf"), (5002, "Radio"), (5038, "Asterisk"),
    (5432, "PostgreSQL"), (5555, "Freeciv"), (5632, "pcAnywhere"), (5672, "AMQP"),
    (5800, "VNC-HTTP"), (5900, "VNC"), (5901, "VNC-1"), (5938, "TeamViewer"),
    (5984, "CouchDB"), (6000, "X11"), (6379, "Redis"), (6443, "Kubernetes-API"),
    (6543, "MythTV"), (6667, "IRC"), (6881, "BitTorrent"), (7000, "Cassandra-Intra"),
    (7001, "Cassandra-TLS"), (7070, "RealServer"), (7199, "Cassandra-JMX"), (7474, "Neo4j"),
    (8000, "HTTP-Alt"), (8008, "HTTP-Alt"), (8080, "HTTP-Proxy"), (8081, "HTTP-Proxy"),
    (8090, "Atlassian-Confluence"), (8443, "HTTPS-Alt"), (8883, "MQTT-SSL"),
    (8888, "HTTP-Alt"), (9000, "SonarQube/Portainer"), (9042, "Cassandra-CQL"),
    (9090, "Prometheus"), (9092, "Kafka"), (9100, "JetDirect/PromExporter"),
    (9160, "Cassandra-Thrift"), (9200, "Elasticsearch"), (9300, "Elasticsearch-Node"),
    (9443, "Portainer-SSL"), (10000, "Webmin"), (10001, "Webmin-Alt"), (10250, "Kubelet-API"),
    (11211, "Memcached"), (27017, "MongoDB"), (27018, "MongoDB-Shard"), (27019, "MongoDB-Config"),
    (28017, "MongoDB-Web"), (50000, "SAP/DB2"), (50070, "Hadoop-Namenode"), (61616, "ActiveMQ"),
    (8086, "InfluxDB"), (8181, "GlassFish"), (17500, "Dropbox"), (25565, "Minecraft"),
    (27015, "HLDS/Steam"), (30000, "K8s-NodePort")
];

/// Security headers to check
const SECURITY_HEADERS: &[&str] = &[
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "content-security-policy",
];

/// Privacy keywords in WHOIS output
const PRIVACY_KEYWORDS: &[&str] = &[
    "redacted",
    "privacy",
    "gdpr",
    "protected",
    "proxy",
    "private",
];

// ── Data Structures ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainInfoResult {
    pub domain: String,
    pub ipv4: Option<String>,
    pub ipv6: Vec<String>,
    pub all_ipv4: Vec<String>,
    pub reverse_dns: Option<String>,
    pub whois: WhoisInfo,
    pub ssl: SslInfo,
    pub dns: DnsInfo,
    pub open_ports: Vec<String>,
    pub http_status: Option<String>,
    pub web_server: Option<String>,
    pub response_time_ms: Option<f64>,
    pub security: SecurityInfo,
    pub security_score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisInfo {
    pub registrar: String,
    pub creation_date: String,
    pub expiry_date: String,
    pub last_updated: String,
    pub domain_status: Vec<String>,
    pub registrant: String,
    pub privacy_protection: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub name_servers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslInfo {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_until_expiry: Option<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub alternative_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsInfo {
    pub nameservers: Vec<String>,
    pub mx_records: Vec<String>,
    pub txt_records: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spf: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dmarc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityInfo {
    pub https_available: bool,
    pub https_redirect: bool,
    pub security_headers: HashMap<String, String>,
    pub headers_count: usize,
}

// ── Main function ───────────────────────────────────────────────────────────

pub async fn get_domain_info(
    domain: &str,
    progress_tx: Option<tokio::sync::mpsc::Sender<crate::ScanProgress>>,
) -> Result<DomainInfoResult, Box<dyn std::error::Error + Send + Sync>> {
    let clean = clean_domain(domain);

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .user_agent("Mozilla/5.0")
        .build()?;

    if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "Domain Info".into(), percentage: 5.0, message: format!("Initializing scan for {}", clean), status: "Info".into() }).await; }

    // ── IP Resolution ───────────────────────────────────────────────────
    let (mut ipv4, mut all_ipv4, mut ipv6) = (None, vec![], vec![]);
    if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "IP Resolution".into(), percentage: 10.0, message: "Resolving IP addresses...".into(), status: "Info".into() }).await; }

    if let Ok(addrs) = tokio::net::lookup_host(format!("{}:80", clean)).await {
        for addr in addrs {
            match addr.ip() {
                std::net::IpAddr::V4(ip) => {
                    all_ipv4.push(ip.to_string());
                }
                std::net::IpAddr::V6(ip) => {
                    ipv6.push(ip.to_string());
                }
            }
        }
    }
    if !all_ipv4.is_empty() {
        ipv4 = Some(all_ipv4[0].clone());
    }
    if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "IP Resolution".into(), percentage: 15.0, message: "IP Resolution completed".into(), status: "Success".into() }).await; }

    // ── Reverse DNS ─────────────────────────────────────────────────────
    if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "Reverse DNS".into(), percentage: 18.0, message: "Looking up reverse DNS...".into(), status: "Info".into() }).await; }
    let reverse_dns = if let Some(ref ip) = ipv4 {
        reverse_dns_lookup(ip).await
    } else {
        None
    };
    if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "Reverse DNS".into(), percentage: 20.0, message: "Reverse DNS completed".into(), status: "Success".into() }).await; }

    // ── Run concurrent tasks ────────────────────────────────────────────
    let whois_fut = async {
        if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "WHOIS".into(), percentage: 25.0, message: "Querying WHOIS registries...".into(), status: "Info".into() }).await; }
        let res = query_whois(&clean).await;
        if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "WHOIS".into(), percentage: 40.0, message: "WHOIS data retrieved".into(), status: "Success".into() }).await; }
        res
    };
    let ssl_fut = async {
        if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "SSL".into(), percentage: 30.0, message: "Verifying SSL certificates...".into(), status: "Info".into() }).await; }
        let res = check_ssl(&clean).await;
        if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "SSL".into(), percentage: 50.0, message: "SSL certificate validated".into(), status: "Success".into() }).await; }
        res
    };
    let dns_fut = async {
        if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "DNS".into(), percentage: 35.0, message: "Fetching DNS records...".into(), status: "Info".into() }).await; }
        let res = get_dns_records(&clean).await;
        if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "DNS".into(), percentage: 60.0, message: "DNS records retrieved".into(), status: "Success".into() }).await; }
        res
    };
    let ports_fut = async {
        if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "Ports".into(), percentage: 40.0, message: "Scanning common ports...".into(), status: "Info".into() }).await; }
        let res = scan_ports(ipv4.as_deref()).await;
        if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "Ports".into(), percentage: 70.0, message: "Port scanning complete".into(), status: "Success".into() }).await; }
        res
    };
    let http_fut = async {
        if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "HTTP".into(), percentage: 45.0, message: "Checking HTTP status...".into(), status: "Info".into() }).await; }
        let res = check_http_status(&client, &clean).await;
        if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "HTTP".into(), percentage: 80.0, message: "HTTP check complete".into(), status: "Success".into() }).await; }
        res
    };
    let security_fut = async {
        if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "Security".into(), percentage: 50.0, message: "Analyzing security headers...".into(), status: "Info".into() }).await; }
        let res = check_security(&client, &clean).await;
        if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "Security".into(), percentage: 90.0, message: "Security analysis complete".into(), status: "Success".into() }).await; }
        res
    };

    let (whois, ssl, dns, open_ports, http_info, security) = tokio::join!(
        whois_fut,
        ssl_fut,
        dns_fut,
        ports_fut,
        http_fut,
        security_fut
    );

    // ── Security Score ──────────────────────────────────────────────────
    let score = calculate_security_score(&ssl, &dns, &security);

    Ok(DomainInfoResult {
        domain: clean,
        ipv4,
        ipv6,
        all_ipv4,
        reverse_dns,
        whois,
        ssl,
        dns,
        open_ports,
        http_status: http_info.0,
        web_server: http_info.1,
        response_time_ms: http_info.2,
        security,
        security_score: score,
    })
}

// ── Domain cleaning ─────────────────────────────────────────────────────────

fn clean_domain(domain: &str) -> String {
    let d = domain
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .replace("www.", "");
    d.split('/')
        .next()
        .unwrap_or(&d)
        .split(':')
        .next()
        .unwrap_or(&d)
        .to_string()
}

// ── Reverse DNS ─────────────────────────────────────────────────────────────

pub async fn reverse_dns_lookup(ip: &str) -> Option<String> {
    let output = tokio::process::Command::new("dig")
        .args(["+short", "-x", ip])
        .output()
        .await
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text.trim_end_matches('.').to_string())
    }
}

// ── WHOIS via TCP socket ────────────────────────────────────────────────────

fn get_whois_server(domain: &str) -> &'static str {
    let tld = domain.split('.').next_back().unwrap_or("");
    WHOIS_SERVERS
        .iter()
        .find(|(t, _)| *t == tld)
        .map(|(_, s)| *s)
        .unwrap_or("whois.iana.org")
}

async fn query_whois_tcp(domain: &str, server: &str) -> Option<String> {
    let addr = format!("{}:43", server);
    let mut stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&addr))
        .await
        .ok()?
        .ok()?;

    stream
        .write_all(format!("{}\r\n", domain).as_bytes())
        .await
        .ok()?;

    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut buf)).await;

    Some(String::from_utf8_lossy(&buf).to_string())
}

pub async fn query_whois(domain: &str) -> WhoisInfo {
    let mut info = WhoisInfo {
        registrar: "Unknown".into(),
        creation_date: "Unknown".into(),
        expiry_date: "Unknown".into(),
        last_updated: "Unknown".into(),
        domain_status: vec![],
        registrant: "Unknown".into(),
        privacy_protection: "Unknown".into(),
        name_servers: vec![],
    };

    let server = get_whois_server(domain);
    let output = match query_whois_tcp(domain, server).await {
        Some(o) if !o.is_empty() => o,
        _ => return info,
    };

    // Follow referral
    let final_output = if let Some(caps) = Regex::new(r"(?i)Registrar WHOIS Server:\s*(.+)")
        .ok()
        .and_then(|r| r.captures(&output))
    {
        let referral = caps
            .get(1)
            .unwrap()
            .as_str()
            .trim()
            .replace("whois://", "")
            .replace("http://", "")
            .replace("https://", "");
            
        if let Some(ref_out) = query_whois_tcp(domain, &referral).await {
            format!("{}\n---\n{}", output, ref_out)
        } else {
            output
        }
    } else {
        output
    };

    // Parse registrar
    for pat in &[
        r"(?i)Registrar:\s*(.+)",
        r"(?i)Registrar Name:\s*(.+)",
        r"(?i)Registrar Organization:\s*(.+)",
    ] {
        if let Some(m) = Regex::new(pat).ok().and_then(|r| r.captures(&final_output)) {
            info.registrar = m.get(1).unwrap().as_str().trim().to_string();
            break;
        }
    }

    // Parse creation date
    for pat in &[
        r"(?i)Creation Date:\s*(.+)",
        r"(?i)Created Date:\s*(.+)",
        r"(?i)Created:\s*(.+)",
        r"(?i)Registration Time:\s*(.+)",
    ] {
        if let Some(m) = Regex::new(pat).ok().and_then(|r| r.captures(&final_output)) {
            info.creation_date = m
                .get(1)
                .unwrap()
                .as_str()
                .trim()
                .split('\n')
                .next()
                .unwrap_or("")
                .to_string();
            break;
        }
    }

    // Parse expiry date
    for pat in &[
        r"(?i)Registry Expiry Date:\s*(.+)",
        r"(?i)Registrar Registration Expiration Date:\s*(.+)",
        r"(?i)Expir(?:y|ation) Date:\s*(.+)",
        r"(?i)expires:\s*(.+)",
        r"(?i)Expiration Time:\s*(.+)",
    ] {
        if let Some(m) = Regex::new(pat).ok().and_then(|r| r.captures(&final_output)) {
            info.expiry_date = m
                .get(1)
                .unwrap()
                .as_str()
                .trim()
                .split('\n')
                .next()
                .unwrap_or("")
                .to_string();
            break;
        }
    }

    // Parse updated date
    for pat in &[
        r"(?i)Updated Date:\s*(.+)",
        r"(?i)Last Updated:\s*(.+)",
        r"(?i)last-update:\s*(.+)",
        r"(?i)Modified Date:\s*(.+)",
    ] {
        if let Some(m) = Regex::new(pat).ok().and_then(|r| r.captures(&final_output)) {
            info.last_updated = m
                .get(1)
                .unwrap()
                .as_str()
                .trim()
                .split('\n')
                .next()
                .unwrap_or("")
                .to_string();
            break;
        }
    }

    // Parse domain status
    if let Ok(rx) = Regex::new(r"(?i)(?:Domain )?Status:\s*(.+)") {
        info.domain_status = rx
            .captures_iter(&final_output)
            .filter_map(|c| {
                c.get(1).map(|m| {
                    m.as_str()
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .to_string()
                })
            })
            .filter(|s| !s.is_empty())
            .take(3)
            .collect();
    }
    if info.domain_status.is_empty() {
        info.domain_status.push("Unknown".into());
    }

    // Parse registrant
    for pat in &[
        r"(?i)Registrant Name:\s*(.+)",
        r"(?i)Registrant:\s*(.+)",
        r"(?i)Registrant Organization:\s*(.+)",
    ] {
        if let Some(m) = Regex::new(pat).ok().and_then(|r| r.captures(&final_output)) {
            let val = m
                .get(1)
                .unwrap()
                .as_str()
                .trim()
                .split('\n')
                .next()
                .unwrap_or("")
                .to_string();
            if !val.is_empty() {
                info.registrant = val;
                break;
            }
        }
    }

    // Privacy protection
    let lower = final_output.to_lowercase();
    info.privacy_protection = if PRIVACY_KEYWORDS.iter().any(|k| lower.contains(k)) {
        "Active".into()
    } else {
        "Inactive".into()
    };

    // Name servers
    if let Ok(rx) = Regex::new(r"(?i)Name Server:\s*(.+)") {
        info.name_servers = rx
            .captures_iter(&final_output)
            .filter_map(|c| c.get(1).map(|m| m.as_str().trim().to_lowercase()))
            .take(4)
            .collect();
    }

    info
}

// ── SSL Certificate ─────────────────────────────────────────────────────────

pub async fn check_ssl(domain: &str) -> SslInfo {
    // Use openssl s_client to get certificate info
    let output = match tokio::process::Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &format!("{}:443", domain),
            "-servername",
            domain,
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => {
            return SslInfo {
                status: "Error".into(),
                issued_to: None,
                issuer: None,
                protocol_version: None,
                expiry_date: None,
                days_until_expiry: None,
                alternative_names: vec![],
            }
        }
    };

    if output.contains("CONNECTED") {
        let mut ssl = SslInfo {
            status: "Valid".into(),
            issued_to: None,
            issuer: None,
            protocol_version: None,
            expiry_date: None,
            days_until_expiry: None,
            alternative_names: vec![],
        };

        // Extract subject CN
        if let Some(m) = Regex::new(r"subject=.*?CN\s*=\s*([^\n/,]+)")
            .ok()
            .and_then(|r| r.captures(&output))
        {
            ssl.issued_to = Some(m.get(1).unwrap().as_str().trim().to_string());
        }

        // Extract issuer CN
        if let Some(m) = Regex::new(r"issuer=.*?CN\s*=\s*([^\n/,]+)")
            .ok()
            .and_then(|r| r.captures(&output))
        {
            ssl.issuer = Some(m.get(1).unwrap().as_str().trim().to_string());
        }

        // Extract protocol
        if let Some(m) = Regex::new(r"Protocol\s*:\s*(.+)")
            .ok()
            .and_then(|r| r.captures(&output))
        {
            ssl.protocol_version = Some(m.get(1).unwrap().as_str().trim().to_string());
        }

        // Get dates via openssl x509
        if let Ok(cert_output) = tokio::process::Command::new("sh")
            .args(["-c", &format!("echo | openssl s_client -connect {}:443 -servername {} 2>/dev/null | openssl x509 -noout -dates -subject -ext subjectAltName 2>/dev/null", domain, domain)])
            .output()
            .await
        {
            let cert_text = String::from_utf8_lossy(&cert_output.stdout);

            if let Some(m) = Regex::new(r"notAfter=(.+)").ok().and_then(|r| r.captures(&cert_text)) {
                let expiry_str = m.get(1).unwrap().as_str().trim().to_string();
                ssl.expiry_date = Some(expiry_str.clone());

                // Compute days_until_expiry from parsed date
                // OpenSSL format: "Jun 15 12:00:00 2025 GMT" or "Jun  5 12:00:00 2025 GMT"
                let clean_expiry = expiry_str.trim_end_matches(" GMT").trim_end_matches(" UTC");
                
                // Try parsing with space-padded day (%e) or zero-padded day (%d)
                let parsed_date = chrono::NaiveDateTime::parse_from_str(clean_expiry, "%b %e %H:%M:%S %Y")
                    .or_else(|_| chrono::NaiveDateTime::parse_from_str(clean_expiry, "%b %d %H:%M:%S %Y"));
                    
                if let Ok(expiry) = parsed_date {
                    let now = chrono::Utc::now().naive_utc();
                    ssl.days_until_expiry = Some((expiry - now).num_days());
                }
            }

            // Extract SANs
            if let Some(san_section) = cert_text.split("X509v3 Subject Alternative Name:").nth(1) {
                let names: Vec<String> = Regex::new(r"DNS:([^,\s]+)")
                    .ok()
                    .map(|r| r.captures_iter(san_section).filter_map(|c| c.get(1).map(|m| m.as_str().to_string())).take(5).collect())
                    .unwrap_or_default();
                ssl.alternative_names = names;
            }
        }

        ssl
    } else {
        SslInfo {
            status: "HTTPS not available".into(),
            issued_to: None,
            issuer: None,
            protocol_version: None,
            expiry_date: None,
            days_until_expiry: None,
            alternative_names: vec![],
        }
    }
}

// ── DNS Records via dig ─────────────────────────────────────────────────────

async fn dig_query(domain: &str, rtype: &str) -> Vec<String> {
    tokio::process::Command::new("dig")
        .args(["+short", rtype, domain])
        .output()
        .await
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|t| {
            t.lines()
                .filter(|l| !l.trim().is_empty() && !l.starts_with(';'))
                .map(|l| l.trim().to_string())
                .collect()
        })
        .unwrap_or_default()
}

pub async fn get_dns_records(domain: &str) -> DnsInfo {
    let (ns, mx, txt) = tokio::join!(
        dig_query(domain, "NS"),
        dig_query(domain, "MX"),
        dig_query(domain, "TXT"),
    );

    let spf = txt.iter().find(|t| t.contains("v=spf1")).cloned();
    let dmarc_records = dig_query(&format!("_dmarc.{}", domain), "TXT").await;
    let dmarc = dmarc_records.into_iter().find(|t| t.contains("v=DMARC1"));

    DnsInfo {
        nameservers: ns,
        mx_records: mx,
        txt_records: txt,
        spf,
        dmarc,
    }
}

// ── Port Scanning ───────────────────────────────────────────────────────────

pub async fn scan_ports(ip: Option<&str>) -> Vec<String> {
    let ip = match ip {
        Some(ip) => ip,
        None => return vec![],
    };

    let mut results = Vec::new();
    let mut handles = Vec::new();

    for &(port, service) in COMMON_PORTS {
        let addr = format!("{}:{}", ip, port);
        handles.push(tokio::spawn(async move {
            match tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(&addr)).await {
                Ok(Ok(_)) => Some(format!("{}/{}", port, service)),
                _ => None,
            }
        }));
    }

    for handle in handles {
        if let Ok(Some(port_str)) = handle.await {
            results.push(port_str);
        }
    }

    results.sort();
    results
}

// ── HTTP Status Check ───────────────────────────────────────────────────────

pub async fn check_http_status(
    client: &Client,
    domain: &str,
) -> (Option<String>, Option<String>, Option<f64>) {
    for proto in &["https", "http"] {
        let url = format!("{}://{}", proto, domain);
        let start = Instant::now();
        match client.get(&url).send().await {
            Ok(resp) => {
                let elapsed = start.elapsed().as_secs_f64() * 1000.0;
                let status_str = format!("{} - {}", resp.status().as_u16(), proto.to_uppercase());
                let server = resp
                    .headers()
                    .get("server")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                return (
                    Some(status_str),
                    server,
                    Some((elapsed * 100.0).round() / 100.0),
                );
            }
            Err(_) => continue,
        }
    }
    (None, None, None)
}

// ── Security Check ──────────────────────────────────────────────────────────

pub async fn check_security(client: &Client, domain: &str) -> SecurityInfo {
    let mut sec = SecurityInfo {
        https_available: false,
        https_redirect: false,
        security_headers: HashMap::new(),
        headers_count: 0,
    };

    // HTTPS + security headers
    if let Ok(resp) = client.get(format!("https://{}", domain)).send().await {
        sec.https_available = true;
        for header in SECURITY_HEADERS {
            if let Some(val) = resp.headers().get(*header) {
                if let Ok(v) = val.to_str() {
                    sec.security_headers
                        .insert(header.to_string(), v.to_string());
                    sec.headers_count += 1;
                }
            }
        }
    }

    // HTTP → HTTPS redirect
    if let Ok(resp) = client.get(format!("http://{}", domain)).send().await {
        let final_url = resp.url().to_string();
        if final_url.starts_with("https://") {
            sec.https_redirect = true;
        }
    }

    sec
}

// ── Security Score (0-100) ──────────────────────────────────────────────────

pub fn calculate_security_score(ssl: &SslInfo, dns: &DnsInfo, security: &SecurityInfo) -> u32 {
    let mut score: u32 = 0;

    // HTTPS available (+30)
    if security.https_available {
        score += 30;
    }

    // HTTPS redirect (+10)
    if security.https_redirect {
        score += 10;
    }

    // SSL valid (+20)
    if ssl.status == "Valid" {
        score += 20;
    }

    // Security headers (up to +20, 4 points each)
    score += (security.headers_count as u32 * 4).min(20);

    // SPF record (+10)
    if dns.spf.is_some() {
        score += 10;
    }

    // DMARC record (+10)
    if dns.dmarc.is_some() {
        score += 10;
    }

    score
}
