use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT, AUTHORIZATION, ACCEPT};
use serde::Deserialize;
use std::time::Duration;
use tokio::time::sleep;
use regex::Regex;

#[derive(Deserialize, Debug)]
pub struct SearchResponse {
    pub total_count: u32,
    pub items: Vec<SearchItem>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SearchItem {
    pub name: String,
    pub path: String,
    pub repository: Repository,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Repository {
    pub full_name: String,
}

#[derive(Debug, Clone)]
pub struct LeakResult {
    pub secret_type: String,
    pub repo: String,
    pub file_path: String,
    pub matched_content: String,
}

pub struct RepoScanner {
    client: reqwest::Client,
    regex_signatures: Vec<(&'static str, Regex)>,
}

impl RepoScanner {
    pub fn new(github_token: &str) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static("SecOps-Scanner/3.0"));
        headers.insert(ACCEPT, HeaderValue::from_static("application/vnd.github+json"));
        headers.insert("X-GitHub-Api-Version", HeaderValue::from_static("2022-11-28"));
        
        // Terminalden gelen çift tırnak (") ve tek tırnak (') işaretlerini tamamen temizler
        let clean_token = github_token.trim().trim_matches('"').trim_matches('\'');
        let auth_header_value = format!("Bearer {}", clean_token);
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_header_value).unwrap());

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap();

        let signatures = vec![
            ("AWS Access Key", Regex::new(r"AKIA[0-9A-Z]{16}").unwrap()),
            ("Slack OAuth Token", Regex::new(r"xox[baprs]-[0-9a-zA-Z]{10,48}").unwrap()),
            ("GitHub Personal Token", Regex::new(r"ghp_[a-zA-Z0-9]{36}").unwrap()),
            ("Google API Key", Regex::new(r"AIza[yA-Z0-9_-]{35}").unwrap()),
            ("Private Key File", Regex::new(r"-----BEGIN [A-Z]+ PRIVATE KEY-----").unwrap()),
            ("Database URL Leak", Regex::new(r"postgresql://|mongodb://|mysql://").unwrap()),
        ];

        Self { client, regex_signatures: signatures }
    }

    fn generate_global_dorks(&self, target_user: &str) -> Vec<String> {
        vec![
            format!("user:{} \"AKIA\"", target_user),
            format!("user:{} \"ghp_\"", target_user),
            format!("user:{} \"password=\"", target_user),
            format!("user:{} \"DATABASE_URL\"", target_user),
            format!("user:{} filename:.env", target_user),
        ]
    }

    async fn execute_search_with_retry(&self, query: &str) -> Option<SearchResponse> {
        let url = "https://api.github.com/search/code";
        let mut current_delay = Duration::from_secs(3);

        for attempt in 1..=3 {
            let res = self.client.get(url).query(&[("q", query)]).send().await;

            if let Ok(resp) = res {
                if resp.status() == reqwest::StatusCode::OK {
                    return resp.json::<SearchResponse>().await.ok();
                } else if resp.status() == reqwest::StatusCode::FORBIDDEN || resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                    sleep(current_delay).await;
                    current_delay *= 2;
                }
            }
        }
        None
    }

    async fn fetch_raw_file(&self, repo: &str, path: &str) -> Option<String> {
        let branches = vec!["main", "master"];
        for branch in branches {
            let raw_url = format!("https://raw.githubusercontent.com/{}/{}/{}", repo, branch, path);
            if let Ok(resp) = self.client.get(&raw_url).send().await {
                if resp.status().is_success() {
                    return resp.text().await.ok();
                }
            }
        }
        None
    }

    fn analyze_content(&self, content: &str, repo: &str, path: &str) -> Vec<LeakResult> {
        let mut local_leaks = Vec::new();
        for (secret_name, regex_engine) in &self.regex_signatures {
            for mat in regex_engine.find_iter(content) {
                local_leaks.push(LeakResult {
                    secret_type: secret_name.to_string(),
                    repo: repo.to_string(),
                    file_path: path.to_string(),
                    matched_content: mat.as_str().to_string(),
                });
            }
        }
        local_leaks
    }

    async fn get_user_repositories(&self, target_user: &str) -> Vec<String> {
        let url = format!("https://api.github.com/users/{}/repos", target_user);
        let mut repo_list = Vec::new();

        #[derive(Deserialize)]
        struct RepoInfo { name: String }

        if let Ok(resp) = self.client.get(&url).send().await {
            if let Ok(repos) = resp.json::<Vec<RepoInfo>>().await {
                for r in repos {
                    repo_list.push(r.name);
                }
            }
        }
        repo_list
    }

    pub async fn run(&self, target_user: &str) -> Vec<LeakResult> {
        let mut all_leaks = Vec::new();
        
        println!("[*] AŞAMA 1: Global İndeks Araması Başlatılıyor...");
        let dorks = self.generate_global_dorks(target_user);

        for dork in dorks {
            if let Some(search_result) = self.execute_search_with_retry(&dork).await {
                for item in search_result.items {
                    if let Some(file_content) = self.fetch_raw_file(&item.repository.full_name, &item.path).await {
                        let leaks = self.analyze_content(&file_content, &item.repository.full_name, &item.path);
                        for leak in leaks {
                            println!(
                                "[🚨 GLOBAL SIZINTI] Tür: {} | Konum: {}\n    └── Yakalanan Key: \x1b[31m{}\x1b[0m", 
                                leak.secret_type, leak.file_path, leak.matched_content
                            );
                            all_leaks.push(leak);
                        }
                    }
                    sleep(Duration::from_millis(400)).await;
                }
            }
        }

        println!("\n[*] AŞAMA 2: İndeks Dışı Riskli Dosyalar Taranıyor (Derin Tarama)...");
        let repos = self.get_user_repositories(target_user).await;
        let critical_files = vec![".env", "config.json", "database.yml", "src/config.js", "README.md"];

        for repo in repos {
            let full_repo_name = format!("{}/{}", target_user, repo);
            for file_path in &critical_files {
                if let Some(file_content) = self.fetch_raw_file(&full_repo_name, file_path).await {
                    let leaks = self.analyze_content(&file_content, &full_repo_name, file_path);
                    for leak in leaks {
                        if !all_leaks.iter().any(|l| l.repo == leak.repo && l.file_path == leak.file_path) {
                            println!(
                                "[🚨 DERİN TARAMA SIZINTISI] Tür: {} | Konum: {}\n    └── Yakalanan Key: \x1b[31m{}\x1b[0m", 
                                leak.secret_type, leak.file_path, leak.matched_content
                            );
                            all_leaks.push(leak);
                        }
                    }
                }
            }
        }

        all_leaks
    }
}