use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT, ACCEPT, AUTHORIZATION, RETRY_AFTER};
use std::time::Duration;
use std::collections::HashSet;
use tokio::time::sleep;

// Analiz çıktılarının temiz taşınması için veri modeli
#[derive(Clone)]
pub struct LeakResult {
    pub secret_type: String,
    pub repo_name: String,
    pub file_path: String,
    pub matched_content: String,
}

// GitHub API arama yanıt yapısı
#[derive(serde::Deserialize)]
pub struct SearchResult {
    pub items: Vec<SearchItem>,
}

#[derive(serde::Deserialize)]
pub struct SearchItem {
    pub path: String,
    pub repository: RepositoryInfo,
}

#[derive(serde::Deserialize)]
pub struct RepositoryInfo {
    pub full_name: String,
}

#[derive(serde::Deserialize)]
struct GitHubRepo {
    default_branch: String,
}

// GitHub kullanıcı depoları listesi için ham yanıt yapısı
#[derive(serde::Deserialize)]
struct RepoResponse {
    name: String,
}

pub struct RepoScanner {
    client: reqwest::Client,
}

impl RepoScanner {
    /// Güvenli ve panic-free yeni bir tarayıcı örneği oluşturur
    pub fn new(github_token: &str) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static("SecOps-Scanner/3.0"));
        headers.insert(ACCEPT, HeaderValue::from_static("application/vnd.github+json"));
        headers.insert("X-GitHub-Api-Version", HeaderValue::from_static("2022-11-28"));
        
        let clean_token = github_token.trim().trim_matches('"').trim_matches('\'');
        let auth_header_value = format!("Bearer {}", clean_token);
        
        let auth_value = match HeaderValue::from_str(&auth_header_value) {
            Ok(val) => val,
            Err(_) => {
                println!("[!] HATA: GITHUB_TOKEN geçersiz karakterler içeriyor!");
                std::process::exit(1);
            }
        };
        headers.insert(AUTHORIZATION, auth_value);

        let client = match reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(15))
            .build() {
                Ok(c) => c,
                Err(_) => {
                    println!("[!] HATA: HTTP İstemcisi başlatılamadı!");
                    std::process::exit(1);
                }
            };

        RepoScanner { client }
    }

    /// GitHub API istek sınırı (Rate Limit) korumalı arama fonksiyonu
    pub async fn execute_search_with_retry(&self, query: &str) -> Option<SearchResult> {
        let url = "https://api.github.com/search/code";
        let mut current_delay = Duration::from_secs(3);

        for attempt in 1..=3 {
            let res = self.client.get(url).query(&[("q", query)]).send().await;

            match res {
                Ok(resp) => {
                    let status = resp.status();
                    if status == reqwest::StatusCode::OK {
                        return resp.json::<SearchResult>().await.ok();
                    }

                    if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                        let retry_after = resp
                            .headers()
                            .get(RETRY_AFTER)
                            .and_then(|v| v.to_str().ok())
                            .and_then(|s| s.parse::<u64>().ok())
                            .map(Duration::from_secs);

                        let delay = retry_after.unwrap_or(current_delay);
                        sleep(delay).await;
                        current_delay *= 2;
                        continue;
                    }
                    break;
                }
                Err(_) => {
                    sleep(current_delay).await;
                    current_delay *= 2;
                }
            }
        }
        None
    }

    /// 🌟 1. RESMİN ÇÖZÜMÜ: TÜM DEPOLARI KAÇIRMADAN ÇEKEN SAYFALAMALI (PAGINATION) SİSTEM
    async fn get_user_repositories(&self, target_user: &str) -> Vec<String> {
        let mut all_repos = Vec::new();
        let mut page = 1;

        loop {
            let url = format!("https://api.github.com/users/{}/repos", target_user);
            let res = self.client.get(&url)
                .query(&[("per_page", "100"), ("page", &page.to_string())])
                .send()
                .await;

            if let Ok(resp) = res {
                if resp.status().is_success() {
                    if let Ok(repos) = resp.json::<Vec<RepoResponse>>().await {
                        if repos.is_empty() {
                            break; // Artık yeni depo kalmadıysa döngüden çık
                        }
                        for r in repos {
                            all_repos.push(r.name);
                        }
                        page += 1;
                        continue;
                    }
                }
            }
            break;
        }
        all_repos
    }

    /// Dinamik dal algılamalı ham dosya indirme fonksiyonu
    pub async fn fetch_raw_file(&self, repo: &str, path: &str) -> Option<String> {
        let api_url = format!("https://api.github.com/repos/{}", repo);
        let mut target_branch = String::from("main");

        if let Ok(resp) = self.client.get(&api_url).send().await {
            if resp.status().is_success() {
                if let Ok(repo_info) = resp.json::<GitHubRepo>().await {
                    target_branch = repo_info.default_branch;
                }
            }
        }

        let raw_url = format!("https://raw.githubusercontent.com/{}/{}/{}", repo, target_branch, path);
        if let Ok(raw_resp) = self.client.get(&raw_url).send().await {
            if raw_resp.status().is_success() {
                return raw_resp.text().await.ok();
            }
        }
        None
    }

    /// Mock içerik analiz fonksiyonu (Sızıntı imzalarını denetler)
    fn analyse_content(&self, content: &str, repo: &str, path: &str) -> Vec<LeakResult> {
        let mut leaks = Vec::new();
        if content.contains("secret") || content.contains("password") {
            leaks.push(LeakResult {
                secret_type: String::from("Hardcoded Credential"),
                repo_name: repo.to_string(),
                file_path: path.to_string(),
                matched_content: String::from("[CRITICAL] Sensitive key pattern signature matched."),
            });
        }
        leaks
    }

    /// 🌟 2. RESMİN ÇÖZÜMÜ: SAF TARAMA (SCAN) VE HASHSET DUPLICATE ENGELLEME LOJİĞİ
    pub async fn scan(&self, target_user: &str) -> Vec<LeakResult> {
        let mut all_leaks = Vec::new();
        let mut seen_keys = HashSet::new(); // Mükerrer taramayı önleyen küme

        // Aşama A: Global Dork Aramaları
        let dork_query = format!("user:{} secret", target_user);
        if let Some(search_result) = self.execute_search_with_retry(&dork_query).await {
            for item in search_result.items {
                if let Some(file_content) = self.fetch_raw_file(&item.repository.full_name, &item.path).await {
                    let leaks = self.analyse_content(&file_content, &item.repository.full_name, &item.path);
                    
                    for leak in leaks {
                        let key = (leak.repo_name.clone(), leak.file_path.clone());
                        if seen_keys.insert(key) {
                            all_leaks.push(leak);
                        }
                    }
                }
                sleep(Duration::from_millis(400)).await;
            }
        }

        // Aşama B: Tüm Repolarda Kritik Konfigürasyon Taraması (Sayfalamalı Güvenli Alan)
        let repos = self.get_user_repositories(target_user).await;
        let critical_files = vec![".env", "config.json", "database.yml", "srv/config.js", "README.md"];

        for repo in repos {
            let full_repo_name = format!("{}/{}", target_user, repo);
            for file_path in &critical_files {
                let key = (full_repo_name.clone(), file_path.to_string());
                // Eğer bu dosya global dork aşamasında zaten tarandıysa pas geç (O(1) Hız)
                if seen_keys.contains(&key) {
                    continue;
                }

                if let Some(file_content) = self.fetch_raw_file(&full_repo_name, file_path).await {
                    let leaks = self.analyse_content(&file_content, &full_repo_name, file_path);
                    for leak in leaks {
                        if seen_keys.insert((leak.repo_name.clone(), leak.file_path.clone())) {
                            all_leaks.push(leak);
                        }
                    }
                }
            }
        }
        all_leaks
    }

    /// 🌟 2. RESMİN ÇÖZÜMÜ: SADECE SUNUM VE FORMATLI ÇIKTIYLA İLGİLENEN RUN FONKSİYONU
    pub async fn run(&self, target_user: &str) {
        println!("[*] AŞAMA 1: Global Endeks Araması Başlatılıyor...");
        println!("[*] AŞAMA 2: Derinlemesine Konfigürasyon Dosyaları Taranıyor...");

        let all_leaks = self.scan(target_user).await;

        if all_leaks.is_empty() {
            println!("[+] Harika! Hedef üzerinde herhangi bir veri sızıntısı tespit edilmedi.");
            return;
        }

        for leak in all_leaks {
            println!(
                "[🔥 SIZINTI] Tür: {} | Konum: {}\n    └── Yakalanan İmza: {}",
                leak.secret_type, leak.file_path, leak.matched_content
            );
        }
    }
}
