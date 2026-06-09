use std::env;

#[tokio::main]
async fn main() {
    println!("===================================================");
    println!("      Advanced Hibrit GitHub Secrets Dumper v3.0   ");
    println!("===================================================");

    // 1. GITHUB_TOKEN kontrolü (Eksikse panic fırlatmadan temiz çıkış yapar)
    let token = match env::var("GITHUB_TOKEN") {
        Ok(t) => t,
        Err(_) => {
            println!("[!] HATA: GITHUB_TOKEN tanımlanmamış!");
            std::process::exit(1);
        }
    };

    // 2. Dinamik Hedef Kullanıcı Kontrolü (Komut satırından argüman alır)
    // Kullanım: cargo run -- <hedef_kullanici_adi>
    let target_user = match env::args().nth(1) {
        Some(arg) if !arg.trim().is_empty() => arg,
        _ => {
            println!("[!] HATA: Hedef kullanıcı adı belirtilmedi.");
            println!("[*] Kullanım: cargo run -- <github_kullanici_adi>");
            std::process::exit(1);
        }
    };

    // Güvenli tarayıcı motorunu başlat ve çalıştır
    let scanner = repo_scanner::RepoScanner::new(&token);
    scanner.run(&target_user).await;
}
