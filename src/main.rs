mod repo_scanner;

#[tokio::main]
async fn main() {
    println!("======================================================");
    println!("     Advanced Hibrit GitHub Secrets Dumper v3.0       ");
    println!("======================================================");

    let token = match std::env::var("GITHUB_TOKEN") {
        Ok(t) => t,
        Err(_) => {
            println!("[!] HATA: GITHUB_TOKEN tanımlanmamış!");
            return;
        }
    };

    // 🎯 BURAYA TARAMAK İSTEDİĞİN KİŞİNİN KULLANICI ADINI YAZABİLİRSİN
    let target_user = "hedef_kullanici_adi"; 

    let scanner = repo_scanner::RepoScanner::new(&token);
    let sonuclar = scanner.run(target_user).await;

    println!("\n=================== OPERASYON RAPORU ===================");
    println!("[+] Tarama Tamamlandı.");
    println!("[+] Toplam Yakalanan Kritik Sızıntı Sayısı: {}", sonuclar.len());
    
    if sonuclar.len() > 0 {
        println!("\n[🚨] DETAYLI BULGU LİSTESİ:");
        for (i, leak) in sonuclar.iter().enumerate() {
            println!(
                "    {}. [{}] -> Repo: {} | Dosya: {}\n       └── Sızan Kritik Veri: {}", 
                i + 1, leak.secret_type, leak.repo, leak.file_path, leak.matched_content
            );
        }
    } else {
        println!("[+] Hedef profil üzerinde herhangi bir sızıntı izine rastlanmadı.");
    }
    println!("========================================================");
}