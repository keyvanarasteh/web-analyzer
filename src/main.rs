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
            std::process::exit(1); // 🌟 return; yerine bunu yazdık
        }
    };

// Hedef kullanıcı adını komut satırı argümanlarından al
// Örnek kullanım: cargo run -- hedef_kullanici_adi
let target_user = match std::env::args().nth(1) {
    Some(arg) if !arg.trim().is_empty() => arg,
    _ => {
        println!("[!] HATA: Hedef kullanıcı adı belirtilmedi.");
        println!("[*] Kullanım: cargo run -- <github_kullanici_adi>");
        std::process::exit(1);
    }
};

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
