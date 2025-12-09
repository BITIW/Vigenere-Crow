use clap::{Parser, Subcommand};
use fastrand::Rng;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

const ALPHABET: [char; 26] = [
    'A','B','C','D','E','F','G','H','I','J','K','L','M',
    'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
];

const TABLE: [[char; 26]; 10] = [
    ['R','S','A','K','F','B','R','S','I','M','E','R','B','S','E','N','N','O','E','I','T','T','U','S','L','M'],
    ['O','J','T','A','U','I','O','S','E','R','O','E','A','I','N','P','T','G','E','T','I','I','N','E','Z','U'],
    ['O','E','G','D','E','S','A','E','Q','I','D','W','T','A','N','U','I','O','B','U','E','R','O','L','T','H'],
    ['S','D','F','E','N','H','F','F','M','O','Y','M','L','N','F','R','I','H','A','I','O','I','S','A','N','U'],
    ['R','H','D','E','E','I','H','O','V','T','R','M','D','O','O','D','A','I','L','A','P','J','R','I','R','I'],
    ['L','I','M','U','O','M','D','A','E','H','S','A','D','P','E','L','W','T','O','T','A','D','E','G','K','T'],
    ['A','A','E','W','I','N','M','Z','L','J','D','E','M','L','S','A','E','P','H','S','N','A','Y','I','E','H'],
    ['E','D','O','H','N','T','N','T','A','S','H','L','D','M','R','R','O','U','M','R','F','T','S','E','N','E'],
    ['O','G','K','A','D','I','Y','H','L','K','A','H','Q','I','T','W','A','E','S','Y','S','E','O','N','B','L'],
    ['N','E','R','E','N','S','C','H','R','C','I','X','D','E','L','T','D','Y','T','T','A','S','T','U','M','V'],
];

/// Voronoi Vigenère cipher with digits 0–9.
/// Non-ASCII-letters are passed through unchanged.
#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Шифрует plaintext; если ключ не указан, генерирует длиной ≤ числу букв
    Encrypt {
        /// Текст для шифрования
        #[arg(short, long, conflicts_with = "file")]
        input: Option<String>,
        /// Путь к файлу для шифрования
        #[arg(short = 'f', long, value_name = "PATH", conflicts_with = "input")]
        file: Option<PathBuf>,
        /// Ключ (только буквы); если не задан — будет сгенерирован
        #[arg(short, long)]
        key: Option<String>,
        /// Длина ключа (≤ числу букв в тексте). Работает только если --key НЕ указан.
        #[arg(long)]
        key_length: Option<usize>,
    },
    /// Дешифрует cipher (цифры и любые символы вне 0–9 проходят как есть)
    Decrypt {
        /// Текст для расшифровки
        #[arg(short, long, conflicts_with = "file")]
        input: Option<String>,
        /// Путь к файлу для дешифровки
        #[arg(short = 'f', long, value_name = "PATH", conflicts_with = "input")]
        file: Option<PathBuf>,
        /// Ключ (только буквы)
        #[arg(short, long)]
        key: String,
    },
}

fn read_input(input: Option<String>, file: Option<PathBuf>) -> String {
    if let Some(s) = input {
        s
    } else if let Some(path) = file {
        fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Не удалось прочитать файл {:?}: {}", path, e))
    } else {
        panic!("Нужно указать либо --input, либо --file");
    }
}

fn encrypt(plain: &str, key: &str) -> Option<String> {
    let mut cipher = String::new();
    let mut key_iter = key
        .chars()
        .cycle()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_uppercase());

    for ch in plain.chars() {
        if ch.is_ascii_alphabetic() {
            let p = ch.to_ascii_uppercase();
            let k = key_iter.next().unwrap();
            let col = ALPHABET.iter().position(|&c| c == k)?;
            let row = TABLE.iter().position(|r| r[col] == p)?;
            cipher.push(std::char::from_digit(row as u32, 10).unwrap());
        } else {
            cipher.push(ch);
        }
    }
    Some(cipher)
}

fn decrypt(cipher: &str, key: &str) -> Option<String> {
    let mut plain = String::new();
    let mut key_iter = key
        .chars()
        .cycle()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_uppercase());

    for ch in cipher.chars() {
        if ch.is_ascii_digit() {
            let row = ch.to_digit(10).unwrap() as usize;
            let k = key_iter.next().unwrap();
            let col = ALPHABET.iter().position(|&c| c == k)?;
            plain.push(TABLE[row][col]);
        } else {
            plain.push(ch);
        }
    }
    Some(plain)
}

fn generate_valid_key(plain: &str, key_len: usize) -> Option<String> {
    let letters: Vec<char> = plain
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let n = letters.len();
    if key_len == 0 || key_len > n {
        return None;
    }
    let mut rng = Rng::new();
    let mut key = Vec::with_capacity(key_len);

    for k in 0..key_len {
        let group: Vec<char> = letters
            .iter()
            .enumerate()
            .filter(|(i, _)| i % key_len == k)
            .map(|(_, &p)| p)
            .collect();

        let mut cand = Vec::new();
        for (col, &alpha) in ALPHABET.iter().enumerate() {
            if group.iter().all(|&p| TABLE.iter().any(|row| row[col] == p)) {
                cand.push(alpha);
            }
        }
        if cand.is_empty() {
            return None;
        }
        let idx = rng.usize(..cand.len());
        key.push(cand[idx]);
    }

    Some(key.into_iter().collect())
}

fn main() {
    let total_start = Instant::now();

    // 1) парсинг CLI и ввод
    let parse_start = Instant::now();
    let cli = Cli::parse();
    let parse_time = parse_start.elapsed();

    // 2) чтение input (строка или файл) и генерация/загрузка ключа
    let gen_start = Instant::now();
    let (mode, text, final_key) = match cli.command {
        Commands::Encrypt { input, file, key, key_length } => {
            let plain = read_input(input, file);
            let final_key = if let Some(k) = key {
                k
            } else {
                let letters_count = plain.chars().filter(|c| c.is_ascii_alphabetic()).count();
                let len = key_length.unwrap_or(letters_count);
                generate_valid_key(&plain, len)
                    .expect("Не удалось сгенерировать допустимый ключ для заданной длины")
            };
            ("encrypt", plain, final_key)
        }
        Commands::Decrypt { input, file, key } => {
            let cipher = read_input(input, file);
            ("decrypt", cipher, key)
        }
    };
    let gen_time = gen_start.elapsed();

    // 3) шифрование / дешифровка
    let cipher_start = Instant::now();
    let output = match mode {
        "encrypt" => encrypt(&text, &final_key).expect("Шифрование не удалось"),
        "decrypt" => decrypt(&text, &final_key).expect("Дешифровка не удалась"),
        _ => unreachable!(),
    };
    let cipher_time = cipher_start.elapsed();

    // 4) итог
    let total_time = total_start.elapsed();

    // 5) вывод результата
    match mode {
        "encrypt" => {
            println!("plain:  {}", text);
            println!("key:    {}", final_key);
            println!("cipher: {}", output);
        }
        "decrypt" => {
            println!("cipher: {}", text);
            println!("key:    {}", final_key);
            println!("plain:  {}", output);
        }
        _ => {}
    }

    // 6) тайминги в stderr
    eprintln!("\n-- Timing (ms) --");
    eprintln!("Parse args & input:       {:.3}", parse_time.as_secs_f64() * 1000.0);
    eprintln!("Read & key generation:    {:.3}", gen_time.as_secs_f64() * 1000.0);
    eprintln!("Encrypt/Decrypt(KAT):          {:.3}", cipher_time.as_secs_f64() * 1000.0);
    eprintln!("Total:                    {:.3}", total_time.as_secs_f64() * 1000.0);
}
