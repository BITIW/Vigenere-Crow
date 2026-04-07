use clap::{Parser, Subcommand};
use rand::rngs::{OsRng, StdRng};
use rand::{Rng, SeedableRng};
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

const ALPHABET: [char; 26] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
];

const TABLE: [[char; 26]; 10] = [
    [
        'R', 'S', 'A', 'K', 'F', 'B', 'R', 'S', 'I', 'M', 'E', 'R', 'B', 'S', 'E', 'N', 'N', 'O',
        'E', 'I', 'T', 'T', 'U', 'S', 'L', 'M',
    ],
    [
        'O', 'J', 'T', 'A', 'U', 'I', 'O', 'S', 'E', 'R', 'O', 'E', 'A', 'I', 'N', 'P', 'T', 'G',
        'E', 'T', 'I', 'I', 'N', 'E', 'Z', 'U',
    ],
    [
        'O', 'E', 'G', 'D', 'E', 'S', 'A', 'E', 'Q', 'I', 'D', 'W', 'T', 'A', 'N', 'U', 'I', 'O',
        'B', 'U', 'E', 'R', 'O', 'L', 'T', 'H',
    ],
    [
        'S', 'D', 'F', 'E', 'N', 'H', 'F', 'F', 'M', 'O', 'Y', 'M', 'L', 'N', 'F', 'R', 'I', 'H',
        'A', 'I', 'O', 'I', 'S', 'A', 'N', 'U',
    ],
    [
        'R', 'H', 'D', 'E', 'E', 'I', 'H', 'O', 'V', 'T', 'R', 'M', 'D', 'O', 'O', 'D', 'A', 'I',
        'L', 'A', 'P', 'J', 'R', 'I', 'R', 'I',
    ],
    [
        'L', 'I', 'M', 'U', 'O', 'M', 'D', 'A', 'E', 'H', 'S', 'A', 'D', 'P', 'E', 'L', 'W', 'T',
        'O', 'T', 'A', 'D', 'E', 'G', 'K', 'T',
    ],
    [
        'A', 'A', 'E', 'W', 'I', 'N', 'M', 'Z', 'L', 'J', 'D', 'E', 'M', 'L', 'S', 'A', 'E', 'P',
        'H', 'S', 'N', 'A', 'Y', 'I', 'E', 'H',
    ],
    [
        'E', 'D', 'O', 'H', 'N', 'T', 'N', 'T', 'A', 'S', 'H', 'L', 'D', 'M', 'R', 'R', 'O', 'U',
        'M', 'R', 'F', 'T', 'S', 'E', 'N', 'E',
    ],
    [
        'O', 'G', 'K', 'A', 'D', 'I', 'Y', 'H', 'L', 'K', 'A', 'H', 'Q', 'I', 'T', 'W', 'A', 'E',
        'S', 'Y', 'S', 'E', 'O', 'N', 'B', 'L',
    ],
    [
        'N', 'E', 'R', 'E', 'N', 'S', 'C', 'H', 'R', 'C', 'I', 'X', 'D', 'E', 'L', 'T', 'D', 'Y',
        'T', 'T', 'A', 'S', 'T', 'U', 'M', 'V',
    ],
];

const LEGACY_VC2_CIPHER_PREFIX: &str = "VC2:";
const LEGACY_VC2_NONCE_HEX_LEN: usize = 16;
const LEGACY_DIGIT_CIPHER_PREFIX: &str = "73";
const LEGACY_HEADER_CHECK_LEN: usize = 8;
const NONCE_DEC_LEN: usize = 8;
const FORMAT_CHECK_LEN: usize = 4;
const AUTH_TAG_LEN: usize = 8;
const LETTER_TOKEN_LEN: usize = 3;
const BYTE_ESCAPE_SENTINEL: [u8; LETTER_TOKEN_LEN] = [9, 9, 9];
const BYTE_TOKEN_TAIL_LEN: usize = 3;
const PACKED_GROUP_TOKENS: usize = 12;
const PACKED_GROUP_WIDTHS: [usize; PACKED_GROUP_TOKENS + 1] = [0, 3, 5, 8, 10, 13, 15, 17, 20, 22, 25, 27, 29];
const ESCAPE_PREFIX: char = '~';
const ESCAPED_LITERAL_HEX_LEN: usize = 6;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    /// Print plaintext/key details for debugging.
    #[arg(long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt plaintext. If key is omitted, a valid key is generated.
    Encrypt {
        /// Text for encryption.
        #[arg(short, long, conflicts_with = "file")]
        input: Option<String>,

        /// File path with text to encrypt.
        #[arg(short = 'f', long, value_name = "PATH", conflicts_with = "input")]
        file: Option<PathBuf>,

        /// Key (ASCII letters only).
        #[arg(short, long)]
        key: Option<String>,

        /// Key length (works only if --key is omitted).
        #[arg(long, conflicts_with = "key")]
        key_length: Option<usize>,
    },

    /// Decrypt ciphertext.
    Decrypt {
        /// Text for decryption.
        #[arg(short, long, conflicts_with = "file")]
        input: Option<String>,

        /// File path with text to decrypt.
        #[arg(short = 'f', long, value_name = "PATH", conflicts_with = "input")]
        file: Option<PathBuf>,

        /// Key (ASCII letters only).
        #[arg(short, long)]
        key: String,
    },
}

fn read_input(input: Option<String>, file: Option<PathBuf>) -> Result<String, String> {
    if let Some(text) = input {
        return Ok(text);
    }

    if let Some(path) = file {
        return fs::read_to_string(&path)
            .map_err(|e| format!("failed to read file {:?}: {}", path, e));
    }

    Err("provide either --input or --file".to_string())
}

fn normalize_key(key: &str) -> Result<Vec<char>, String> {
    if key.is_empty() {
        return Err("key must not be empty".to_string());
    }
    if !key.chars().all(|c| c.is_ascii_alphabetic()) {
        return Err("key must contain ASCII letters only".to_string());
    }

    Ok(key.chars().map(|c| c.to_ascii_uppercase()).collect())
}

fn col_from_letter(ch: char) -> Option<usize> {
    if ch.is_ascii_uppercase() {
        Some((ch as u8 - b'A') as usize)
    } else {
        None
    }
}

enum CipherInput<'a> {
    LegacyRows(&'a str),
    LegacyMaskedRows { nonce: u64, body: &'a str },
    ModernPackedLetters { nonce: u32, body: &'a str },
    ModernTokens { nonce: u32, body: &'a str },
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

fn derive_mask_seed(key: &[char], nonce: u64) -> [u8; 32] {
    let mut state =
        nonce ^ 0x6A09E667F3BCC909 ^ (key.len() as u64).wrapping_mul(0xA0761D6478BD642F);

    for (idx, &ch) in key.iter().enumerate() {
        state ^= ((ch as u64) << ((idx % 8) * 8))
            ^ ((idx as u64 + 1).wrapping_mul(0x9E3779B97F4A7C15));
        state = splitmix64(&mut state);
    }

    let mut seed = [0u8; 32];
    for chunk in seed.chunks_mut(8) {
        chunk.copy_from_slice(&splitmix64(&mut state).to_le_bytes());
    }
    seed
}

fn build_mask_rng(key: &[char], nonce: u64) -> StdRng {
    StdRng::from_seed(derive_mask_seed(key, nonce))
}

fn legacy_header_checksum(key: &[char], nonce: u32) -> u32 {
    let seed = derive_mask_seed(key, nonce as u64);
    let mut head = [0u8; 8];
    head.copy_from_slice(&seed[..8]);
    (u64::from_le_bytes(head) % 100_000_000) as u32
}

fn format_header_check(nonce: u32) -> u32 {
    let mut state = nonce as u64 ^ 0xD6E8FEB86659FD93;
    (splitmix64(&mut state) % 10_000) as u32
}

fn compute_auth_tag(key: &[char], nonce: u32, body: &str, mode_tag: u8) -> String {
    let mut state =
        nonce as u64 ^ 0xC6BC279692B5CC83 ^ (body.len() as u64).wrapping_mul(0x9E3779B97F4A7C15);
    state ^= (mode_tag as u64).wrapping_mul(0x94D049BB133111EB);

    for (idx, &ch) in key.iter().enumerate() {
        state ^= ((ch as u64) << ((idx % 8) * 8))
            ^ ((idx as u64 + 1).wrapping_mul(0xA24BAED4963EE407));
        state = splitmix64(&mut state);
    }

    for (idx, byte) in body.bytes().enumerate() {
        state ^= ((byte - b'0' + 1) as u64)
            .wrapping_mul((idx as u64 + 1).wrapping_mul(0x9E3779B185EBCA87));
        state = splitmix64(&mut state);
    }

    let mut tag = String::with_capacity(AUTH_TAG_LEN);
    for _ in 0..AUTH_TAG_LEN {
        let digit = (splitmix64(&mut state) % 10) as u8;
        tag.push((b'0' + digit) as char);
    }
    tag
}

fn format_ciphertext(nonce: u32, key: &[char], body: &str, mode_tag: u8) -> String {
    let header_check = format_header_check(nonce);
    let auth_tag = compute_auth_tag(key, nonce, body, mode_tag);
    format!("{nonce:0NONCE_DEC_LEN$}{header_check:0FORMAT_CHECK_LEN$}{body}{auth_tag}")
}

fn parse_vc2_ciphertext(cipher: &str) -> Result<Option<CipherInput<'_>>, String> {
    if let Some(rest) = cipher.strip_prefix(LEGACY_VC2_CIPHER_PREFIX) {
        let (nonce_hex, body) = rest
            .split_once(':')
            .ok_or_else(|| "modern ciphertext header is missing body separator".to_string())?;

        if nonce_hex.len() != LEGACY_VC2_NONCE_HEX_LEN
            || !nonce_hex.chars().all(|ch| ch.is_ascii_hexdigit())
        {
            return Err("modern ciphertext nonce must be 16 hex digits".to_string());
        }

        let nonce = u64::from_str_radix(nonce_hex, 16)
            .map_err(|_| "failed to parse modern ciphertext nonce".to_string())?;
        Ok(Some(CipherInput::LegacyMaskedRows { nonce, body }))
    } else {
        Ok(None)
    }
}

fn parse_legacy_digit_ciphertext<'a>(cipher: &'a str, key: &[char]) -> Option<CipherInput<'a>> {
    let header_len = NONCE_DEC_LEN + LEGACY_HEADER_CHECK_LEN;
    if cipher.len() < header_len {
        return None;
    }

    let nonce_start = 0;
    let nonce_end = NONCE_DEC_LEN;
    let check_end = nonce_end + LEGACY_HEADER_CHECK_LEN;

    let nonce_text = &cipher[nonce_start..nonce_end];
    let checksum_text = &cipher[nonce_end..check_end];
    if !nonce_text.chars().all(|ch| ch.is_ascii_digit())
        || !checksum_text.chars().all(|ch| ch.is_ascii_digit())
    {
        return None;
    }

    let nonce = nonce_text.parse::<u32>().ok()?;
    let checksum = checksum_text.parse::<u32>().ok()?;
    if legacy_header_checksum(key, nonce) != checksum {
        return None;
    }

    Some(CipherInput::LegacyMaskedRows {
        nonce: nonce as u64,
        body: &cipher[check_end..],
    })
}

fn parse_modern_digit_ciphertext<'a>(
    cipher: &'a str,
    key: &[char],
) -> Result<Option<CipherInput<'a>>, String> {
    let header_len = NONCE_DEC_LEN + FORMAT_CHECK_LEN;
    if cipher.len() < header_len + AUTH_TAG_LEN || !cipher.chars().all(|ch| ch.is_ascii_digit()) {
        return Ok(None);
    }

    let nonce_text = &cipher[..NONCE_DEC_LEN];
    let check_text = &cipher[NONCE_DEC_LEN..header_len];
    let nonce = nonce_text
        .parse::<u32>()
        .map_err(|_| "failed to parse modern ciphertext nonce".to_string())?;
    let expected_check = format_header_check(nonce);
    let observed_check = check_text
        .parse::<u32>()
        .map_err(|_| "failed to parse modern ciphertext header check".to_string())?;
    if observed_check != expected_check {
        return Ok(None);
    }

    let body_end = cipher.len() - AUTH_TAG_LEN;
    let body = &cipher[header_len..body_end];
    let tag = &cipher[body_end..];
    if tag == compute_auth_tag(key, nonce, body, 0) {
        return Ok(Some(CipherInput::ModernPackedLetters { nonce, body }));
    }
    if tag == compute_auth_tag(key, nonce, body, 1) {
        return Ok(Some(CipherInput::ModernTokens { nonce, body }));
    }

    Err("authentication failed or wrong key".to_string())
}

fn parse_ciphertext_with_key<'a>(cipher: &'a str, key: &[char]) -> Result<CipherInput<'a>, String> {
    if let Some(parsed) = parse_vc2_ciphertext(cipher)? {
        return Ok(parsed);
    }

    if let Some(rest) = cipher.strip_prefix(LEGACY_DIGIT_CIPHER_PREFIX) {
        if let Some(parsed) = parse_legacy_digit_ciphertext(rest, key) {
            return Ok(parsed);
        }
    }

    let looks_like_structured_digits =
        cipher.len() >= NONCE_DEC_LEN + FORMAT_CHECK_LEN + AUTH_TAG_LEN
            && cipher.chars().all(|ch| ch.is_ascii_digit());
    if looks_like_structured_digits {
        if let Some(parsed) = parse_modern_digit_ciphertext(cipher, key)? {
            return Ok(parsed);
        }

        if let Some(parsed) = parse_legacy_digit_ciphertext(cipher, key) {
            return Ok(parsed);
        }

        return Err("ciphertext failed format or authentication checks".to_string());
    }

    Ok(CipherInput::LegacyRows(cipher))
}

fn letter_cells(letter: u8) -> Vec<(usize, usize)> {
    let mut cells = Vec::new();
    let target = letter as char;
    for (row_idx, row) in TABLE.iter().enumerate() {
        for (col_idx, &cell) in row.iter().enumerate() {
            if cell == target {
                cells.push((row_idx, col_idx));
            }
        }
    }
    cells
}

fn packed_body_len_for_tokens(token_count: usize) -> usize {
    let full_groups = token_count / PACKED_GROUP_TOKENS;
    let tail = token_count % PACKED_GROUP_TOKENS;
    full_groups * PACKED_GROUP_WIDTHS[PACKED_GROUP_TOKENS] + PACKED_GROUP_WIDTHS[tail]
}

fn decode_packed_tail_len(remainder: usize) -> Option<usize> {
    PACKED_GROUP_WIDTHS
        .iter()
        .enumerate()
        .find_map(|(idx, &width)| (idx < PACKED_GROUP_TOKENS && width == remainder).then_some(idx))
}

fn pack_base260_tokens(tokens: &[u16]) -> String {
    let mut out = String::with_capacity(packed_body_len_for_tokens(tokens.len()));
    for chunk in tokens.chunks(PACKED_GROUP_TOKENS) {
        let mut value = 0u128;
        for &token in chunk {
            value = value * 260 + token as u128;
        }
        let width = PACKED_GROUP_WIDTHS[chunk.len()];
        out.push_str(&format!("{value:0width$}"));
    }
    out
}

fn unpack_base260_tokens(body: &str) -> Result<Vec<u16>, String> {
    let full_width = PACKED_GROUP_WIDTHS[PACKED_GROUP_TOKENS];
    let remainder = body.len() % full_width;
    let tail_len = if remainder == 0 {
        0
    } else {
        decode_packed_tail_len(remainder)
            .ok_or_else(|| "invalid packed-letter ciphertext length".to_string())?
    };
    let full_chunks = body.len() / full_width;
    let total_tokens = full_chunks * PACKED_GROUP_TOKENS + tail_len;
    let mut tokens = Vec::with_capacity(total_tokens);
    let mut pos = 0usize;

    for _ in 0..full_chunks {
        let end = pos + full_width;
        let mut value = body[pos..end]
            .parse::<u128>()
            .map_err(|_| "failed to parse packed ciphertext chunk".to_string())?;
        let mut chunk_tokens = [0u16; PACKED_GROUP_TOKENS];
        for idx in (0..PACKED_GROUP_TOKENS).rev() {
            chunk_tokens[idx] = (value % 260) as u16;
            value /= 260;
        }
        tokens.extend_from_slice(&chunk_tokens);
        pos = end;
    }

    if tail_len > 0 {
        let mut value = body[pos..]
            .parse::<u128>()
            .map_err(|_| "failed to parse packed ciphertext tail".to_string())?;
        let mut chunk_tokens = vec![0u16; tail_len];
        for idx in (0..tail_len).rev() {
            chunk_tokens[idx] = (value % 260) as u16;
            value /= 260;
        }
        tokens.extend(chunk_tokens);
    }

    Ok(tokens)
}

fn read_escaped_literal<I>(chars: &mut I) -> Result<char, String>
where
    I: Iterator<Item = char>,
{
    let mut hex = String::with_capacity(ESCAPED_LITERAL_HEX_LEN);
    for _ in 0..ESCAPED_LITERAL_HEX_LEN {
        let ch = chars
            .next()
            .ok_or_else(|| "truncated literal escape in ciphertext".to_string())?;
        if !ch.is_ascii_hexdigit() {
            return Err(format!("invalid escaped literal symbol '{}'", ch));
        }
        hex.push(ch);
    }

    let codepoint = u32::from_str_radix(&hex, 16)
        .map_err(|_| format!("failed to parse escaped literal U+{}", hex))?;
    char::from_u32(codepoint).ok_or_else(|| format!("invalid escaped codepoint U+{}", hex))
}

fn push_masked_digits(out: &mut String, token: &[u8], key_shift: u8, mask_rng: &mut StdRng) {
    for &digit in token {
        let mask = mask_rng.gen_range(0..10) as u8;
        let masked = (digit + key_shift + mask) % 10;
        out.push((b'0' + masked) as char);
    }
}

fn unmask_digits(
    body: &[u8],
    pos: &mut usize,
    count: usize,
    key_shift: u8,
    mask_rng: &mut StdRng,
) -> Result<Vec<u8>, String> {
    if *pos + count > body.len() {
        return Err("truncated modern ciphertext body".to_string());
    }

    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let ch = body[*pos];
        if !ch.is_ascii_digit() {
            return Err(format!(
                "unexpected symbol '{}' in modern ciphertext body",
                ch as char
            ));
        }
        let masked = ch - b'0';
        let mask = mask_rng.gen_range(0..10) as u8;
        let plain = (masked + 20 - key_shift - mask) % 10;
        out.push(plain);
        *pos += 1;
    }
    Ok(out)
}

fn encrypt_packed_letters<R: Rng + ?Sized>(
    plain: &str,
    key: &[char],
    rng: &mut R,
    nonce: u32,
) -> Result<String, String> {
    let mut mask_rng = build_mask_rng(key, nonce as u64);
    let mut key_pos = 0usize;
    let mut tokens = Vec::with_capacity(plain.len());

    for &byte in plain.as_bytes() {
        let letter = byte.to_ascii_uppercase();
        let cells = letter_cells(letter);
        if cells.is_empty() {
            return Err(format!("failed to encrypt symbol '{}'", letter as char));
        }

        let (row, col) = cells[rng.gen_range(0..cells.len())];
        let token = (row * ALPHABET.len() + col) as u16;
        let key_shift = col_from_letter(key[key_pos])
            .ok_or_else(|| "internal key column error".to_string())? as u16;
        key_pos = (key_pos + 1) % key.len();
        let mask = (mask_rng.gen_range(0..10) as u16) * 26;
        tokens.push((token + key_shift + mask) % 260);
    }

    let body = pack_base260_tokens(&tokens);
    Ok(format_ciphertext(nonce, key, &body, 0))
}

fn encrypt_general_tokens<R: Rng + ?Sized>(
    plain: &str,
    key: &[char],
    rng: &mut R,
    nonce: u32,
) -> Result<String, String> {
    let mut mask_rng = build_mask_rng(key, nonce as u64);
    let mut body = String::with_capacity(plain.len() * LETTER_TOKEN_LEN);
    let mut key_pos = 0usize;

    for &byte in plain.as_bytes() {
        let key_shift = (col_from_letter(key[key_pos])
            .ok_or_else(|| "internal key column error".to_string())? as u8)
            % 10;
        key_pos = (key_pos + 1) % key.len();

        if byte.is_ascii_alphabetic() {
            let letter = byte.to_ascii_uppercase();
            let cells = letter_cells(letter);
            if cells.is_empty() {
                return Err(format!("failed to encrypt symbol '{}'", letter as char));
            }
            let (row, col) = cells[rng.gen_range(0..cells.len())];
            let token = [row as u8, (col / 10) as u8, (col % 10) as u8];
            push_masked_digits(&mut body, &token, key_shift, &mut mask_rng);
        } else {
            let token = [
                BYTE_ESCAPE_SENTINEL[0],
                BYTE_ESCAPE_SENTINEL[1],
                BYTE_ESCAPE_SENTINEL[2],
                byte / 100,
                (byte / 10) % 10,
                byte % 10,
            ];
            push_masked_digits(&mut body, &token, key_shift, &mut mask_rng);
        }
    }

    Ok(format_ciphertext(nonce, key, &body, 1))
}

fn encrypt<R: Rng + ?Sized>(plain: &str, key: &[char], rng: &mut R) -> Result<String, String> {
    if key.is_empty() {
        return Err("key must not be empty".to_string());
    }

    let nonce = rng.gen_range(0..100_000_000u32);
    if plain.as_bytes().iter().all(|byte| byte.is_ascii_alphabetic()) {
        encrypt_packed_letters(plain, key, rng, nonce)
    } else {
        encrypt_general_tokens(plain, key, rng, nonce)
    }
}

fn decrypt_legacy(cipher: &str, key: &[char]) -> Result<String, String> {
    if key.is_empty() {
        return Err("key must not be empty".to_string());
    }

    let mut plain = String::with_capacity(cipher.len());
    let mut key_pos = 0usize;

    for ch in cipher.chars() {
        if ch.is_ascii_digit() {
            let row = ch
                .to_digit(10)
                .ok_or_else(|| "failed to parse ciphertext digit".to_string())?
                as usize;
            let col = col_from_letter(key[key_pos])
                .ok_or_else(|| "internal key column error".to_string())?;
            key_pos = (key_pos + 1) % key.len();
            plain.push(TABLE[row][col]);
        } else {
            plain.push(ch);
        }
    }

    Ok(plain)
}

fn decrypt_legacy_masked_rows(cipher: &str, key: &[char], nonce: u64) -> Result<String, String> {
    if key.is_empty() {
        return Err("key must not be empty".to_string());
    }

    let mut plain = String::with_capacity(cipher.len());
    let mut key_pos = 0usize;
    let mut mask_rng = build_mask_rng(key, nonce);
    let mut chars = cipher.chars();

    while let Some(ch) = chars.next() {
        if ch == ESCAPE_PREFIX {
            plain.push(read_escaped_literal(&mut chars)?);
            continue;
        }

        if ch.is_ascii_digit() {
            let encoded_row = ch
                .to_digit(10)
                .ok_or_else(|| "failed to parse ciphertext digit".to_string())?
                as usize;
            let mask = mask_rng.gen_range(0..10);
            let row = (encoded_row + 10 - mask) % 10;
            let col = col_from_letter(key[key_pos])
                .ok_or_else(|| "internal key column error".to_string())?;
            key_pos = (key_pos + 1) % key.len();
            plain.push(TABLE[row][col]);
        } else {
            return Err(format!(
                "unexpected symbol '{}' in modern ciphertext body",
                ch
            ));
        }
    }

    Ok(plain)
}

fn decrypt_modern_tokens(cipher: &str, key: &[char], nonce: u32) -> Result<String, String> {
    if key.is_empty() {
        return Err("key must not be empty".to_string());
    }

    let mut bytes = Vec::with_capacity(cipher.len() / LETTER_TOKEN_LEN);
    let mut key_pos = 0usize;
    let mut mask_rng = build_mask_rng(key, nonce as u64);
    let body = cipher.as_bytes();
    let mut pos = 0usize;

    while pos < body.len() {
        let key_shift = (col_from_letter(key[key_pos])
            .ok_or_else(|| "internal key column error".to_string())? as u8)
            % 10;
        key_pos = (key_pos + 1) % key.len();

        let head = unmask_digits(body, &mut pos, LETTER_TOKEN_LEN, key_shift, &mut mask_rng)?;
        if head == BYTE_ESCAPE_SENTINEL {
            let tail = unmask_digits(body, &mut pos, BYTE_TOKEN_TAIL_LEN, key_shift, &mut mask_rng)?;
            let byte = (tail[0] as u16) * 100 + (tail[1] as u16) * 10 + tail[2] as u16;
            if byte > u8::MAX as u16 {
                return Err("decoded byte token is out of range".to_string());
            }
            bytes.push(byte as u8);
        } else {
            let row = head[0] as usize;
            let col = (head[1] as usize) * 10 + head[2] as usize;
            if col >= ALPHABET.len() {
                return Err("decoded letter token has invalid column".to_string());
            }
            bytes.push(TABLE[row][col] as u8);
        }
    }

    String::from_utf8(bytes).map_err(|_| "decrypted text is not valid UTF-8".to_string())
}

fn decrypt_modern_packed_letters(cipher: &str, key: &[char], nonce: u32) -> Result<String, String> {
    if key.is_empty() {
        return Err("key must not be empty".to_string());
    }

    let mut mask_rng = build_mask_rng(key, nonce as u64);
    let mut key_pos = 0usize;
    let tokens = unpack_base260_tokens(cipher)?;
    let mut plain = String::with_capacity(tokens.len());

    for token in tokens {
        let key_shift = col_from_letter(key[key_pos])
            .ok_or_else(|| "internal key column error".to_string())? as u16;
        key_pos = (key_pos + 1) % key.len();
        let mask = (mask_rng.gen_range(0..10) as u16) * 26;
        let value = (token + 520 - key_shift - mask) % 260;
        let row = (value / 26) as usize;
        let col = (value % 26) as usize;
        plain.push(TABLE[row][col]);
    }

    Ok(plain)
}

fn decrypt(cipher: &str, key: &[char]) -> Result<String, String> {
    match parse_ciphertext_with_key(cipher, key)? {
        CipherInput::LegacyRows(body) => decrypt_legacy(body, key),
        CipherInput::LegacyMaskedRows { nonce, body } => decrypt_legacy_masked_rows(body, key, nonce),
        CipherInput::ModernPackedLetters { nonce, body } => decrypt_modern_packed_letters(body, key, nonce),
        CipherInput::ModernTokens { nonce, body } => decrypt_modern_tokens(body, key, nonce),
    }
}

fn generate_random_key<R: Rng + ?Sized>(key_len: usize, rng: &mut R) -> Result<String, String> {
    if key_len == 0 {
        return Err("key length must be at least 1".to_string());
    }

    let mut key = String::with_capacity(key_len);
    for _ in 0..key_len {
        key.push(ALPHABET[rng.gen_range(0..ALPHABET.len())]);
    }
    Ok(key)
}

fn print_timings(
    parse: std::time::Duration,
    prep: std::time::Duration,
    crypto: std::time::Duration,
    total: std::time::Duration,
) {
    eprintln!("\n-- Timing (ms) --");
    eprintln!(
        "Parse args:              {:.3}",
        parse.as_secs_f64() * 1000.0
    );
    eprintln!(
        "Read input/key prep:     {:.3}",
        prep.as_secs_f64() * 1000.0
    );
    eprintln!(
        "Encrypt/Decrypt:         {:.3}",
        crypto.as_secs_f64() * 1000.0
    );
    eprintln!(
        "Total:                   {:.3}",
        total.as_secs_f64() * 1000.0
    );
}

fn run() -> Result<(), String> {
    let total_start = Instant::now();

    let parse_start = Instant::now();
    let cli = Cli::parse();
    let parse_time = parse_start.elapsed();

    let mut rng = OsRng;

    match cli.command {
        Commands::Encrypt {
            input,
            file,
            key,
            key_length,
        } => {
            let prep_start = Instant::now();
            let plain = read_input(input, file)?;

            let (final_key, key_letters, was_generated) = if let Some(user_key) = key {
                let key_letters = normalize_key(&user_key)?;
                (key_letters.iter().collect::<String>(), key_letters, false)
            } else {
                let len = key_length.unwrap_or_else(|| plain.as_bytes().len().max(1));
                let final_key = generate_random_key(len, &mut rng)?;
                let key_letters = normalize_key(&final_key)?;
                (final_key, key_letters, true)
            };

            let prep_time = prep_start.elapsed();

            let crypto_start = Instant::now();
            let cipher = encrypt(&plain, &key_letters, &mut rng)?;
            let crypto_time = crypto_start.elapsed();
            let total_time = total_start.elapsed();

            if cli.verbose {
                println!("plain:  {}", plain);
                println!("key:    {}", final_key);
                println!("cipher: {}", cipher);
            } else {
                println!("{}", cipher);
                if was_generated {
                    eprintln!("generated key: {}", final_key);
                }
            }

            print_timings(parse_time, prep_time, crypto_time, total_time);
        }
        Commands::Decrypt { input, file, key } => {
            let prep_start = Instant::now();
            let cipher_text = read_input(input, file)?;
            let key_letters = normalize_key(&key)?;
            let prep_time = prep_start.elapsed();

            let crypto_start = Instant::now();
            let plain = decrypt(&cipher_text, &key_letters)?;
            let crypto_time = crypto_start.elapsed();
            let total_time = total_start.elapsed();

            if cli.verbose {
                println!("cipher: {}", cipher_text);
                println!("key:    {}", key_letters.iter().collect::<String>());
                println!("plain:  {}", plain);
            } else {
                println!("{}", plain);
            }

            print_timings(parse_time, prep_time, crypto_time, total_time);
        }
    }

    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {}", err);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modern_cipher_round_trips_letters_and_literals() {
        let plain = "Attack at dawn 123!";
        let key_letters = normalize_key("SECRET").unwrap();

        let mut enc_rng = StdRng::seed_from_u64(11);
        let cipher = encrypt(plain, &key_letters, &mut enc_rng).unwrap();

        assert!(cipher.chars().all(|ch| ch.is_ascii_digit()));
        assert!(matches!(
            parse_ciphertext_with_key(&cipher, &key_letters).unwrap(),
            CipherInput::ModernTokens { .. }
        ));
        assert_eq!(decrypt(&cipher, &key_letters).unwrap(), "ATTACK AT DAWN 123!");
    }

    #[test]
    fn legacy_ciphertext_still_decrypts() {
        let cipher = "9999999999";
        let key = normalize_key(
            "JJJJGGJGJJ",
        )
        .unwrap();

        assert_eq!(decrypt(cipher, &key).unwrap(), "C".repeat(cipher.len()));
    }

    #[test]
    fn repeated_c_does_not_collapse_to_single_digit_anymore() {
        let plain = "C".repeat(64);
        let key = normalize_key(&"J".repeat(plain.len())).unwrap();
        let mut rng = StdRng::seed_from_u64(23);
        let cipher = encrypt(&plain, &key, &mut rng).unwrap();

        assert!(cipher.chars().all(|ch| ch.is_ascii_digit()));
        assert_eq!(cipher.len(), 175);

        let body = match parse_ciphertext_with_key(&cipher, &key).unwrap() {
            CipherInput::ModernPackedLetters { body, .. } => body,
            _ => panic!("expected modern ciphertext"),
        };

        let mut seen = [false; 10];
        for ch in body.chars() {
            if ch.is_ascii_digit() {
                seen[ch.to_digit(10).unwrap() as usize] = true;
            }
        }

        assert!(seen.into_iter().filter(|seen_digit| *seen_digit).count() > 1);
        assert_eq!(decrypt(&cipher, &key).unwrap(), plain);
    }

    #[test]
    fn tampering_modern_ciphertext_is_detected() {
        let key = normalize_key("SECRET").unwrap();
        let mut rng = StdRng::seed_from_u64(99);
        let cipher = encrypt("HELLO", &key, &mut rng).unwrap();
        let mut tampered = cipher.into_bytes();
        tampered[10] = if tampered[10] == b'9' { b'0' } else { tampered[10] + 1 };
        let tampered = String::from_utf8(tampered).unwrap();

        assert!(decrypt(&tampered, &key).is_err());
    }

    #[test]
    fn random_key_generation_is_plaintext_independent() {
        let mut rng_a = StdRng::seed_from_u64(5);
        let mut rng_b = StdRng::seed_from_u64(5);
        let key_a = generate_random_key(16, &mut rng_a).unwrap();
        let key_b = generate_random_key(16, &mut rng_b).unwrap();

        assert_eq!(key_a, key_b);
    }
}
