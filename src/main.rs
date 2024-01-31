use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use anyhow::anyhow;
use clap::Parser;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
struct CryptOptions {
    /// Path to the input file
    #[arg(short, long)]
    file: PathBuf,

    /// Password
    #[arg(short, long)]
    password: String,
}

/// Utility for encrypting and decrypting files with passpharse
#[derive(Parser, Debug)]
enum Args {
    /// Encrypt file
    Encrypt(CryptOptions),
    /// Decrypt file
    Decrypt(CryptOptions),
}

fn hash_password(password: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();

    hasher.update(password.as_bytes());

    let result = hasher.finalize();
    result.to_vec()
}

fn encrypt(file: impl AsRef<Path>, passphrase: &str) -> anyhow::Result<()> {
    let passphrase = &hash_password(passphrase)[..32];
    let key = Key::<Aes256Gcm>::from_slice(&passphrase);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(&passphrase[..12]);

    let mut file = OpenOptions::new().read(true).write(true).open(file)?;
    let metadata = file.metadata()?;
    let mut read_buffer = Vec::with_capacity(metadata.len() as usize);

    file.read_to_end(&mut read_buffer)?;
    let ciphertext = cipher
        .encrypt(&nonce, read_buffer.as_ref())
        .map_err(|_| anyhow!("Failed to encrypt the file"))?;
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&ciphertext)?;

    Ok(())
}

fn decrypt(file: impl AsRef<Path>, passphrase: &str) -> anyhow::Result<()> {
    let passphrase = &hash_password(passphrase)[..32];
    let passphrase = Key::<Aes256Gcm>::from_slice(passphrase);
    let cipher = Aes256Gcm::new(&passphrase);
    let nonce = Nonce::from_slice(&passphrase[..12]);

    let mut file = OpenOptions::new().read(true).write(true).open(file)?;

    let metadata = file.metadata()?;
    let mut read_buffer = Vec::with_capacity(metadata.len() as usize);

    file.read_to_end(&mut read_buffer)?;
    let decrypted = cipher
        .decrypt(&nonce, read_buffer.as_ref())
        .map_err(|_| anyhow!("Failed to decrypt the file"))?;

    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_at(&decrypted, 0)?;

    Ok(())
}

fn main() {
    let args = Args::parse();

    match args {
        Args::Encrypt(args) => {
            if let Ok(_) = encrypt(args.file, &args.password) {
                println!("Encryption successful!");
            } else {
                println!("Encryption failed!");
            }
        }
        Args::Decrypt(args) => {
            if let Ok(_) = decrypt(args.file, &args.password) {
                println!("Decryption successful!");
            } else {
                println!("Decryption failed!");
            }
        }
    }
}

#[test]
fn crypt() {
    let data = b"dataratata";
    let pass = "cool password";
    let passphrase = &hash_password(pass)[..32];
    let key = Key::<Aes256Gcm>::from_slice(passphrase);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&passphrase[..12]);
    let encrypted = cipher.encrypt(&nonce, data.as_ref()).unwrap();
    let decrypted = cipher.decrypt(&nonce, encrypted.as_ref()).unwrap();
    assert_eq!(
        String::from_utf8(data.to_vec()).unwrap(),
        String::from_utf8(decrypted).unwrap()
    );
}
