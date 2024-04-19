use std::error::Error;
use std::io::{self, Read, Write};
use std::io::ErrorKind;
use std::iter::repeat;
use std::fs::File;
use crypto::aead::AeadDecryptor;
use crypto::aes_gcm::AesGcm;
use walkdir::WalkDir;
use std::env;


pub fn decrypt_file(input_file: &str, output_file: &str, password: &str) -> Result<(), Box<dyn Error>> {
    let mut input_file = File::open(input_file)?;
    let mut encrypted_data = String::new();
    input_file.read_to_string(&mut encrypted_data)?;

    let decrypted_data = decrypt(&encrypted_data, password)?;
    let mut output_file = File::create(output_file)?;
    output_file.write_all(&decrypted_data)?;

    Ok(())
}

pub fn decrypt(iv_data_mac: &str, key: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let (iv, data, mac) = split_iv_data_mac(iv_data_mac)?;
    let key = get_valid_key(key);

    let key_size = crypto::aes::KeySize::KeySize128;

    // I don't use the aad for verification. aad isn't encrypted anyway, so it's just specified
    // as &[].
    let mut decipher = AesGcm::new(key_size, &key, &iv, &[]);

    // create a list where the decoded data will be saved. dst is transformed in place. It must be exactly the same
    // size as the encrypted data
    let mut dst: Vec<u8> = repeat(0).take(data.len()).collect();
    let result = decipher.decrypt(&data, &mut dst, &mac);

    if result {
        println!("Successful decryption");
    }
    println!("\nDecrypted data: {}", std::str::from_utf8(&dst).unwrap());

    Ok(dst)
}

fn split_iv_data_mac(orig: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let split: Vec<&str> = orig.split('/').into_iter().collect();

    if split.len() != 3 {
        return Err(Box::new(io::Error::from(ErrorKind::Other)));
    }
    let iv_res = hex::decode(split[0]);
    if iv_res.is_err() {
        return Err(Box::new(io::Error::from(ErrorKind::Other)));
    }
    let iv = iv_res.unwrap();

    let data_res = hex::decode(split[1]);
    if data_res.is_err() {
        return Err(Box::new(io::Error::from(ErrorKind::Other)));
    }
    let data = data_res.unwrap();

    let mac_res = hex::decode(split[2]);
    if mac_res.is_err() {
        return Err(Box::new(io::Error::from(ErrorKind::Other)));
    }
    let mac = mac_res.unwrap();

    Ok((iv, data, mac))
}

/// gets a valid key. This must be exactly 16 bytes. if less than 16 bytes, it will be padded with 0.
/// If more than 16 bytes, it will be truncated
fn get_valid_key(key: &str) -> Vec<u8> {
    let mut bytes = key.as_bytes().to_vec();
    if bytes.len() < 16 {
        for _j in 0..(16 - bytes.len()) {
            bytes.push(0x00);
        }
    } else if bytes.len() > 16 {
        bytes = bytes[0..16].to_vec();
    }

    bytes
}

fn decrypt_directory_recursive(directory: &str, password: &str) -> Result<(), Box<dyn Error>> {
    for entry in WalkDir::new(directory).follow_links(true) {
        let entry = entry?;
        if entry.file_type().is_file() {
            let input_file_path = entry.path();
            let output_file_path = entry.path();
            decrypt_file(
                input_file_path.to_str().unwrap(),
                output_file_path.to_str().unwrap(),
                password,
            )?;
        }
    }
    Ok(())
}

fn main() {
    println!("Welcome to the decryption software for the [PLACEHOLDER] ransomware software");
    // Get the command-line arguments
    let args: Vec<String> = env::args().collect();

    let password: &str = &args[1];
    let directory: &str = &args[2];

    //  Decrypt directory
    if let Err(err) = decrypt_directory_recursive(directory, password) {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    }
}
