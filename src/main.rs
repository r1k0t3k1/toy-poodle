use base64::{decode_config, URL_SAFE};
use std::io::Error;

const BLOCK_SIZE: usize = 16;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
//    println!("----- start decryption attack-----");
//    let (plain_text, iv) = decription_attck().await?;
//    println!("[+] plain text:{}", plain_text);
//    println!("[+] iv: {:?}", iv);
//    println!("----- finish decryption attack-----\n");
//
        println!("----- start encryption attack-----");
        let mut tampered_plain_text = b"{\"id\":9,\"admin\":false}".to_vec();
        let result = encription_attack(&mut tampered_plain_text).await?;
        println!("[+] Result: {}", result);
        println!("----- finish encryption attack-----");
    Ok(())
}

// String  => plain text
// Vec<u8> => IV
async fn decription_attck() -> Result<(String, Vec<u8>), Box<dyn std::error::Error>> {
    let token_bytes = get_token().await?;

    let block_count = token_bytes.len() / BLOCK_SIZE;

    let client = reqwest::Client::new();
    let mut exposure_bytes = vec![];

    // 先頭はIVなので処理しない
    for mod_block_i in (1..block_count).rev() {
        let mod_block_start_addr = (mod_block_i - 1) * BLOCK_SIZE;
        let mod_block_end_addr = mod_block_start_addr + BLOCK_SIZE - 1;

        let mut working_bytes = token_bytes.clone();

        working_bytes.truncate(mod_block_end_addr + BLOCK_SIZE + 1);
        // パディングチェックが二回OKにならないように
        for i in mod_block_start_addr..=mod_block_end_addr {
            working_bytes[i] = 0;
        }

        for (count, current_addr) in (mod_block_start_addr..=mod_block_end_addr)
            .rev()
            .enumerate()
        {
            let padding_count = (count + 1) as u8;

            for b in 0..=255 {
                let mut work_clone = working_bytes.clone();
                work_clone[current_addr] = b;
                if count != 0 {
                    for i in current_addr + 1..=mod_block_end_addr {
                        work_clone[i] ^= padding_count;
                    }
                }

                let result = submit_token(&client, work_clone.clone()).await?;
                if result != "decrypt error" {
                    exposure_bytes.insert(0, b ^ padding_count as u8);
                    working_bytes[current_addr] = b ^ padding_count as u8;
                    println!("exposure bytes:{:?}", exposure_bytes);
                    break;
                }
            }
        }
    }
    let mut plain_bytes = vec![];
    for i in 0..token_bytes.len() - BLOCK_SIZE {
        plain_bytes.push(exposure_bytes[i] ^ token_bytes[i]);
    }
    let plain_text = String::from_utf8(plain_bytes).unwrap();

    let mut iv = vec![];
    for i in 0..16 {
        // c0(iv) = Dec(c1) ^ m1
        iv.push(exposure_bytes[i] ^ token_bytes[i] ^ exposure_bytes[i]);
    }
    Ok((plain_text, iv))
}

// String  => Response body
async fn encription_attack(
    tampered_plain_text: &mut Vec<u8>,
) -> Result<String, Box<dyn std::error::Error>> {
    let padded_tamper = padding(tampered_plain_text).unwrap();
    let mut token_bytes = vec![0_u8; padded_tamper.len() + BLOCK_SIZE];
    let block_count = token_bytes.len() / BLOCK_SIZE;

    let client = reqwest::Client::new();

    //    // 先頭はIVなので処理しない
    for mod_block_i in (1..block_count).rev() {
        let mod_block_start_addr = (mod_block_i - 1) * BLOCK_SIZE;
        let mod_block_end_addr = mod_block_start_addr + BLOCK_SIZE - 1;

        let mut working_bytes = token_bytes.clone();
        working_bytes.truncate(mod_block_end_addr + BLOCK_SIZE + 1);

        for (count, current_addr) in (mod_block_start_addr..=mod_block_end_addr)
            .rev()
            .enumerate()
        {
            let padding_count = (count + 1) as u8;

            for b in 0..=255 {
                let mut work_clone = working_bytes.clone();
                work_clone[current_addr] = b;
                if count != 0 {
                    for i in current_addr + 1..=mod_block_end_addr {
                        work_clone[i] ^= padding_count;
                    }
                }

                let result = submit_token(&client, work_clone.clone()).await?;
                if result != "decrypt error" {
                    working_bytes[current_addr] = b ^ padding_count as u8;
                    token_bytes[current_addr] = working_bytes[current_addr] ^ padded_tamper[current_addr];
                    println!("exposure bytes:{:?}", working_bytes);
                    break;
                }
            }
        }
    }
    
    Ok(base64::encode_config(token_bytes, URL_SAFE))
}
fn padding(text: &mut Vec<u8>) -> Result<&mut Vec<u8>, std::io::Error> {
    if text.len() == 0 {
        return Err(Error::new(
            std::io::ErrorKind::InvalidInput,
            "text length must be greater than 0",
        ));
    }
    let padding_count = (BLOCK_SIZE - text.len() % BLOCK_SIZE) as u8;

    for _ in 0..padding_count {
        text.push(padding_count);
    }
    Ok(text)
}

async fn get_token() -> Result<Vec<u8>, reqwest::Error> {
    let get_token_url = "http://localhost:4567/token";

    let token = reqwest::get(get_token_url).await?.text().await?;

    // if base64 decode is failed, panic!
    Ok(decode_config(token.clone(), base64::URL_SAFE).unwrap())
}

async fn submit_token(
    client: &reqwest::Client,
    token_bytes: Vec<u8>,
) -> Result<String, reqwest::Error> {
    let submit_token_url = "http://localhost:4567/check?token=";

    let token_b64 = base64::encode_config(token_bytes.clone(), base64::URL_SAFE);
    Ok(client
        .get(format!("{}{}", submit_token_url, token_b64))
        .send()
        .await?
        .text()
        .await?)
}
