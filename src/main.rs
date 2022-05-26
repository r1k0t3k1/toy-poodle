use base64::decode_config;

const BLOCK_SIZE: usize = 16;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
                    println!("exposure bytes:{:?}\n", exposure_bytes);
                    break;
                }
            }
        }
    }
    let mut plain_text = vec![];
    for i in 0..token_bytes.len() - BLOCK_SIZE {
        plain_text.push(exposure_bytes[i] ^ token_bytes[i]);
    }
    // plain text
    println!("{}", String::from_utf8(plain_text).unwrap());

    for i in 0..16 {
        // c0(iv) = Dec(c1) ^ m1
        print!(
            "{},",
            exposure_bytes[i] ^ token_bytes[i] ^ exposure_bytes[i]
        );
    }

    Ok(())
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
