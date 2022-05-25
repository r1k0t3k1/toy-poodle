use base64::decode_config;

const BLOCK_SIZE: usize = 16;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut token_bytes = get_token().await?;
    let token_backup = token_bytes.clone();

    let client = reqwest::Client::new();

    let block_count = token_bytes.len() / BLOCK_SIZE;
    let start = (block_count-2)*BLOCK_SIZE;
    let end = (block_count-1)*BLOCK_SIZE;

    // 最後から二つ目の16バイトブロックを全て\x00にして送信する
    for i in start..end {
        token_bytes[i] = 0;
    }

    let mut exposure_bytes: Vec<u8> = vec![];

    // 最後から二つ目のブロックのブロックサイズ分ケツから回す(16回)
    for (b_count, b_i) in (start..end).rev().enumerate() {
        for i in 0..=255 {
            token_bytes[b_i] = i;
            let mut clone = token_bytes.clone();
            for (c, i) in (b_i..end).rev().enumerate() {
                clone[i] ^= (c + 1) as u8;
                clone[i] ^= (exposure_bytes.len() + 1) as u8;
            }
            let result = submit_token(&client, clone.clone()).await?;
            if result != "decrypt error" {
                exposure_bytes.insert(0, i ^ (b_count+1) as u8);
                println!("exposure bytes:{:?}", exposure_bytes);
                break;
            }
        }
    }

    for (i,v) in (start..end).enumerate() {
        print!("{},", exposure_bytes[i] ^ token_backup[v]);
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
