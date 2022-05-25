use base64::decode_config;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut token_bytes = get_token().await?;

    let client = reqwest::Client::new();

    // 最後の16バイトブロックを全て\x00にして送信する
    let zero_byte_count = 16;
    token_bytes.truncate(token_bytes.len() - zero_byte_count);
    for _ in 0..16 {
        token_bytes.push(0);
    }

    for i in 0..=255 {
        //token_bytes.pop();
        //token_bytes.push(i);
        token_bytes[31] = i;
        let result = submit_token(&client, token_bytes.clone()).await?;
        if result != "decrypt error" {
            println!("{}:{}:{:?}", token_bytes.len(), i, &result);
        }
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
