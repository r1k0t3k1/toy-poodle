use base64::{decode_config, encode_config};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let get_token_url = "http://localhost:4567/token";
    let submit_token_url = "http://localhost:4567/check";

    let client = reqwest::Client::new();
    let token_resp = client.get(get_token_url)
        .send()
        .await?;

    let token: String = token_resp.text().await?;
    let mut token_bytes: Vec<u8> = base64::decode_config(token.clone(), base64::URL_SAFE).unwrap() ;
    
    println!("{:?}", &token);

    let submit_resp = client
        .get(submit_token_url)
        .query(&[("token",token.as_str())])
        .send()
        .await?;
    

    // 最後の16バイトブロックを全て\x00にして送信する
    let zero_byte_count = 16;
    token_bytes.truncate(token_bytes.len() - zero_byte_count);
    for _ in 0..16 {
        token_bytes.push(0);
    }
    
    println!("{:?}", &token_bytes);

    for i in 0..255 {
        token_bytes.pop();
        token_bytes.push(i);
        let token_b64 = base64::encode_config(token_bytes.clone(), base64::URL_SAFE);
        let submit_resp = reqwest::get(format!("http://localhost:4567/check?token={token_b64}"))
        .await
        .unwrap();

        let body = submit_resp.text().await?;
        println!("{}:{:?}", i,&body);
    }
    Ok(())
}
