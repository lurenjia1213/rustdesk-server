use hbb_common::tokio;
use hbbs::jwt;

#[test]
fn test_generate_token() {
    std::env::set_var("RUSTDESK_API_JWT_KEY", "testjwt");
    let token = jwt::generate_token(1, 3600).unwrap();
    println!("Generated Token: {}", token);
    assert!(!token.is_empty(), "Generated token should not be empty");
}

#[tokio::test]
async fn test_verify_token() {
    std::env::set_var("RUSTDESK_API_JWT_KEY", "testjwt");
    let token = jwt::generate_token(1, 2).unwrap();
    println!(
        "Token : {:?}, now: {:?}",
        token,
        chrono::Utc::now().timestamp()
    );

    let result = jwt::verify_token(&token);
    println!("Token Verification Result: {:?}", result);
    assert!(result.is_ok(), "Token should be valid");

    // 验证 claims 字段可访问
    let claims = result.unwrap();
    assert_eq!(claims.user_id, 1);
}

#[tokio::test]
async fn test_verify_expired_token() {
    std::env::set_var("RUSTDESK_API_JWT_KEY", "testjwt");
    // Generate a token already expired by 120 seconds.
    // jsonwebtoken v8 defaults to a 60 s leeway, so -1 s is not enough.
    let token = jwt::generate_token(1, -120).unwrap();

    let result = jwt::verify_token(&token);
    assert!(result.is_err(), "Expired token should fail verification");
    assert!(
        result.unwrap_err().contains("Token verification failed"),
        "Error should mention verification failure"
    );
}
