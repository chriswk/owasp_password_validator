use super::PasswordTest;

pub struct HasUppercaseLetters {}

impl PasswordTest for HasUppercaseLetters {
    fn test(&self, password: &str) -> Result<(), String> {
        if password.chars().all(|f| !f.is_ascii_uppercase()) {
            Err("Password must contain at least one uppercase letter".to_string())
        } else {
            Ok(())
        }
    }
}
