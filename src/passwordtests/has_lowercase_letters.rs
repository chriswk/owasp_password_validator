use crate::PasswordTest;

pub struct HasLowercaseLetters {}

impl PasswordTest for HasLowercaseLetters {
    fn test(&self, password: &str) -> Result<(), String> {
        if password.chars().all(|f| !f.is_ascii_lowercase()) {
            Err("Password must contain at least one lowercase letter".to_string())
        } else {
            Ok(())
        }
    }
}
