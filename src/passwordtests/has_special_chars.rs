use super::PasswordTest;

pub struct HasSpecialChars {}

const SPECIAL_CHARS: [char; 33] = [
    '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=',
    '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~', ' ',
];

impl PasswordTest for HasSpecialChars {
    fn test(&self, password: &str) -> Result<(), String> {
        if password.chars().all(|f| !SPECIAL_CHARS.contains(&f)) {
            Err(format!(
                "[{password}] Password must contain at least one special character"
            ))
        } else {
            Ok(())
        }
    }
}
