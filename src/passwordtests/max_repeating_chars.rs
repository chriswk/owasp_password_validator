use crate::PasswordTest;

pub struct MaxRepeatingChars {
    pub max_repeating_chars: usize,
}

impl PasswordTest for MaxRepeatingChars {
    fn test(&self, password: &str) -> Result<(), String> {
        if password.chars().any(|c| {
            password
                .chars()
                .collect::<Vec<char>>()
                .windows(self.max_repeating_chars)
                .any(|w| w.iter().all(|x| *x == c))
        }) {
            Err(format!(
                "Password must not contain {} or more repeating characters",
                self.max_repeating_chars
            ))
        } else {
            Ok(())
        }
    }
}
