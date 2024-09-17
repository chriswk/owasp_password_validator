use crate::PasswordTest;

pub struct MinDigits {
    pub min_digits: usize,
}

impl PasswordTest for MinDigits {
    fn test(&self, password: &str) -> Result<(), String> {
        if password.chars().filter(|f| f.is_ascii_digit()).count() < self.min_digits {
            Err(format!(
                "Password must contain at least {} digits",
                self.min_digits
            ))
        } else {
            Ok(())
        }
    }
}
