use crate::PasswordTest;

pub struct MinLength {
    pub min_length: usize,
}

impl PasswordTest for MinLength {
    fn test(&self, password: &str) -> Result<(), String> {
        if password.len() < self.min_length {
            Err(format!(
                "Password must be at least {} characters long",
                self.min_length
            ))
        } else {
            Ok(())
        }
    }
}
