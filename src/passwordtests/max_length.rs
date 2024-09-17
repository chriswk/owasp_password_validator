use crate::PasswordTest;

pub struct MaxLengthTest {
    pub max_length: usize,
}

impl PasswordTest for MaxLengthTest {
    fn test(&self, password: &str) -> Result<(), String> {
        if password.len() > self.max_length {
            Err(format!(
                "Password must be at most {} characters long",
                self.max_length
            ))
        } else {
            Ok(())
        }
    }
}
