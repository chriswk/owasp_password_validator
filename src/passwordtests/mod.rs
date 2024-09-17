pub(crate) mod has_lowercase_letters;
pub(crate) mod has_special_chars;
pub(crate) mod has_uppercase_letters;
pub(crate) mod max_length;
pub(crate) mod max_repeating_chars;
pub(crate) mod min_digits;
pub(crate) mod min_length;
pub trait PasswordTest {
    fn test(&self, password: &str) -> Result<(), String>;
}
