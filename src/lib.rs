use passwordtests::PasswordTest;

mod passwordtests;

#[derive(Debug, Clone)]
pub struct TestConfig {
    /// Toggles the "passphrase" mechanism on and off.
    /// If set to false, the strength-checker will abandon the notion of "passphrases"
    /// and will subject all passwords to the same complexity requirements
    pub allow_passphrase: bool,
    /// constraint on a passowrd's maximum length
    pub max_length: usize,
    /// constraint on a password's minimum length
    pub min_length: usize,
    /// minimum length a password needs to achieve in order to be considered a "passphrase"
    /// (and thus exempted from the optional complexity tests by default)
    pub min_phrase_length: usize,

    /// Minimum number of optional tests that must be passed in order for a password to be considered "strong"
    /// By default (per the OWASP guidelines), four optional
    pub min_optional_tests_to_pass: usize,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            allow_passphrase: true,
            max_length: 128,
            min_length: 10,
            min_phrase_length: 20,
            min_optional_tests_to_pass: 4,
        }
    }
}

pub struct OwaspTester {
    pub config: TestConfig,
    pub required_tests: Vec<Box<dyn PasswordTest>>,
    pub optional_tests: Vec<Box<dyn PasswordTest>>,
}

impl Default for OwaspTester {
    fn default() -> Self {
        Self::new(TestConfig::default())
    }
}
impl OwaspTester {
    pub fn new(config: TestConfig) -> Self {
        OwaspTester {
            config: config.clone(),
            required_tests: vec![
                Box::new(passwordtests::min_length::MinLength {
                    min_length: config.min_length,
                }),
                Box::new(passwordtests::max_length::MaxLengthTest {
                    max_length: config.max_length,
                }),
                Box::new(passwordtests::max_repeating_chars::MaxRepeatingChars {
                    max_repeating_chars: 3,
                }),
            ],
            optional_tests: vec![
                Box::new(passwordtests::has_lowercase_letters::HasLowercaseLetters {}),
                Box::new(passwordtests::has_uppercase_letters::HasUppercaseLetters {}),
                Box::new(passwordtests::min_digits::MinDigits { min_digits: 1 }),
                Box::new(passwordtests::has_special_chars::HasSpecialChars {}),
            ],
        }
    }

    pub fn validate_password(&self, password: &str) -> Result<(), FailedTestResult> {
        let mut errors = vec![];
        let mut required_test_errors = vec![];
        let mut optional_test_errors = vec![];
        let mut optional_tests_passed = 0;
        let mut strong = true;
        let mut is_passphrase = false;
        for test in &self.required_tests {
            match test.test(password) {
                Ok(_) => {}
                Err(e) => {
                    errors.push(e.clone());
                    required_test_errors.push(e);
                    strong = false;
                }
            }
        }

        if self.config.allow_passphrase && password.len() > self.config.min_phrase_length {
            is_passphrase = true;
        } else {
            for test in &self.optional_tests {
                match test.test(password) {
                    Ok(_) => {
                        optional_tests_passed += 1;
                    }
                    Err(e) => {
                        errors.push(e.clone());
                        optional_test_errors.push(e);
                        strong = false;
                    }
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(FailedTestResult {
                errors,
                required_test_errors,
                optional_test_errors,
                is_passphrase,
                strong,
                optional_tests_passed,
            })
        }
    }
}

#[derive(Debug, Clone)]
pub struct FailedTestResult {
    pub errors: Vec<String>,
    pub required_test_errors: Vec<String>,
    pub optional_test_errors: Vec<String>,
    pub is_passphrase: bool,
    pub strong: bool,
    pub optional_tests_passed: u32,
}

#[cfg(test)]
mod tests {
    use crate::{OwaspTester, TestConfig};

    #[test]
    pub fn min_length_should_be_enforced() {
        let owasp_tester = OwaspTester::default();
        let result = owasp_tester.validate_password("L0^eSex");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.required_test_errors.len(), 1);
        assert!(!err.strong);
        assert!(!err.is_passphrase);
        assert!(err.optional_test_errors.is_empty())
    }

    #[test]
    pub fn max_length_should_be_enforced() {
        let owasp_tester = OwaspTester::default();
        let result = owasp_tester.validate_password(&"L0^eSex".repeat(50));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.required_test_errors.len(), 1);
        assert!(!err.strong);
        assert!(err.optional_test_errors.is_empty())
    }

    #[test]
    pub fn repeating_characters_should_be_enforced() {
        let owasp_tester = OwaspTester::default();
        let result = owasp_tester.validate_password("L0^eSexxxx");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.required_test_errors.len(), 1);
        assert!(!err.strong);
        assert!(err.optional_test_errors.is_empty())
    }

    #[test]
    pub fn valid_password_should_be_recognized_as_such() {
        let owasp_tester = OwaspTester::default();
        let result = owasp_tester.validate_password("L0veSexSecre+God");
        assert!(result.is_ok());
    }

    #[test]
    pub fn must_have_at_least_one_lowercase_character() {
        let owasp_tester = OwaspTester::default();
        let result = owasp_tester.validate_password("L0VESSEXSECRE+GOD");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.optional_test_errors.len(), 1);
        assert!(!err.strong);
        assert!(err.required_test_errors.is_empty());
    }

    #[test]
    pub fn must_have_at_least_one_uppercase_character() {
        let owasp_tester = OwaspTester::default();
        let result = owasp_tester.validate_password("l0vesexsecre+god");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.optional_test_errors.len(), 1);
        assert!(!err.strong);
        assert!(err.required_test_errors.is_empty());
    }

    #[test]
    pub fn at_least_one_digit_is_required() {
        let owasp_tester = OwaspTester::default();
        let result = owasp_tester.validate_password("LoveSexSecre+tGod");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.optional_test_errors.len(), 1);
        assert!(!err.strong);
        assert!(err.required_test_errors.is_empty());
    }

    #[test]
    pub fn at_least_one_special_character_should_be_required() {
        let owasp_tester = OwaspTester::default();
        let result = owasp_tester.validate_password("L0veSexSecreGod");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.optional_test_errors.len(), 1);
        assert!(!err.strong);
        assert!(err.required_test_errors.is_empty());
    }

    #[test]
    pub fn the_appropriate_characters_should_be_recognized_as_special() {
        let mut specials = " !\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~".chars();
        let owasp_tester = OwaspTester::default();
        assert!(specials.all(|special_char| {
            match owasp_tester.validate_password(&format!("L0veSexSecre{}God", special_char)) {
                Ok(()) => true,
                Err(e) => {
                    eprintln!("{e:?}");
                    false
                }
            }
        }))
    }

    #[test]
    pub fn passphrases_should_be_subject_to_optional_tests_by_default() {
        let owasp_tester = OwaspTester::default();
        let result = owasp_tester.validate_password("Hack the planet! Hack the planet!");
        assert!(result.is_ok());
    }

    #[test]
    pub fn passphrases_can_be_configured_to_be_subject_to_optional_tests_by_default() {
        let owasp_config = TestConfig {
            allow_passphrase: false,
            ..Default::default()
        };
        let owasp_tester = OwaspTester::new(owasp_config);
        let result = owasp_tester.validate_password("Hack the planet! Hack the planet!");
        assert!(result.is_err());
    }
}
