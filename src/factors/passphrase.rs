use crate::factor::Factor;
use dialoguer::Password;

/// A passphrase encryption factor, based solely on user input.
pub struct PassphraseFactor;
impl Factor for PassphraseFactor {
    type Data = ();
    type Key = Vec<u8>;

    fn name() -> &'static str {
        "Passphrase"
    }
    fn create() -> (Self::Data, Self::Key) {
        let passphrase = Password::new()
            .with_prompt("Enter a passphrase")
            .interact()
            .unwrap();
        ((), passphrase.into_bytes())
    }
    fn derive(_: Self::Data) -> Self::Key {
        let passphrase = Password::new()
            .with_prompt("Enter the passphrase")
            .interact()
            .unwrap();
        passphrase.into_bytes()
    }
}
