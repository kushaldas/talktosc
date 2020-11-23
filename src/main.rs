use rpassword;
use talktosc::*;

fn main() {
    let pass = rpassword::read_password_from_tty(Some("Password: ")).unwrap();
    entry(pass.into_bytes());
}
