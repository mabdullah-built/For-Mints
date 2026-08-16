//! `kairox clock` — reports timing information. Never modifies the system
//! clock.

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub fn run() {
    let now = OffsetDateTime::now_utc();
    println!(
        "System UTC time: {}",
        now.format(&Rfc3339).unwrap_or_else(|_| now.to_string())
    );
    println!("Unix timestamp: {}", now.unix_timestamp());
    println!();
    println!(
        "Note: Kairox reports UTC only and never displays an OS local-timezone\n\
         offset here, because looking one up from a multi-threaded process is\n\
         documented as unsound by the `time` crate. Convert the UTC value above\n\
         to your local timezone externally if needed."
    );
}
