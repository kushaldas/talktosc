//! Module Errors for the talktosc project
//!

use thiserror::Error;

/// TalktoSCError enumarates all the possible errors from the library.
#[derive(Error, Debug)]
pub enum TalktoSCError {
     /// When we failed to create a context to talk to the smartcard.
     #[error("Failed to create a context {0}")]
    ContextError(String),
    /// When we fail to list the readers in the system.
    #[error("Failed to list readers: {0}")]
    ReaderError(String),
    /// When no card reader is attached to the system.
    #[error("No reader is connected.")]
    MissingReaderError,
    /// When no smartcard is attached to the reader.
    #[error("No smartcard is attached to the reader.")]
    MissingSmartCardError,
    /// When we can not connect to the smartcard.
    #[error("Failed to connect to the card: {0}")]
    SmartCardConnectionError(String)
}
