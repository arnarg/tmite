use std::time::Duration;

use iroh::endpoint::{RecvStream, SendStream};
use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

pub use tmite_proto::frame::{self, FrameError};
pub use tmite_proto::limits::MAX_CONTROL_FRAME;

#[derive(Debug, Error)]
pub enum FrameIoError {
    #[error("timed out waiting for frame")]
    Timeout,
    #[error("stream closed before frame completed")]
    Eof,
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("stream io error: {0}")]
    Io(std::io::Error),
}

/// Reads one complete length-prefixed frame with a total deadline.
pub async fn read_frame<T: DeserializeOwned>(
    recv: &mut RecvStream,
    deadline: Duration,
) -> Result<(u8, T), FrameIoError> {
    async fn read(recv: &mut RecvStream) -> Result<(u8, Vec<u8>), FrameIoError> {
        let stream_err = |e: std::io::Error| FrameIoError::Io(e);
        let mut header = [0u8; 5];
        recv.read_exact(&mut header)
            .await
            .map_err(|e| stream_err(std::io::Error::other(e.to_string())))?;
        let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        if len > MAX_CONTROL_FRAME {
            return Err(FrameIoError::Frame(FrameError::TooLarge {
                len,
                max: frame::MAX_CONTROL_FRAME,
            }));
        }
        let mut payload = vec![0u8; len];
        recv.read_exact(&mut payload)
            .await
            .map_err(|e| stream_err(std::io::Error::other(e.to_string())))?;
        Ok((header[0], payload))
    }
    let (msg_type, payload) = tokio::time::timeout(deadline, read(recv))
        .await
        .map_err(|_| FrameIoError::Timeout)??;
    let parsed: T = frame::decode_payload(&payload)?;
    Ok((msg_type, parsed))
}

/// Writes one length-prefixed frame.
pub async fn write_frame<T: Serialize>(
    send: &mut SendStream,
    msg_type: u8,
    payload: &T,
) -> Result<(), FrameIoError> {
    let bytes = frame::encode_frame(msg_type, payload)?;
    send.write_all(&bytes)
        .await
        .map_err(|e| FrameIoError::Io(std::io::Error::other(e.to_string())))?;
    Ok(())
}

/// Reads one frame and requires it to be of the given type.
pub async fn expect_frame<T: DeserializeOwned>(
    recv: &mut RecvStream,
    msg_type: u8,
    deadline: Duration,
) -> Result<T, FrameIoError> {
    let (t, payload) = read_frame::<T>(recv, deadline).await?;
    if t != msg_type {
        return Err(FrameIoError::Frame(FrameError::UnexpectedType(t)));
    }
    Ok(payload)
}
