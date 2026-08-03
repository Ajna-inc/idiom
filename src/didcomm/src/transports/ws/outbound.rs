//! WebSocket outbound transport
//!
//! Provides a `WsConnection` type that wraps a tokio-tungstenite WebSocket connection
//! for sending and receiving DIDComm messages over WebSocket.

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::SinkExt;
use futures_util::StreamExt;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::{
    connect_async, tungstenite::Message as WsMessage, MaybeTlsStream, WebSocketStream,
};

use crate::transports::{Result, TransportError};

/// A WebSocket read stream (the receiving half of a split WebSocket).
pub type WsReadStream = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

/// A WebSocket connection for sending DIDComm messages.
///
/// Wraps the write half of a split WebSocket stream. The read half is returned
/// separately from `connect()` so the caller can process incoming messages.
pub struct WsConnection {
    writer: Arc<Mutex<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, WsMessage>>>,
}

impl WsConnection {
    /// Connect to a WebSocket endpoint.
    ///
    /// Returns `(WsConnection, WsReadStream)` — the connection for sending messages
    /// and the read stream for receiving incoming frames.
    pub async fn connect(endpoint: &str) -> Result<(Self, WsReadStream)> {
        tracing::debug!("[WS] Connecting to {}", endpoint);

        let (ws_stream, _response) = connect_async(endpoint).await.map_err(|e| {
            TransportError::Connection(format!(
                "WebSocket connection to {} failed: {}",
                endpoint, e
            ))
        })?;

        tracing::debug!("[WS] Connected to {}", endpoint);

        let (writer, reader) = ws_stream.split();

        Ok((
            Self {
                writer: Arc::new(Mutex::new(writer)),
            },
            reader,
        ))
    }

    /// Send a packed DIDComm message over WebSocket as a text frame.
    pub async fn send(&self, message: &str) -> Result<()> {
        let mut writer = self.writer.lock().await;
        writer
            .send(WsMessage::Text(message.to_string()))
            .await
            .map_err(|e| TransportError::SendFailed(format!("WebSocket send failed: {}", e)))?;
        Ok(())
    }

    /// Send a DCX-style binary frame over WebSocket.
    ///
    /// Used by DCX's outbound transport (opcode `0x2`) so binary frames
    /// can coexist with text-frame DIDComm v2 on the same connection.
    pub async fn send_binary(&self, message: Vec<u8>) -> Result<()> {
        let mut writer = self.writer.lock().await;
        writer.send(WsMessage::Binary(message)).await.map_err(|e| {
            TransportError::SendFailed(format!("WebSocket binary send failed: {}", e))
        })?;
        Ok(())
    }

    /// Send a WebSocket protocol-level Ping frame. Used by the agent's
    /// keepalive loop (Fix 4A) to keep iOS/macOS from reclaiming the socket
    /// during quiet periods. The remote should respond with a Pong; the
    /// agent observes that pong via the read stream and treats it as
    /// connection activity.
    pub async fn send_ping(&self, payload: Vec<u8>) -> Result<()> {
        let mut writer = self.writer.lock().await;
        writer.send(WsMessage::Ping(payload)).await.map_err(|e| {
            TransportError::SendFailed(format!("WebSocket ping send failed: {}", e))
        })?;
        Ok(())
    }

    /// Close the WebSocket connection gracefully.
    pub async fn close(&self) -> Result<()> {
        let mut writer = self.writer.lock().await;
        writer
            .send(WsMessage::Close(None))
            .await
            .map_err(|e| TransportError::SendFailed(format!("WebSocket close failed: {}", e)))?;
        Ok(())
    }
}
