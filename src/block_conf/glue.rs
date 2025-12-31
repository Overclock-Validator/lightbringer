use std::{io::IoSlice, sync::Arc};

use anyhow::{Result, anyhow};
use futures::{AsyncReadExt, AsyncWriteExt};
use glommio::net::TcpStream;
use rustls::{ClientConfig, ClientConnection};
use rustls_async::{TlsConnector, TlsStream};
use rustls_platform_verifier::ConfigVerifierExt;

pub enum MaybeTlsStream {
    Tls(Box<TlsStream<ClientConnection, TcpStream>>),
    Plain(TcpStream),
}

impl MaybeTlsStream {
    pub async fn new(is_tls: bool, host: &str, port: u16) -> Result<Self> {
        let tcp_stream = TcpStream::connect((host, port))
            .await
            .map_err(|_| anyhow!("Failed to connect to {host}:{port}"))?;

        if is_tls {
            let tls_config = ClientConfig::with_platform_verifier()?;
            let server_name = host.to_string().try_into()?;
            let connector = TlsConnector::new(Arc::new(tls_config), server_name)?;
            let mut stream = connector.connect(tcp_stream);
            stream.flush().await?;
            Ok(Self::Tls(Box::new(stream)))
        } else {
            Ok(Self::Plain(tcp_stream))
        }
    }
}

impl wtx::stream::StreamReader for MaybeTlsStream {
    async fn read(&mut self, bytes: &mut [u8]) -> wtx::Result<usize> {
        match self {
            MaybeTlsStream::Tls(tls_stream) => tls_stream.read(bytes).await.map_err(|e| e.into()),
            MaybeTlsStream::Plain(tcp_stream) => tcp_stream.read(bytes).await.map_err(|e| e.into()),
        }
    }
}

impl wtx::stream::StreamWriter for MaybeTlsStream {
    async fn write_all(&mut self, bytes: &[u8]) -> wtx::Result<()> {
        match self {
            MaybeTlsStream::Tls(tls_stream) => {
                tls_stream.write_all(bytes).await.map_err(|e| e.into())
            }
            MaybeTlsStream::Plain(tcp_stream) => {
                tcp_stream.write_all(bytes).await.map_err(|e| e.into())
            }
        }
    }

    async fn write_all_vectored(&mut self, bytes: &[&[u8]]) -> wtx::Result<()> {
        match bytes {
            [] => Ok(()),
            [single] => self.write_all(single).await,
            _ => {
                let mut buffer = [IoSlice::new(&[]); 8];
                if bytes.len() > buffer.len() {
                    return Err(wtx::Error::VectoredWriteOverflow);
                }
                for (elem, io_slice) in bytes.iter().zip(&mut buffer) {
                    *io_slice = IoSlice::new(elem);
                }
                let io_slices = buffer.get(..bytes.len()).unwrap_or_default();
                _ = match self {
                    MaybeTlsStream::Tls(tls_stream) => tls_stream.write_vectored(io_slices).await?,
                    MaybeTlsStream::Plain(tcp_stream) => {
                        tcp_stream.write_vectored(io_slices).await?
                    }
                };
                Ok(())
            }
        }
    }
}
