use color_eyre::Result as EyreResult;
use tracing::{info, instrument};
use tracing_subscriber::EnvFilter;

use futures::future;
use std::sync::Arc;
use thrussh::{client, ChannelId, Disconnect};
use thrussh_keys::key;

pub mod error {
    #[derive(thiserror::Error, Debug)]
    pub enum ClientError {
        #[error("Ssh error")]
        Ssh {
            #[from]
            source: thrussh::Error,
        },
        #[error("Ssh error")]
        SshKey {
            #[from]
            source: thrussh_keys::Error,
        },
        #[error("Ssh error")]
        Auth {
            #[from]
            source: thrussh::AgentAuthError,
        },
        #[error("IO Error")]
        IO {
            #[from]
            source: std::io::Error,
        },
    }
}

#[derive(Debug)]
struct Client {}

impl client::Handler for Client {
    type Error = error::ClientError;
    type FutureUnit = future::Ready<Result<(Self, client::Session), Self::Error>>;
    type FutureBool = future::Ready<Result<(Self, bool), Self::Error>>;

    #[instrument(level = "info")]
    fn finished_bool(self, b: bool) -> Self::FutureBool {
        future::ready(Ok((self, b)))
    }

    #[instrument(level = "info", skip(session))]
    fn finished(self, session: client::Session) -> Self::FutureUnit {
        future::ready(Ok((self, session)))
    }

    #[instrument(level = "info")]
    fn check_server_key(self, server_public_key: &key::PublicKey) -> Self::FutureBool {
        self.finished_bool(true)
    }

    #[instrument(level = "info", skip(session))]
    fn channel_open_confirmation(
        self,
        channel: ChannelId,
        max_packet_size: u32,
        window_size: u32,
        session: client::Session,
    ) -> Self::FutureUnit {
        self.finished(session)
    }

    #[instrument(level = "info", skip(session))]
    fn data(self, channel: ChannelId, data: &[u8], session: client::Session) -> Self::FutureUnit {
        info!("data on channel: {:?}", std::str::from_utf8(data));
        self.finished(session)
    }
}

#[tokio::main]
async fn main() -> EyreResult<()> {
    setup_logging()?;
    info!("Starting");

    let user_name = std::env::var("USER").unwrap();
    let password = std::env::var("TEST_PASSWORD").unwrap();

    let config = thrussh::client::Config::default();
    info!(?config);
    let config = Arc::new(config);
    let ssh_client = Client {};
    let mut session = thrussh::client::connect(config, "127.0.0.1:22", ssh_client).await?;
    let auth = session.authenticate_password(user_name, password).await?;

    info!("Loged in: {:?}", auth);

    let mut channel_direct = session
        .channel_open_direct_tcpip("localhost", 80, "localhost", 3333)
        .await?;
    info!("=== after open channel\n");

    let data = b"GET / HTTP/1.0\nUser-Agent: curl/7.68.0\nAccept: */*\nConnection: close\n\n";
    channel_direct.data(&data[..]).await?;
    while let Some(msg) = channel_direct.wait().await {
        match msg {
            thrussh::ChannelMsg::Data { ref data } => {
                info!(?data);
            }
            thrussh::ChannelMsg::Eof => {
                info!("EOF");
                break;
            }
            msg => {
                info!(?msg)
            }
        }
    }
    session
        .disconnect(Disconnect::ByApplication, "", "English")
        .await?;

    session.await?;

    Ok(())
}

pub fn setup_logging() -> EyreResult<()> {
    if std::env::var("RUST_LIB_BACKTRACE").is_err() {
        std::env::set_var("RUST_LIB_BACKTRACE", "1");
    }
    color_eyre::install()?;

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "trace");
    }
    tracing_subscriber::fmt::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    Ok(())
}
