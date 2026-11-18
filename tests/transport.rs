use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use mender_connect_rust::protocol::{ProtoHdr, ProtoMsg, ProtoType, decode, encode};
use mender_connect_rust::transport::{MAX_INBOUND_MESSAGE_SIZE, Transport};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{
    Callback, ErrorResponse, Request, Response,
};
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;
use tokio_tungstenite::{accept_async, accept_hdr_async};

#[derive(Clone, Debug)]
struct CaptureHandshake {
    path: Arc<Mutex<Option<String>>>,
    authorization: Arc<Mutex<Option<String>>>,
}

impl Callback for CaptureHandshake {
    fn on_request(self, request: &Request, response: Response) -> Result<Response, ErrorResponse> {
        *self.path.lock().unwrap() = Some(request.uri().path().to_owned());
        *self.authorization.lock().unwrap() = request
            .headers()
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        Ok(response)
    }
}

fn client_message() -> ProtoMsg {
    ProtoMsg {
        header: ProtoHdr {
            proto: ProtoType::SHELL,
            msg_type: "shell".to_owned(),
            session_id: "client-session".to_owned(),
            properties: BTreeMap::new(),
        },
        body: b"client-body".to_vec(),
    }
}

fn server_message() -> ProtoMsg {
    ProtoMsg {
        header: ProtoHdr {
            proto: ProtoType::SHELL,
            msg_type: "shell".to_owned(),
            session_id: "server-session".to_owned(),
            properties: BTreeMap::new(),
        },
        body: b"server-body".to_vec(),
    }
}

#[tokio::test]
async fn exchanges_binary_messages_and_captures_handshake() {
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let path = Arc::new(Mutex::new(None));
        let authorization = Arc::new(Mutex::new(None));
        let capture = CaptureHandshake {
            path: path.clone(),
            authorization: authorization.clone(),
        };

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut websocket = accept_hdr_async(stream, capture).await.unwrap();

            let incoming = websocket.next().await.unwrap().unwrap();
            let incoming = incoming.into_data();
            let decoded: ProtoMsg = decode(incoming.as_ref()).unwrap();
            assert_eq!(decoded.header.msg_type, "shell");
            assert_eq!(decoded.header.session_id, "client-session");
            assert_eq!(decoded.body, b"client-body".to_vec());

            let response = server_message();
            websocket
                .send(Message::Binary(encode(&response).unwrap().into()))
                .await
                .unwrap();
            SinkExt::close(&mut websocket).await.unwrap();
        });

        let mut transport = Transport::connect(&format!("ws://{address}"), "test-token")
            .await
            .unwrap();
        transport.send(&client_message()).await.unwrap();

        let response = transport.receive().await.unwrap().unwrap();
        assert_eq!(response.header.msg_type, "shell");
        assert_eq!(response.header.session_id, "server-session");
        assert_eq!(response.body, b"server-body".to_vec());
        assert!(transport.receive().await.unwrap().is_none());

        server.await.unwrap();
        assert_eq!(
            path.lock().unwrap().as_deref(),
            Some("/api/devices/v1/deviceconnect/connect")
        );
        assert_eq!(
            authorization.lock().unwrap().as_deref(),
            Some("Bearer test-token")
        );
    })
    .await;

    result.unwrap();
}

#[tokio::test]
async fn rejects_oversized_inbound_messages() {
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut websocket = accept_async(stream).await.unwrap();
            let oversized = vec![0u8; MAX_INBOUND_MESSAGE_SIZE + 1];
            let _ = websocket.send(Message::Binary(oversized.into())).await;
            let _ = SinkExt::close(&mut websocket).await;
        });

        let mut transport = Transport::connect(&format!("ws://{address}"), "test-token")
            .await
            .unwrap();
        assert!(transport.receive().await.is_err());

        server.await.unwrap();
    })
    .await;

    result.unwrap();
}

#[tokio::test]
async fn returns_none_on_normal_peer_close() {
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut websocket = accept_async(stream).await.unwrap();
            SinkExt::close(&mut websocket).await.unwrap();
        });

        let mut transport = Transport::connect(&format!("ws://{address}"), "test-token")
            .await
            .unwrap();
        assert!(transport.receive().await.unwrap().is_none());

        server.await.unwrap();
    })
    .await;

    result.unwrap();
}
