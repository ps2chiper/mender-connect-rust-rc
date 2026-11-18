use std::env;
use std::time::Duration;

use mender_connect_rust::auth::{AuthClient, DBUS_OBJECT_PATH, DBUS_SERVICE};
use zbus::object_server::SignalEmitter;

struct MockAuthentication {
    token: String,
    server_url: String,
    fetch_result: bool,
}

#[zbus::interface(name = "io.mender.Authentication1")]
impl MockAuthentication {
    async fn get_jwt_token(&self) -> (String, String) {
        (self.token.clone(), self.server_url.clone())
    }

    async fn fetch_jwt_token(&self) -> bool {
        self.fetch_result
    }

    #[zbus(signal)]
    async fn jwt_token_state_change(
        emitter: &zbus::object_server::SignalEmitter<'_>,
        token: &str,
        server_url: &str,
    ) -> zbus::Result<()>;
}

#[tokio::test]
async fn auth_methods_and_signal_subscription_work_on_private_bus() {
    if env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
        eprintln!(
            "skipping auth integration test: DBUS_SESSION_BUS_ADDRESS is not set; run under dbus-run-session"
        );
        return;
    }

    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let service_connection = zbus::Connection::session()
            .await
            .expect("service session bus");
        service_connection
            .request_name(DBUS_SERVICE)
            .await
            .expect("request AuthenticationManager name");
        service_connection
            .object_server()
            .at(
                DBUS_OBJECT_PATH,
                MockAuthentication {
                    token: "trial-token".to_owned(),
                    server_url: "https://mender.example".to_owned(),
                    fetch_result: true,
                },
            )
            .await
            .expect("register mock Authentication1 interface");

        let client_connection = zbus::Connection::session()
            .await
            .expect("client session bus");
        let client = AuthClient::from_connection(client_connection);

        let (token, server_url) = client.get_jwt_token().await.expect("GetJwtToken");
        assert_eq!(token, "trial-token");
        assert_eq!(server_url, "https://mender.example");
        assert!(client.fetch_jwt_token().await.expect("FetchJwtToken"));

        let mut subscription = client.subscribe_jwt_token_state_change();
        subscription.wait_ready().await.expect("subscription ready");

        let emitter =
            SignalEmitter::new(&service_connection, DBUS_OBJECT_PATH).expect("signal emitter");
        MockAuthentication::jwt_token_state_change(
            &emitter,
            "next-token",
            "https://mender.example",
        )
        .await
        .expect("emit first state change");
        let first = subscription
            .next()
            .await
            .expect("first state change")
            .expect("first event");
        assert_eq!(
            first,
            ("next-token".to_owned(), "https://mender.example".to_owned())
        );

        MockAuthentication::jwt_token_state_change(&emitter, "", "https://mender.example")
            .await
            .expect("emit revocation state change");
        let second = subscription
            .next()
            .await
            .expect("second state change")
            .expect("second event");
        assert_eq!(second, (String::new(), "https://mender.example".to_owned()));
    })
    .await;

    result.expect("auth integration test timed out");
}
