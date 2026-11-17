//! Release-gating black-box checks. Child binaries use isolated storage, trust and local upstreams.
mod support;
use hickory_proto::{op::ResponseCode, rr::RecordType};
use reqwest::Method;
use serde_json::json;
use std::{
    process::{Command, Stdio},
    time::Duration,
};
use support::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[tokio::test]
async fn real_system_shares_live_policy_enforces_roles_and_persists_across_restart() {
    let sandbox = Sandbox::new("filtering-persistence");
    sandbox.stage("provisioning");
    let dns_origin = DnsOrigin::new().await;
    let plain = Origin::new(&sandbox, false).await;
    let secure = Origin::new(&sandbox, true).await;
    let config = sandbox.config(dns_origin.address, "local", "127.0.0.1:0".parse().unwrap());
    sandbox.provision(&config).await;
    let runtime = Runtime::start(&sandbox, &config, &secure.roots, None, 1).await;
    let mut admin = Api::login(runtime.ready.web, "admin").await;
    let admin2 = Api::login(runtime.ready.web, "admin").await;
    let viewer = Api::login(runtime.ready.web, "viewer").await;
    sandbox.stage("authorization-and-ca");
    assert_eq!(
        Api::anonymous(runtime.ready.web)
            .send(Method::GET, "/api/v1/lists", None)
            .await
            .status()
            .as_u16(),
        401
    );
    for path in ["/api/v1/lists", "/api/v1/metrics", "/dashboard"] {
        assert_eq!(
            viewer.send(Method::GET, path, None).await.status().as_u16(),
            200
        );
    }
    assert_eq!(
        viewer
            .send(
                Method::POST,
                "/api/v1/lists",
                Some(json!({"expected_revision":0,"name":"denied"}))
            )
            .await
            .status()
            .as_u16(),
        403
    );
    assert_eq!(
        viewer
            .send(Method::GET, "/api/v1/certificates/ca", None)
            .await
            .status()
            .as_u16(),
        403
    );
    let response = admin
        .send(Method::GET, "/api/v1/certificates/ca", None)
        .await;
    assert_eq!(response.status().as_u16(), 200);
    let public = response.bytes().await.unwrap().to_vec();
    assert!(!public.windows(11).any(|s| s == b"PRIVATE KEY"));
    let ca = rustls::pki_types::CertificateDer::from(pem::parse(&public).unwrap().into_contents());
    let (status, created) = admin
        .json(
            Method::POST,
            "/api/v1/lists",
            Some(json!({"expected_revision":0,"name":"Shared devices"})),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(created["revision"], 1);
    let mut a = TcpStream::connect(runtime.ready.http).await.unwrap();
    let mut b = TcpStream::connect(runtime.ready.http).await.unwrap();
    assert_eq!(
        get(
            &mut a,
            &plain.url("http", "/exact"),
            &plain.address.to_string()
        )
        .await
        .0,
        200
    );
    assert_eq!(
        get(
            &mut b,
            &plain.url("http", "/exact"),
            &plain.address.to_string()
        )
        .await
        .0,
        200
    );
    let (mut passthrough, leaf) = tls(
        runtime.ready.http,
        "127.0.0.1",
        secure.address.port(),
        secure.certificate.clone(),
    )
    .await;
    assert_eq!(leaf, secure.certificate.as_ref());
    sandbox.stage("mixed-import-and-dns");
    let rules = format!(
        "blocked.test\n*.ads.test\n{}\n{}\nhttps://only-url.test/ads\nmalformed rule\n",
        plain.url("http", "/exact"),
        plain.url("http", "/promo/*")
    );
    let response = admin
        .client
        .post(format!(
            "{}/api/v1/lists/1/imports?expected_revision=1&filename=fixture.txt",
            admin.origin
        ))
        .header("cookie", &admin.cookie)
        .header("origin", &admin.origin)
        .header("x-csrf-token", &admin.csrf)
        .header("content-type", "text/plain")
        .body(rules)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let report = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(report["import"]["accepted"], 5);
    assert_eq!(report["import"]["malformed"][0]["line"], 6);
    for io in [&mut a, &mut b] {
        for path in [
            "/exact",
            "/exact?credential=NEVER-LOG-query-credential",
            "/promo",
            "/promo/a/banner",
        ] {
            let (code, body) = get(io, &plain.url("http", path), &plain.address.to_string()).await;
            assert_eq!(code, 403);
            assert!(body.is_empty());
        }
        for path in ["/exact/", "/exact-sibling", "/promotional", "/news"] {
            assert_eq!(
                get(io, &plain.url("http", path), &plain.address.to_string())
                    .await
                    .0,
                200
            );
        }
    }
    for tcp in [false, true] {
        let address = if tcp {
            runtime.ready.dns_tcp
        } else {
            runtime.ready.dns_udp
        };
        for name in ["blocked.test", "child.ads.test", "nested.child.ads.test"] {
            assert_eq!(
                dns(address, name, RecordType::A, tcp)
                    .await
                    .metadata
                    .response_code,
                ResponseCode::NXDomain
            );
        }
        for name in ["ads.test", "notads.test", "only-url.test"] {
            for kind in [RecordType::A, RecordType::AAAA] {
                let response = dns(address, name, kind, tcp).await;
                assert_eq!(response.metadata.response_code, ResponseCode::NoError);
                assert_eq!(response.answers[0].record_type(), kind);
            }
        }
    }
    sandbox.stage("selective-https-and-live-update");
    let (mut unlisted, leaf) = tls(
        runtime.ready.http,
        "localhost",
        secure.address.port(),
        secure.certificate.clone(),
    )
    .await;
    assert_eq!(leaf, secure.certificate.as_ref());
    let saved = admin
        .rules(1, admin.revision().await, secure.url("https", "/ads/*"))
        .await;
    assert_eq!(saved["import"]["accepted"], 1);
    closed(&mut passthrough).await;
    let (mut inspected, leaf) = tls(
        runtime.ready.http,
        "127.0.0.1",
        secure.address.port(),
        ca.clone(),
    )
    .await;
    assert_ne!(leaf, secure.certificate.as_ref());
    for path in [
        "/ads",
        "/ads?credential=NEVER-LOG-query-credential",
        "/ads/deep",
    ] {
        let (code, body) = get(&mut inspected, path, &secure.address.to_string()).await;
        assert_eq!(code, 403);
        assert!(body.is_empty());
    }
    assert_eq!(
        get(&mut inspected, "/news", &secure.address.to_string())
            .await
            .0,
        200
    );
    admin
        .rules(1, admin.revision().await, secure.url("https", "/news"))
        .await;
    assert_eq!(
        get(
            &mut inspected,
            "/news?ignored=1",
            &secure.address.to_string()
        )
        .await,
        (403, vec![])
    );
    assert_eq!(
        get(&mut inspected, "/newspaper", &secure.address.to_string())
            .await
            .0,
        200
    );
    assert_eq!(
        get(
            &mut unlisted,
            "/ads",
            &format!("localhost:{}", secure.address.port())
        )
        .await
        .0,
        200
    );
    // The earlier origin response closed its passthrough socket. Use a fresh,
    // idle TLS tunnel so this assertion proves domain-rule invalidation itself.
    drop(unlisted);
    let (mut unlisted, _) = tls(
        runtime.ready.http,
        "localhost",
        secure.address.port(),
        secure.certificate.clone(),
    )
    .await;
    admin
        .rules(1, admin.revision().await, "localhost".into())
        .await;
    closed(&mut unlisted).await;
    assert_eq!(
        connect(runtime.ready.http, "localhost", secure.address.port())
            .await
            .1,
        403
    );
    let (_, list) = admin.json(Method::GET, "/api/v1/lists/1", None).await;
    let manual = list["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["kind"]["type"] == "manual")
        .unwrap()["id"]
        .as_i64()
        .unwrap();
    let (status, _) = admin
        .json(
            Method::DELETE,
            &format!("/api/v1/sources/{manual}"),
            Some(json!({"expected_revision":admin.revision().await})),
        )
        .await;
    assert_eq!(status, 200);
    closed(&mut inspected).await;
    let (_, leaf) = tls(
        runtime.ready.http,
        "127.0.0.1",
        secure.address.port(),
        secure.certificate.clone(),
    )
    .await;
    assert_eq!(leaf, secure.certificate.as_ref());
    sandbox.stage("concurrent-edits");
    let revision = admin.revision().await;
    let first = json!({"expected_revision":revision,"text":"race-one.test"});
    let second = json!({"expected_revision":revision,"text":"race-two.test"});
    let (one, two) = tokio::join!(
        admin.json(Method::POST, "/api/v1/lists/1/rules", Some(first)),
        admin2.json(Method::POST, "/api/v1/lists/1/rules", Some(second))
    );
    assert!(matches!((one.0, two.0), (200, 409) | (409, 200)));
    assert_eq!(admin.revision().await, revision + 1);
    let winner = if one.0 == 200 {
        "race-one.test"
    } else {
        "race-two.test"
    };
    let loser = if one.0 == 200 {
        "race-two.test"
    } else {
        "race-one.test"
    };
    assert_eq!(
        dns(runtime.ready.dns_udp, winner, RecordType::A, false)
            .await
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(
        dns(runtime.ready.dns_udp, loser, RecordType::A, false)
            .await
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    sandbox.stage("interrupted-import");
    let revision = admin.revision().await;
    let mut interrupted = TcpStream::connect(runtime.ready.web).await.unwrap();
    interrupted.write_all(format!("POST /api/v1/lists/1/imports?expected_revision={revision}&filename=incomplete.txt HTTP/1.1\r\nHost: {}\r\nOrigin: {}\r\nCookie: {}\r\nX-CSRF-Token: {}\r\nContent-Type: text/plain\r\nContent-Length: 1000\r\nConnection: close\r\n\r\nmust-not-block.test\n",runtime.ready.web,admin.origin,admin.cookie,admin.csrf).as_bytes()).await.unwrap();
    interrupted.shutdown().await.unwrap();
    let mut reply = vec![];
    bounded(interrupted.read_to_end(&mut reply)).await.unwrap();
    assert!(reply.is_empty() || support::status(&reply) >= 400);
    assert_eq!(admin.revision().await, revision);
    assert_eq!(
        dns(
            runtime.ready.dns_udp,
            "must-not-block.test",
            RecordType::A,
            false
        )
        .await
        .metadata
        .response_code,
        ResponseCode::NoError
    );
    sandbox.stage("abandoned-import-response");
    let body = "accepted-before-disconnect.test\n";
    let mut abandoned = TcpStream::connect(runtime.ready.web).await.unwrap();
    abandoned.write_all(format!("POST /api/v1/lists/1/imports?expected_revision={revision}&filename=accepted.txt HTTP/1.1\r\nHost: {}\r\nOrigin: {}\r\nCookie: {}\r\nX-CSRF-Token: {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",runtime.ready.web,admin.origin,admin.cookie,admin.csrf,body.len()).as_bytes()).await.unwrap();
    assert_eq!(support::status(&head(&mut abandoned).await), 200);
    drop(abandoned); // Commit/publication precede headers, even if the JSON report is abandoned.
    assert_eq!(admin.revision().await, revision + 1);
    assert_eq!(
        dns(
            runtime.ready.dns_udp,
            "accepted-before-disconnect.test",
            RecordType::A,
            false
        )
        .await
        .metadata
        .response_code,
        ResponseCode::NXDomain
    );
    sandbox.stage("restart-and-persistence");
    let old = runtime.ready;
    drop(a);
    drop(b);
    runtime.stop().await;
    assert!(tokio::net::TcpListener::bind(old.http).await.is_ok());
    assert!(tokio::net::TcpListener::bind(old.dns_tcp).await.is_ok());
    assert!(tokio::net::UdpSocket::bind(old.dns_udp).await.is_ok());
    let runtime = Runtime::start(&sandbox, &config, &secure.roots, None, 2).await;
    admin.origin = format!("http://{}", runtime.ready.web);
    assert_eq!(
        admin
            .send(Method::GET, "/api/v1/auth/me", None)
            .await
            .status()
            .as_u16(),
        200
    );
    let metrics = admin.json(Method::GET, "/api/v1/metrics", None).await.1;
    assert_eq!(metrics["http"]["allowed"], 0);
    assert_eq!(metrics["dns"]["allowed"], 0);
    assert_eq!(metrics["imports"]["partial"], 0);
    assert_eq!(
        admin
            .send(Method::GET, "/api/v1/certificates/ca", None)
            .await
            .bytes()
            .await
            .unwrap()
            .as_ref(),
        public.as_slice()
    );
    assert_eq!(
        dns(runtime.ready.dns_udp, winner, RecordType::A, false)
            .await
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(
        dns(
            runtime.ready.dns_udp,
            "accepted-before-disconnect.test",
            RecordType::A,
            false
        )
        .await
        .metadata
        .response_code,
        ResponseCode::NXDomain
    );
    let mut io = TcpStream::connect(runtime.ready.http).await.unwrap();
    assert_eq!(
        get(
            &mut io,
            &plain.url("http", "/promo/deeper"),
            &plain.address.to_string()
        )
        .await,
        (403, vec![])
    );
    runtime.stop().await;
    sandbox.assert_logs_safe();
    sandbox.stage("complete");
}

#[tokio::test]
async fn real_listener_failure_restarts_without_duplicate_listeners_or_lost_policy() {
    let sandbox = Sandbox::new("proxy-recovery");
    let upstream = DnsOrigin::new().await;
    let origin = Origin::new(&sandbox, false).await;
    let config = sandbox.config(upstream.address, "none", "127.0.0.1:0".parse().unwrap());
    let mut runtime = Runtime::start(&sandbox, &config, &origin.roots, Some(64), 1).await;
    let api = Api::anonymous(runtime.ready.web);
    let (status, _) = api.json(Method::POST, "/api/v1/lists", None).await;
    assert_eq!(status, 403); // Missing CSRF never mutates state.
    let mut api = api;
    let csrf = api
        .client
        .get(format!("{}/api/v1/auth/csrf", api.origin))
        .send()
        .await
        .unwrap();
    api.cookie = csrf
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .into();
    api.csrf = csrf.json::<serde_json::Value>().await.unwrap()["csrf"]
        .as_str()
        .unwrap()
        .into();
    assert_eq!(
        api.json(
            Method::POST,
            "/api/v1/lists",
            Some(json!({"expected_revision":0,"name":"Recovery"}))
        )
        .await
        .0,
        200
    );
    api.rules(1, 1, "blocked-recovery.test".into()).await;
    sandbox.stage("exhaust-child-descriptors");
    let old = runtime.ready;
    let mut held = vec![];
    bounded(async {
        loop {
            if std::fs::read_to_string(&runtime.log)
                .unwrap()
                .contains("proxy restart scheduled")
            {
                break;
            }
            assert!(
                held.len() < 128,
                "descriptor exhaustion did not trigger a listener failure"
            );
            if let Ok(Ok(io)) =
                tokio::time::timeout(Duration::from_millis(250), TcpStream::connect(old.http)).await
            {
                held.push(io);
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    held.clear();
    sandbox.stage("recover-and-probe");
    runtime.refresh_ready(true).await;
    let metrics = api.json(Method::GET, "/api/v1/metrics", None).await.1;
    assert_eq!(metrics["health"]["ready"], true);
    assert!(metrics["health"]["http"]["restarts"].as_u64().unwrap() >= 1);
    assert_eq!(metrics["imports"]["succeeded"], 1);
    assert_eq!(
        dns(
            runtime.ready.dns_udp,
            "blocked-recovery.test",
            RecordType::A,
            false
        )
        .await
        .metadata
        .response_code,
        ResponseCode::NXDomain
    );
    let mut io = TcpStream::connect(runtime.ready.http).await.unwrap();
    assert_eq!(
        get(
            &mut io,
            "http://blocked-recovery.test/",
            "blocked-recovery.test"
        )
        .await,
        (403, vec![])
    );
    let text = std::fs::read_to_string(&runtime.log).unwrap();
    assert!(text.lines().any(|s| s.contains("proxy restart scheduled")
        && s.contains("Http")
        && s.contains("ListenerIo")));
    assert!(
        tokio::net::TcpListener::bind(runtime.ready.http)
            .await
            .is_err()
    );
    runtime.stop().await;
    sandbox.assert_logs_safe();
    sandbox.stage("complete");
}

#[tokio::test]
async fn startup_failures_exit_without_readiness_and_keep_diagnostics_secret_free() {
    let sandbox = Sandbox::new("startup-failures");
    let upstream = DnsOrigin::new().await;
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = sandbox.config(upstream.address, "none", occupied.local_addr().unwrap());
    sandbox.stage("occupied-listener");
    let log = sandbox.root.join("bind-failure.log");
    let output = std::fs::File::create(&log).unwrap();
    let mut child = Process(
        Command::new(binary())
            .arg("--config")
            .arg(&config)
            .stdout(Stdio::null())
            .stderr(output)
            .spawn()
            .unwrap(),
    );
    let code = bounded(async {
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        loop {
            if let Some(code) = child.0.try_wait().unwrap() {
                break code;
            }
            tick.tick().await;
        }
    })
    .await;
    assert_eq!(code.code(), Some(1));
    let text = std::fs::read_to_string(log).unwrap();
    assert!(!text.contains("runtime ready"));
    assert!(text.contains("Bind failure"));
    sandbox.stage("malformed-configuration");
    std::fs::write(
        &config,
        format!("schema_version=1\ndata_dir='{PRIVATE_QUERY}'\n[dns]\nupstreams=['invalid']"),
    )
    .unwrap();
    let log = std::fs::File::create(sandbox.root.join("config-failure.log")).unwrap();
    let mut child = Process(
        Command::new(binary())
            .arg("--config")
            .arg(&config)
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    let code = bounded(async {
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        loop {
            if let Some(code) = child.0.try_wait().unwrap() {
                break code;
            }
            tick.tick().await;
        }
    })
    .await;
    assert_eq!(code.code(), Some(2));
    sandbox.assert_logs_safe();
    sandbox.stage("complete");
}
