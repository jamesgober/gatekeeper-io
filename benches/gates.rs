//! The request path through both gates, with an in-memory session.

use std::{hint::black_box, sync::Arc};

use criterion::{Criterion, criterion_group, criterion_main};
use gatekeeper_io::*;

fn bench(c: &mut Criterion) {
    let schema = Schema::builder("web")
        .permissions(&["post.read", "post.write"])
        .role("author", &["post.read", "post.write"])
        .build()
        .expect("schema");
    let write = Rule::signed_in()
        .needs(&schema, &["post.write"])
        .expect("rule");
    let gk = Gatekeeper::builder(schema, GateKeys::derive(&[1; 32]).expect("keys"))
        .expect("builder")
        .password_policy(PasswordPolicy::insecure_for_tests())
        .signals(Arc::new(MemorySignals::new(64)))
        .build()
        .expect("gatekeeper");
    gk.create_account(
        "a@x.io",
        "benchmark password",
        Standing::Active,
        &["author"],
    )
    .expect("account");
    let peer = "192.0.2.1".parse().expect("ip");

    // Sign in once through the real flow.
    let get = Visit::new(peer);
    let page = gk
        .authorize(
            gk.authenticate(Inspected::new(), &get).expect("auth"),
            &Rule::guest_only(),
        )
        .expect("page");
    let form = gk.login_form(&page, &get).expect("form");
    let pre = form
        .set_cookie()
        .expect("cookie")
        .split(';')
        .next()
        .expect("pair")
        .to_owned();
    let post = Visit::new(peer)
        .method(b"POST")
        .cookie_header(Some(pre.as_bytes()));
    let page = gk
        .authorize(
            gk.authenticate(Inspected::new(), &post).expect("auth"),
            &Rule::guest_only(),
        )
        .expect("page");
    let Login::SignedIn(si) = gk.login(
        &page,
        &post,
        LoginForm {
            identifier: "a@x.io",
            password: "benchmark password",
            csrf: form.token().as_bytes(),
        },
    ) else {
        panic!("sign-in");
    };
    let cookie = si
        .set_cookies()
        .next()
        .expect("cookie")
        .split(';')
        .next()
        .expect("pair")
        .to_owned();
    let member = Visit::new(peer).cookie_header(Some(cookie.as_bytes()));
    let guest = Visit::new(peer);

    c.bench_function("gates/authenticate_member", |b| {
        b.iter(|| gk.authenticate(Inspected::new(), black_box(&member)))
    });
    c.bench_function("gates/authenticate_guest", |b| {
        b.iter(|| gk.authenticate(Inspected::new(), black_box(&guest)))
    });
    let identified = gk.authenticate(Inspected::new(), &member).expect("member");
    c.bench_function("gates/authorize", |b| {
        b.iter(|| gk.authorize(black_box(identified.clone()), black_box(&write)))
    });
    c.bench_function("gates/both", |b| {
        b.iter(|| {
            let id = gk.authenticate(Inspected::new(), black_box(&member))?;
            gk.authorize(id, black_box(&write))
        })
    });
    let cleared = gk.authorize(identified, &write).expect("cleared");
    let token = gk.csrf_token(&cleared).expect("token");
    c.bench_function("gates/csrf_check", |b| {
        b.iter(|| {
            gk.check_csrf(
                black_box(&cleared),
                black_box(&member),
                black_box(token.as_bytes()),
            )
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
