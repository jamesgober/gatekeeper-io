//! A whole sign-in, request by request, with in-memory stores and no
//! sockets: what a browser sends, what each gate answers.
//!
//! Run with `cargo run --example sign_in`.

use gatekeeper_io::*;

fn cookie_pair(set_cookie: &str) -> &str {
    set_cookie.split(';').next().unwrap_or_default()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let schema = Schema::builder("blog")
        .permissions(&["post.read", "post.write"])
        .role("member", &["post.read"])
        .role("author", &["post.write"])
        .inherits("member")
        .build()?;
    let login_page = Rule::guest_only();
    let write = Rule::signed_in().needs(&schema, &["post.write"])?;
    let logout = Rule::signed_in();

    let gk = Gatekeeper::builder(schema, GateKeys::derive(&[42u8; 32])?)?
        .password_policy(PasswordPolicy::insecure_for_tests())
        .origin("http://localhost:8080")
        .build()?;
    gk.create_account(
        "alice@example.com",
        "correct horse battery",
        Standing::Active,
        &["author"],
    )?;
    let peer = "127.0.0.1".parse()?;

    // 1. GET /login: a guest, cleared for the guests-only form.
    let get = Visit::new(peer);
    let page = gk.authorize(gk.authenticate(Inspected::new(), &get)?, &login_page)?;
    let form = gk.login_form(&page, &get)?;
    let pre = cookie_pair(form.set_cookie().unwrap_or_default()).to_owned();
    println!(
        "GET /login        guest, form token issued, cookie {}",
        pre.split('=').next().unwrap_or_default()
    );

    // 2. POST /login with the token and the cookie.
    let post = Visit::new(peer)
        .method(b"POST")
        .cookie_header(Some(pre.as_bytes()))
        .fetch_site(Some(b"same-origin"));
    let page = gk.authorize(gk.authenticate(Inspected::new(), &post)?, &login_page)?;
    let fields = LoginForm {
        identifier: "alice@example.com",
        password: "correct horse battery",
        csrf: form.token().as_bytes(),
    };
    let Login::SignedIn(signed_in) = gk.login(&page, &post, fields) else {
        return Err("sign-in failed".into());
    };
    let session = cookie_pair(signed_in.set_cookies().next().unwrap_or_default()).to_owned();
    println!(
        "POST /login       303 See Other, signed in as {}",
        signed_in.user()
    );

    // 3. POST /posts: signed in, allowed to write.
    let visit = Visit::new(peer).cookie_header(Some(session.as_bytes()));
    let cleared = gk.authorize(gk.authenticate(Inspected::new(), &visit)?, &write)?;
    println!("POST /posts       cleared for post.write");

    // 4. A forged cookie is a guest, and the write is refused with 401.
    let forged = format!("{}x", &session[..session.len() - 1]);
    let fake = Visit::new(peer).cookie_header(Some(forged.as_bytes()));
    let refused = gk
        .authorize(gk.authenticate(Inspected::new(), &fake)?, &write)
        .unwrap_err();
    println!("forged cookie     {} ({refused})", refused.status());

    // 5. POST /logout with the session's CSRF token.
    let csrf = gk.csrf_token(&cleared)?;
    let post = Visit::new(peer)
        .method(b"POST")
        .cookie_header(Some(session.as_bytes()))
        .fetch_site(Some(b"same-origin"));
    let page = gk.authorize(gk.authenticate(Inspected::new(), &post)?, &logout)?;
    let out = gk.logout(page, &post, csrf.as_bytes())?;
    println!(
        "POST /logout      303 See Other, {}",
        out.set_cookie().unwrap_or_default()
    );

    // 6. The old cookie, replayed: a guest.
    let id = gk.authenticate(Inspected::new(), &visit)?;
    println!("old cookie        guest: {}", id.is_guest());
    Ok(())
}
