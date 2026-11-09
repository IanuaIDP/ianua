//! What the customization scenarios share: a person Tess invited who
//! joined and signed in, an image to upload, and the portal whose sign-in
//! page shows what Tess chose.

use std::io::Write as _;

use flate2::Compression;
use flate2::write::ZlibEncoder;
use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{Request, Text, people, routing};
use ianua_scenarios::expect::eventually;
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::routes::{Placement, RouteSpec, domain};
use ianua_scenarios::upstreams::Echo;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::app_sign_in::{AppSignInSettings, ConfigureAppSignIn};
use ianua_scenarios::wire::branding::LogoFile;
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::wire::routing::RoutePolicy;
use ianua_scenarios::world::{MEMBER_ROLE, World};
use serde::de::IgnoredAny;

/// The eight bytes every PNG file starts with.
const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

/// Someone at the address `name`, invited into the tenant by Tess with
/// its `Member` role, who accepted from the mailed link and signed in.
///
/// # Panics
///
/// When the invitation, the acceptance or the sign-in is refused.
pub(crate) async fn person(world: &World<'_>, name: &str) -> Person {
    let mut person = world.newcomer(name, &format!("{name} Branded"));
    let invitation = people::invite(
        world.tenant(),
        &InviteUser {
            email: person.email().to_owned(),
            display_name: person.account().display_name.clone(),
            role_id: world.role_id(MEMBER_ROLE).await,
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    person.record_invitation(&invitation.id);
    person.accept_invitation(world.stack()).await;
    person.sign_in(world.stack()).await;
    person
}

/// A real PNG of `width` by `height` pixels, one flat colour.
///
/// # Panics
///
/// When the image cannot be compressed, which writing to memory never
/// fails at.
pub(crate) fn png(width: u32, height: u32) -> Vec<u8> {
    let mut header = Vec::with_capacity(13);
    header.extend_from_slice(&width.to_be_bytes());
    header.extend_from_slice(&height.to_be_bytes());
    header.extend_from_slice(&[8, 2, 0, 0, 0]);
    let row_bytes = usize::try_from(width).expect("a width fits") * 3;
    let mut pixels = Vec::new();
    for _ in 0..height {
        pixels.push(0);
        pixels.resize(pixels.len() + row_bytes, 0x7F);
    }
    let mut compressor = ZlibEncoder::new(Vec::new(), Compression::fast());
    compressor
        .write_all(&pixels)
        .expect("memory takes the pixels");
    let compressed = compressor.finish().expect("memory takes the pixels");

    let mut image = PNG_SIGNATURE.to_vec();
    append_chunk(&mut image, b"IHDR", &header);
    append_chunk(&mut image, b"IDAT", &compressed);
    append_chunk(&mut image, b"IEND", &[]);
    image
}

/// Adds one PNG chunk of `kind` holding `data` to `image`, with its length
/// and its checksum.
fn append_chunk(image: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    let length = u32::try_from(data.len()).expect("a chunk fits");
    image.extend_from_slice(&length.to_be_bytes());
    image.extend_from_slice(kind);
    image.extend_from_slice(data);
    let mut checksum = flate2::Crc::new();
    checksum.update(kind);
    checksum.update(data);
    image.extend_from_slice(&checksum.sum().to_be_bytes());
}

/// `bytes` as a file named as a PNG, whatever it really holds: the name
/// and type an uploader claims are theirs to write.
pub(crate) fn claimed_png(bytes: Vec<u8>) -> LogoFile {
    LogoFile {
        file_name: "acme.png".to_owned(),
        content_type: "image/png".to_owned(),
        bytes,
    }
}

/// A portal Tess put behind the gateway on the tenant's own domain, whose
/// visitors sign in on its own host.
pub(crate) struct Portal {
    /// The host its pages are served on.
    pub(crate) host: String,
    /// The app behind it, kept running for as long as the portal is used.
    _app: Echo,
}

impl Portal {
    /// The portal Tess opens, answering its sign-in address once this
    /// returns.
    ///
    /// # Panics
    ///
    /// When a step of setting it up is refused or the gateway never serves
    /// it.
    pub(crate) async fn opened(world: &World<'_>) -> Self {
        let tess = world.admin().client();
        let stack = world.stack();
        let unique = uuid::Uuid::new_v4().simple().to_string();
        let word = &unique[..8];
        let name = format!("portal-{word}.{}", stack.customer_domain());
        let host = domain::brought(stack, tess, world.tenant(), &name).await;
        let app = Echo::start(stack, &host).await.expect("the portal starts");
        let probe = Client::new(stack, "a probe").expect("a client for the probe");
        let account = RouteSpec::public(&format!("portal-{word}"), "/account/*")
            .asking(RoutePolicy::Authenticated)
            .pinned(&format!("portal-{word}"))
            .on_hosts(std::slice::from_ref(&host))
            .applied(
                tess,
                &probe,
                Placement {
                    tenant: world.tenant(),
                    upstream: &app.url(),
                    host: &host,
                },
            )
            .await;
        let signing_in = ConfigureAppSignIn {
            app_sign_in: Some(AppSignInSettings {
                hosts: vec![host.clone()],
                signed_out_browsers: "refuse".to_owned(),
            }),
            accepts_app_sign_in_of: None,
            delivery: None,
        };
        routing::configure_app_sign_in(world.tenant(), &account.service_id, &signing_in)
            .send(tess)
            .await
            .ok();
        let portal = Self { host, _app: app };
        portal.answers(&probe).await;
        portal
    }

    /// Waits until the gateway serves the portal's sign-in page.
    async fn answers(&self, probe: &Client) {
        let login = self.login();
        eventually("the gateway to serve the portal's sign-in page", || async {
            let answer = probe.send::<IgnoredAny>(Call::get(login.as_str())).await;
            (answer.status() == Status::OK).then_some(())
        })
        .await;
    }

    /// The portal's sign-in address.
    fn login(&self) -> String {
        format!("https://{}/.ianua/login", self.host)
    }

    /// The sign-in page as `visitor` sees it, in the languages
    /// `languages` names when it names any.
    ///
    /// # Panics
    ///
    /// When the page is refused.
    pub(crate) async fn page(&self, visitor: &Client, languages: Option<&str>) -> String {
        let mut call = Call::get(self.login());
        if let Some(wanted) = languages {
            call = call.header("accept-language", wanted);
        }
        Request::<Text>::text(call).send_text(visitor).await.ok()
    }
}
