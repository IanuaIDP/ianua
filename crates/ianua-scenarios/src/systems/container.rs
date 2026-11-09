//! One container started for a scenario, publishing one port on loopback,
//! removed with its volumes when dropped.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::expect::{Waiting, eventually_paced};

/// The longest a system may take to take its first command, inside the
/// time a scenario is given.
const STARTING: Duration = Duration::from_secs(90);

/// What a container runs.
#[derive(Debug, Default)]
pub(crate) struct ContainerSpec<'a> {
    /// Container reference passed to Docker to start the external system.
    pub image: &'a str,
    /// The port the system listens on inside.
    pub port: u16,
    /// Its environment.
    pub env: &'a [(&'a str, &'a str)],
    /// The program to run in place of the image's own, if any.
    pub entrypoint: Option<&'a str>,
    /// The arguments after the image.
    pub args: &'a [&'a str],
    /// A folder shown inside at `/certs`, read-only.
    pub certificates: Option<&'a Path>,
    /// Named volumes kept between runs and where each is shown inside, such
    /// as a model cache downloaded once per machine.
    pub volumes: &'a [(&'a str, &'a str)],
    /// The platform its image is run as when not the machine's own, such as
    /// `linux/amd64` for an image built for it alone.
    pub platform: Option<&'a str>,
}

/// A running container.
#[derive(Debug)]
pub struct Container {
    name: String,
    port: u16,
}

impl Container {
    /// A container running `spec`.
    ///
    /// # Panics
    ///
    /// When docker cannot start it, which needs docker on the path.
    /// Container launch is a scenario prerequisite; command failure aborts setup.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub(crate) fn run(spec: &ContainerSpec<'_>) -> Self {
        let name = format!("ianua-company-{}", uuid::Uuid::new_v4().simple());
        let mut command = Command::new("docker");
        command.args(["run", "-d", "--name", &name, "--label", "ianua-test=1"]);
        command.args(["-p", &format!("127.0.0.1::{}", spec.port)]);
        for (key, value) in spec.env {
            command.args(["-e", &format!("{key}={value}")]);
        }
        if let Some(folder) = spec.certificates {
            command.args(["-v", &format!("{}:/certs:ro", folder.display())]);
        }
        if let Some(platform) = spec.platform {
            command.args(["--platform", platform]);
        }
        for (volume, inside) in spec.volumes {
            command.args(["-v", &format!("{volume}:{inside}")]);
        }
        if let Some(entrypoint) = spec.entrypoint {
            command.args(["--entrypoint", entrypoint]);
        }
        command.arg(spec.image).args(spec.args);
        let output = command.output().expect("docker can be run");
        assert!(
            output.status.success(),
            "the container did not start: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let port = published_port(&name, spec.port);
        Self { name, port }
    }

    /// The loopback port it publishes.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Runs `args` inside until it succeeds, as a system still starting
    /// refuses its first commands.
    ///
    /// # Panics
    ///
    /// When it has not succeeded once the system had time to start.
    pub async fn exec_until_done(&self, args: &[&str]) {
        let waiting = Waiting {
            patience: STARTING,
            every: Duration::from_millis(500),
        };
        eventually_paced(&format!("the system takes {args:?}"), waiting, || async {
            Command::new("docker")
                .arg("exec")
                .arg(&self.name)
                .args(args)
                .output()
                .ok()
                .filter(|output| output.status.success())
                .map(|_| ())
        })
        .await;
    }
}

impl Container {
    /// Waits until `path` on its port answers with success, as a server
    /// still starting or still fetching what it serves does not, for up to
    /// five minutes.
    ///
    /// # Panics
    ///
    /// When it never answered with success.
    pub async fn answer_until_ready(&self, path: &str) {
        let address = format!("http://127.0.0.1:{}{path}", self.port);
        let client = reqwest::Client::new();
        let waiting = Waiting {
            patience: Duration::from_secs(300),
            every: Duration::from_secs(1),
        };
        eventually_paced(&format!("{address} answers"), waiting, || async {
            let answered = client.get(&address).send().await.ok()?;
            answered.status().is_success().then_some(())
        })
        .await;
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", "-v", &self.name])
            .output();
    }
}

/// The loopback port container `name` publishes for `port`.
/// A started scenario container must publish the port requested by its specification.
#[allow(clippy::expect_used)]
fn published_port(name: &str, port: u16) -> u16 {
    let output = Command::new("docker")
        .args(["port", name, &format!("{port}/tcp")])
        .output()
        .expect("docker can be run");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .and_then(|line| line.rsplit(':').next())
        .and_then(|port| port.trim().parse().ok())
        .expect("the container publishes its port")
}
