//! The runtimes offered for new versions, each in the exact image the
//! operator set, or the one pinned here, and those the operator retired.

use ianua_app::ports::workflows::{OfferedRuntime, SandboxRuntimes};
use ianua_domain::domains::workflows::sandbox::runtime::{Runtime, RuntimeImage};

/// The image each runtime is offered in unless the operator sets another:
/// the official slim image, named by the content it had when it was
/// pinned here. A newer image is offered by moving its line here, or by
/// the operator's setting; versions saved before keep theirs.
pub const DEFAULT_IMAGES: [(Runtime, &str); 6] = [
    (
        Runtime::Python311,
        "python:3.11-slim@sha256:db20d8506e2f15b6db39b40b6015ca46bae855dec6dd326d462cfe79ae972893",
    ),
    (
        Runtime::Python312,
        "python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30",
    ),
    (
        Runtime::Python313,
        "python:3.13-slim@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1",
    ),
    (
        Runtime::Node20,
        "node:20-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0",
    ),
    (
        Runtime::Node22,
        "node:22-slim@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da",
    ),
    (
        Runtime::Node24,
        "node:24-slim@sha256:c86ecead9e55a5210ac1727de38a4ca840bf03dcaf34dc9749addbf383b1920c",
    ),
];

/// The runtimes the operator offers, each in its image.
#[derive(Debug, Clone)]
pub struct ConfiguredRuntimes {
    offered: Vec<OfferedRuntime>,
}

impl ConfiguredRuntimes {
    /// Offers `offered`, in the order given.
    #[must_use]
    pub fn new(offered: Vec<OfferedRuntime>) -> Self {
        Self { offered }
    }
}

impl SandboxRuntimes for ConfiguredRuntimes {
    fn offered(&self) -> Vec<OfferedRuntime> {
        self.offered.clone()
    }

    fn image_of(&self, runtime: Runtime) -> Option<RuntimeImage> {
        self.offered
            .iter()
            .find(|offered| offered.runtime == runtime)
            .map(|offered| offered.image.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every runtime has a default image, and each is named by its content.
    #[test]
    fn every_runtime_has_a_pinned_default() {
        for runtime in Runtime::ALL {
            let (_, image) = DEFAULT_IMAGES
                .iter()
                .find(|(pinned, _)| *pinned == runtime)
                .expect("a default image");
            assert!(RuntimeImage::new(*image).is_ok(), "{image}");
        }
    }

    /// A runtime left out is not offered, and its image is not handed out.
    #[test]
    fn a_runtime_left_out_is_not_offered() {
        let image = RuntimeImage::new(DEFAULT_IMAGES[2].1).unwrap();
        let runtimes = ConfiguredRuntimes::new(vec![OfferedRuntime {
            runtime: Runtime::Python313,
            image: image.clone(),
        }]);

        assert_eq!(runtimes.image_of(Runtime::Python313), Some(image));
        assert_eq!(runtimes.image_of(Runtime::Python311), None);
    }
}
