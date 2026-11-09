//! A request path is read into its canonical form before any rule sees it,
//! so `/admin/../admin` and `/%61dmin` cannot be matched as written.

use ianua_domain::types::CanonicalPath;

fn main() {
    let _path: CanonicalPath = "/admin/../admin".into();
}
