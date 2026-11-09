//! How many sign-ins a node works on at once, admitted before any of them
//! reaches the database.
//!
//! A sign-in holds one database connection from its first lookup until it
//! is answered, and it can wait meanwhile: an account being guessed at
//! paces each new try, and only so many passwords are hashed at once. A
//! crowd guessing one person's password would otherwise hold every
//! connection waiting, and everybody else's requests would find none.
//! So a sign-in first takes one of a few places here, waiting only a
//! short bound for one, and is answered busy when none frees up. Waiting
//! here holds no connection, and the places are fewer than the
//! connections a node keeps, so other requests always find one.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use ianua_app::error::AppError;
use tokio::sync::Semaphore;

use crate::error::ApiError;

/// The places among the sign-ins this node works on at once.
#[derive(Debug, Clone)]
pub struct SignInAdmission {
    places: Arc<Semaphore>,
    wait: Duration,
}

impl SignInAdmission {
    /// `places` sign-ins at once, each waiting at most `wait` for a place.
    #[must_use]
    pub fn new(places: NonZeroUsize, wait: Duration) -> Self {
        Self {
            places: Arc::new(Semaphore::new(places.get())),
            wait,
        }
    }
}

/// Runs a sign-in once it holds a place, or answers it busy when no place
/// frees up within the wait.
pub async fn sign_in_admission(
    State(admission): State<SignInAdmission>,
    request: Request,
    next: Next,
) -> Response {
    let place = tokio::time::timeout(
        admission.wait,
        Arc::clone(&admission.places).acquire_owned(),
    )
    .await;
    let Ok(Ok(_held)) = place else {
        return ApiError::from(AppError::Busy).into_response();
    };
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::middleware::from_fn_with_state;
    use axum::routing::post;
    use tokio::sync::Notify;
    use tower::ServiceExt as _;

    use super::*;

    /// A sign-in that holds its place until `release` is notified.
    fn router(admission: SignInAdmission, release: Arc<Notify>) -> Router {
        Router::new()
            .route(
                "/sign-in",
                post(move || {
                    let release = Arc::clone(&release);
                    async move {
                        release.notified().await;
                        "signed in"
                    }
                }),
            )
            .layer(from_fn_with_state(admission, sign_in_admission))
    }

    /// A sign-in request to the test router.
    fn sign_in() -> HttpRequest<Body> {
        HttpRequest::post("/sign-in").body(Body::empty()).unwrap()
    }

    /// A second sign-in receives 429 while the sole permit is occupied;
    /// releasing the first request lets it finish successfully.
    #[tokio::test]
    async fn a_sign_in_finding_no_place_is_answered_busy() {
        let admission = SignInAdmission::new(NonZeroUsize::MIN, Duration::from_millis(50));
        let release = Arc::new(Notify::new());
        let app = router(admission, Arc::clone(&release));
        let first = tokio::spawn(app.clone().oneshot(sign_in()));
        tokio::task::yield_now().await;

        let second = app.oneshot(sign_in()).await.unwrap();

        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        release.notify_one();
        assert_eq!(first.await.unwrap().unwrap().status(), StatusCode::OK);
    }

    /// Ann signs in once the sign-in before her is answered: its place is
    /// hers.
    #[tokio::test]
    async fn a_place_freed_admits_the_next_sign_in() {
        let admission = SignInAdmission::new(NonZeroUsize::MIN, Duration::from_secs(5));
        let release = Arc::new(Notify::new());
        let app = router(admission, Arc::clone(&release));
        release.notify_one();
        let first = app.clone().oneshot(sign_in()).await.unwrap();

        release.notify_one();
        let second = app.oneshot(sign_in()).await.unwrap();

        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::OK);
    }
}
