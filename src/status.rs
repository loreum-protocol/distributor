use std::error::Error;
use vercel_lambda::{
    error::VercelError,
    http::{StatusCode, Version},
    lambda, IntoResponse, Request, Response,
};

fn handler(_: Request) -> Result<impl IntoResponse, VercelError> {
    let response = Response::builder()
        .version(Version::HTTP_2)
        .status(StatusCode::NO_CONTENT)
        .header("Content-Type", "text/plain")
        .body(())?;

    Ok(response)
}

fn main() -> Result<(), Box<dyn Error>> {
    Ok(lambda!(handler))
}
