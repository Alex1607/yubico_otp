use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    Ok,
    BadOtp,
    ReplayedOtp,
    BadSignature,
    MissingParameter,
    NoSuchClient,
    OperationNotAllowed,
    BackendError,
    NotEnoughAnswers,
    ReplayedRequest,
}

impl FromStr for State {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "OK" => Ok(State::Ok),
            "BAD_OTP" => Ok(State::BadOtp),
            "REPLAYED_OTP" => Ok(State::ReplayedOtp),
            "BAD_SIGNATURE" => Ok(State::BadSignature),
            "MISSING_PARAMETER" => Ok(State::MissingParameter),
            "NO_SUCH_CLIENT" => Ok(State::NoSuchClient),
            "OPERATION_NOT_ALLOWED" => Ok(State::OperationNotAllowed),
            "BACKEND_ERROR" => Ok(State::BackendError),
            "NOT_ENOUGH_ANSWERS" => Ok(State::NotEnoughAnswers),
            "REPLAYED_REQUEST" => Ok(State::ReplayedRequest),
            _ => Err(()),
        }
    }
}
