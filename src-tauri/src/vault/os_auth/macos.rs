// LocalAuthentication: Touch ID or Apple Watch, falling back to the account password.

use std::sync::mpsc;

use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAError, LAPolicy};

use super::{Outcome, cancelled, failed};
use crate::error::AppResult;

pub fn unprotected() -> bool {
    let context = unsafe { LAContext::new() };
    matches!(unsafe { context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication) }, Err(error) if error.code() == LAError::PasscodeNotSet.0)
}

pub fn confirm(reason: &str) -> AppResult<Outcome> {
    let context = unsafe { LAContext::new() };
    let policy = LAPolicy::DeviceOwnerAuthentication;
    if let Err(error) = unsafe { context.canEvaluatePolicy_error(policy) } {
        if error.code() == LAError::PasscodeNotSet.0 {
            return Ok(Outcome::NoProtection);
        }
        return Ok(Outcome::Unavailable(error.localizedDescription().to_string()));
    }

    let (sender, answer) = mpsc::channel::<(bool, isize)>();
    let reply = RcBlock::new(move |ok: Bool, error: *mut NSError| {
        let code = if error.is_null() { 0 } else { unsafe { (*error).code() } };
        let _ = sender.send((ok.as_bool(), code));
    });
    unsafe { context.evaluatePolicy_localizedReason_reply(policy, &NSString::from_str(reason), &reply) };

    // The context has to stay alive until the reply arrives, so it's only dropped after this.
    let result = answer.recv().map_err(|_| failed())?;
    drop(context);
    match result {
        (true, _) => Ok(Outcome::Confirmed),
        (false, code) if code == LAError::UserCancel.0 || code == LAError::SystemCancel.0 || code == LAError::AppCancel.0 => Err(cancelled()),
        (false, code) if code == LAError::PasscodeNotSet.0 => Ok(Outcome::NoProtection),
        _ => Err(failed()),
    }
}
