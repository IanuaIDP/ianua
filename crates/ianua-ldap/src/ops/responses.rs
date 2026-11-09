//! `LdapMsg` response builders for the operations
//! `ldap3_proto::simple::ServerOps` doesn't cover — it has no `gen_success`/
//! `gen_error` helpers for these the way it does for Bind/Search/Compare,
//! so this mirrors that shape by hand.

use ldap3_proto::proto::{
    LdapBindResponse, LdapExtendedResponse, LdapMsg, LdapOp, LdapPasswordModifyResponse,
    LdapResult, LdapResultCode,
};

fn result(code: LdapResultCode, message: String) -> LdapResult {
    LdapResult {
        code,
        matcheddn: String::new(),
        message,
        referral: Vec::new(),
    }
}

pub(super) fn add_response(msgid: i32, code: LdapResultCode, message: String) -> LdapMsg {
    LdapMsg {
        msgid,
        op: LdapOp::AddResponse(result(code, message)),
        ctrl: vec![],
    }
}

pub(super) fn modify_response(msgid: i32, code: LdapResultCode, message: String) -> LdapMsg {
    LdapMsg {
        msgid,
        op: LdapOp::ModifyResponse(result(code, message)),
        ctrl: vec![],
    }
}

pub(super) fn delete_response(msgid: i32, code: LdapResultCode, message: String) -> LdapMsg {
    LdapMsg {
        msgid,
        op: LdapOp::DelResponse(result(code, message)),
        ctrl: vec![],
    }
}

pub(super) fn modify_dn_response(msgid: i32, code: LdapResultCode, message: String) -> LdapMsg {
    LdapMsg {
        msgid,
        op: LdapOp::ModifyDNResponse(result(code, message)),
        ctrl: vec![],
    }
}

pub(super) fn sasl_bind_response(msgid: i32, code: LdapResultCode, message: String) -> LdapMsg {
    LdapMsg {
        msgid,
        op: LdapOp::BindResponse(LdapBindResponse {
            res: result(code, message),
            saslcreds: None,
        }),
        ctrl: vec![],
    }
}

pub(super) fn password_modify_response(
    msgid: i32,
    code: LdapResultCode,
    message: String,
    gen_password: Option<String>,
) -> LdapMsg {
    let extended = match gen_password {
        Some(_) => LdapPasswordModifyResponse {
            res: result(code, message),
            gen_password,
        }
        .into(),
        None => LdapExtendedResponse {
            res: result(code, message),
            name: None,
            value: None,
        },
    };
    LdapMsg {
        msgid,
        op: LdapOp::ExtendedResponse(extended),
        ctrl: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extended_value(msg: LdapMsg) -> Option<Vec<u8>> {
        match msg.op {
            LdapOp::ExtendedResponse(r) => r.value,
            other => panic!("expected ExtendedResponse, got {other:?}"),
        }
    }

    #[test]
    fn without_a_generated_password_the_response_value_is_absent_not_an_empty_sequence() {
        let msg = password_modify_response(1, LdapResultCode::Success, String::new(), None);

        assert_eq!(
            extended_value(msg),
            None,
            "an empty SEQUENCE wrapped in Some(..) is spec-legal but real ldappasswd \
             clients reject it — the field itself must be absent"
        );
    }

    #[test]
    fn with_a_generated_password_the_response_value_carries_it() {
        let msg = password_modify_response(
            1,
            LdapResultCode::Success,
            String::new(),
            Some("generated".to_owned()),
        );

        assert!(extended_value(msg).is_some());
    }
}
