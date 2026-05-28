//! OCSF field validation and helper functions for OTTL pipelines (caver-collector#86).
//!
//! Public API:
//!   `validate(event, class_uid)` → `Result<(), Vec<String>>` — required-field check
//!   `required_fields(class_uid)` → `&'static [&'static str]` — per-class required fields
//!   `class_name(class_uid)` → `Option<&'static str>`
//!   `category_uid(class_uid)` → `Option<u32>`
//!   `type_uid(class_uid, activity_id)` → `u32`

use serde_json::Value;

// ---------------------------------------------------------------------------
// OCSF class registry (OCSF 1.3 subset)
// ---------------------------------------------------------------------------

struct ClassMeta {
    uid: u32,
    name: &'static str,
    category_uid: u32,
    required: &'static [&'static str],
}

static CLASSES: &[ClassMeta] = &[
    ClassMeta {
        uid: 1001,
        name: "File System Activity",
        category_uid: 2,
        required: &[
            "class_uid",
            "category_uid",
            "activity_id",
            "time",
            "severity_id",
            "metadata",
            "file",
        ],
    },
    ClassMeta {
        uid: 1002,
        name: "Kernel Extension Activity",
        category_uid: 2,
        required: &[
            "class_uid",
            "category_uid",
            "activity_id",
            "time",
            "severity_id",
            "metadata",
        ],
    },
    ClassMeta {
        uid: 2001,
        name: "Security Finding",
        category_uid: 2,
        required: &[
            "class_uid",
            "category_uid",
            "activity_id",
            "time",
            "severity_id",
            "metadata",
            "finding_info",
        ],
    },
    ClassMeta {
        uid: 3001,
        name: "DNS Activity",
        category_uid: 4,
        required: &[
            "class_uid",
            "category_uid",
            "activity_id",
            "time",
            "severity_id",
            "metadata",
            "query",
        ],
    },
    ClassMeta {
        uid: 3002,
        name: "Network Activity",
        category_uid: 4,
        required: &[
            "class_uid",
            "category_uid",
            "activity_id",
            "time",
            "severity_id",
            "metadata",
        ],
    },
    ClassMeta {
        uid: 3003,
        name: "HTTP Activity",
        category_uid: 4,
        required: &[
            "class_uid",
            "category_uid",
            "activity_id",
            "time",
            "severity_id",
            "metadata",
            "http_request",
            "http_response",
        ],
    },
    ClassMeta {
        uid: 3006,
        name: "FTP Activity",
        category_uid: 4,
        required: &[
            "class_uid",
            "category_uid",
            "activity_id",
            "time",
            "severity_id",
            "metadata",
        ],
    },
    ClassMeta {
        uid: 4001,
        name: "Account Change",
        category_uid: 3,
        required: &[
            "class_uid",
            "category_uid",
            "activity_id",
            "time",
            "severity_id",
            "metadata",
            "user",
        ],
    },
    ClassMeta {
        uid: 4002,
        name: "Authentication",
        category_uid: 3,
        required: &[
            "class_uid",
            "category_uid",
            "activity_id",
            "time",
            "severity_id",
            "status_id",
            "metadata",
            "user",
        ],
    },
    ClassMeta {
        uid: 4003,
        name: "Authorize Session",
        category_uid: 3,
        required: &[
            "class_uid",
            "category_uid",
            "activity_id",
            "time",
            "severity_id",
            "metadata",
            "user",
        ],
    },
    ClassMeta {
        uid: 4004,
        name: "Entity Management",
        category_uid: 3,
        required: &[
            "class_uid",
            "category_uid",
            "activity_id",
            "time",
            "severity_id",
            "metadata",
        ],
    },
    ClassMeta {
        uid: 4005,
        name: "User Access Management",
        category_uid: 3,
        required: &[
            "class_uid",
            "category_uid",
            "activity_id",
            "time",
            "severity_id",
            "metadata",
            "user",
        ],
    },
    ClassMeta {
        uid: 4006,
        name: "Group Management",
        category_uid: 3,
        required: &[
            "class_uid",
            "category_uid",
            "activity_id",
            "time",
            "severity_id",
            "metadata",
            "group",
        ],
    },
    ClassMeta {
        uid: 5001,
        name: "Process Activity",
        category_uid: 2,
        required: &[
            "class_uid",
            "category_uid",
            "activity_id",
            "time",
            "severity_id",
            "metadata",
            "process",
        ],
    },
    ClassMeta {
        uid: 5002,
        name: "Module Activity",
        category_uid: 2,
        required: &[
            "class_uid",
            "category_uid",
            "activity_id",
            "time",
            "severity_id",
            "metadata",
        ],
    },
    ClassMeta {
        uid: 6001,
        name: "Detection Finding",
        category_uid: 5,
        required: &[
            "class_uid",
            "category_uid",
            "activity_id",
            "time",
            "severity_id",
            "metadata",
            "finding_info",
            "analytic",
        ],
    },
    ClassMeta {
        uid: 6002,
        name: "Vulnerability Finding",
        category_uid: 5,
        required: &[
            "class_uid",
            "category_uid",
            "activity_id",
            "time",
            "severity_id",
            "metadata",
            "finding_info",
            "vulnerabilities",
        ],
    },
    ClassMeta {
        uid: 6003,
        name: "Compliance Finding",
        category_uid: 5,
        required: &[
            "class_uid",
            "category_uid",
            "activity_id",
            "time",
            "severity_id",
            "metadata",
            "finding_info",
            "compliance",
        ],
    },
];

fn class_meta(class_uid: u32) -> Option<&'static ClassMeta> {
    CLASSES.iter().find(|c| c.uid == class_uid)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Validate that `event` contains all required OCSF fields for `class_uid`.
/// Returns `Ok(())` on success, or a list of missing field names on error.
pub fn validate(event: &Value, class_uid: u32) -> Result<(), Vec<String>> {
    let meta = match class_meta(class_uid) {
        Some(m) => m,
        None => {
            return Err(vec![format!("unknown class_uid {class_uid}")]);
        }
    };

    let mut missing: Vec<String> = meta
        .required
        .iter()
        .filter(|&&field| event.get(field).is_none())
        .map(|&f| f.to_string())
        .collect();

    // Also check that class_uid in the event matches the expected value
    if let Some(uid_val) = event.get("class_uid") {
        if uid_val.as_u64().map_or(true, |u| u != class_uid as u64) {
            missing.push(format!("class_uid mismatch: expected {class_uid}"));
        }
    }

    if missing.is_empty() {
        Ok(())
    } else {
        Err(missing)
    }
}

/// Return the list of required field names for an OCSF class, or `&[]` for unknown classes.
pub fn required_fields(class_uid: u32) -> &'static [&'static str] {
    class_meta(class_uid).map_or(&[], |m| m.required)
}

/// Return the human-readable class name for a class_uid.
pub fn class_name(class_uid: u32) -> Option<&'static str> {
    class_meta(class_uid).map(|m| m.name)
}

/// Return the category_uid for a class_uid.
pub fn category_uid(class_uid: u32) -> Option<u32> {
    class_meta(class_uid).map(|m| m.category_uid)
}

/// Compute the OCSF type_uid: `class_uid * 100 + activity_id`.
pub fn type_uid(class_uid: u32, activity_id: u32) -> u32 {
    class_uid * 100 + activity_id
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_auth_event() -> serde_json::Value {
        json!({
            "class_uid": 4002,
            "class_name": "Authentication",
            "category_uid": 3,
            "category_name": "Identity & Access Management",
            "activity_id": 1,
            "type_uid": 400201,
            "time": 1779962400000i64,
            "severity_id": 1,
            "status_id": 1,
            "status": "Success",
            "metadata": {"version": "1.3.0", "product": {"name": "Okta", "vendor_name": "Okta"}},
            "user": {"uid": "u1", "name": "alice@example.com", "type_id": 1}
        })
    }

    #[test]
    fn valid_event_passes() {
        assert!(validate(&valid_auth_event(), 4002).is_ok());
    }

    #[test]
    fn missing_field_fails() {
        let mut ev = valid_auth_event();
        ev.as_object_mut().unwrap().remove("user");
        let err = validate(&ev, 4002).unwrap_err();
        assert!(err.iter().any(|s| s.contains("user")));
    }

    #[test]
    fn missing_metadata_fails() {
        let mut ev = valid_auth_event();
        ev.as_object_mut().unwrap().remove("metadata");
        let err = validate(&ev, 4002).unwrap_err();
        assert!(err.contains(&"metadata".to_string()));
    }

    #[test]
    fn unknown_class_uid_error() {
        let ev = json!({"class_uid": 9999});
        let err = validate(&ev, 9999).unwrap_err();
        assert!(err[0].contains("unknown"));
    }

    #[test]
    fn class_uid_mismatch_reported() {
        let mut ev = valid_auth_event();
        ev["class_uid"] = json!(9999); // wrong class in event
        let err = validate(&ev, 4002).unwrap_err();
        assert!(err.iter().any(|s| s.contains("mismatch")));
    }

    #[test]
    fn required_fields_known_class() {
        let fields = required_fields(4002);
        assert!(fields.contains(&"user"));
        assert!(fields.contains(&"status_id"));
        assert!(fields.contains(&"metadata"));
    }

    #[test]
    fn required_fields_unknown_class_empty() {
        assert_eq!(required_fields(9999), &[] as &[&str]);
    }

    #[test]
    fn class_name_lookup() {
        assert_eq!(class_name(4002), Some("Authentication"));
        assert_eq!(class_name(3003), Some("HTTP Activity"));
        assert_eq!(class_name(5001), Some("Process Activity"));
        assert_eq!(class_name(9999), None);
    }

    #[test]
    fn category_uid_lookup() {
        assert_eq!(category_uid(4002), Some(3)); // IAM
        assert_eq!(category_uid(3003), Some(4)); // Network
        assert_eq!(category_uid(5001), Some(2)); // System
        assert_eq!(category_uid(9999), None);
    }

    #[test]
    fn type_uid_calculation() {
        assert_eq!(type_uid(4002, 1), 400201);
        assert_eq!(type_uid(3003, 1), 300301);
        assert_eq!(type_uid(5001, 1), 500101);
    }
}
