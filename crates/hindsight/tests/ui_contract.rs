//! K3 presentation contract — static source/DOM/copy rules over the fourteen
//! `[[W33D:…]]` templates and `service.css`, frozen by the Step 3 shared
//! contract for `W33D-UIUX-WAVE35-HINDSIGHT-INCIDENT-COMPARATOR-20260721`.
//!
//! These tests prove presentation seams only: exact marker inventory and
//! cardinality, single-authority DOM order, closed data hooks, native form
//! semantics, no-script/no-remote rules, and the static responsive and
//! accessibility gates. They never render truth, never compose values, and
//! never claim browser, store, or composer behavior.

const DASHBOARD: &str = include_str!("../templates/dashboard.html");
const INCIDENT: &str = include_str!("../templates/incident.html");
const TOPBAR: &str = include_str!("../templates/fragments/topbar.html");
const INLINE_NOTICE: &str = include_str!("../templates/fragments/inline_notice.html");
const WINDOW_CHOICE: &str = include_str!("../templates/fragments/window_choice.html");
const DISCLOSURE: &str = include_str!("../templates/fragments/disclosure.html");
const FEED_CHANNEL: &str = include_str!("../templates/fragments/feed_channel.html");
const EVENT: &str = include_str!("../templates/fragments/event.html");
const INCIDENT_ROW: &str = include_str!("../templates/fragments/incident_row.html");
const OPERATOR_MARK: &str = include_str!("../templates/fragments/note.html");
const ERROR_DOC: &str = include_str!("../templates/fragments/error.html");
const OPEN_FORM: &str = include_str!("../templates/fragments/open_incident_form.html");
const NOTE_FORM: &str = include_str!("../templates/fragments/note_form.html");
const RESOLVE_FORM: &str = include_str!("../templates/fragments/resolve_form.html");
const CSS: &str = include_str!("../static/service.css");

const ALL_TEMPLATES: [(&str, &str); 14] = [
    ("dashboard.html", DASHBOARD),
    ("incident.html", INCIDENT),
    ("fragments/topbar.html", TOPBAR),
    ("fragments/inline_notice.html", INLINE_NOTICE),
    ("fragments/window_choice.html", WINDOW_CHOICE),
    ("fragments/disclosure.html", DISCLOSURE),
    ("fragments/feed_channel.html", FEED_CHANNEL),
    ("fragments/event.html", EVENT),
    ("fragments/incident_row.html", INCIDENT_ROW),
    ("fragments/note.html", OPERATOR_MARK),
    ("fragments/error.html", ERROR_DOC),
    ("fragments/open_incident_form.html", OPEN_FORM),
    ("fragments/note_form.html", NOTE_FORM),
    ("fragments/resolve_form.html", RESOLVE_FORM),
];

const DASHBOARD_SLOTS: &[&str] = &[
    "STATIC_CSS",
    "TOPBAR_FRAGMENT",
    "DOCUMENT_TITLE_TEXT",
    "HEADING_TITLE_TEXT",
    "PAGE_NOTICE_FRAGMENT",
    "WINDOW_REQUESTED_TEXT",
    "WINDOW_EFFECTIVE_TEXT",
    "WINDOW_OBSERVED_TEXT",
    "WINDOW_OBSERVED_DATETIME_ATTRIBUTE",
    "WINDOW_LIFECYCLE_TEXT",
    "WINDOW_LIFECYCLE_TOKEN",
    "WINDOW_CHOICES_FRAGMENT",
    "AUDIT_CHANNEL_FRAGMENT",
    "LOG_CHANNEL_FRAGMENT",
    "METRIC_CHANNEL_FRAGMENT",
    "INCIDENT_SECTION_STATE_TEXT",
    "INCIDENT_SECTION_STATE_TOKEN",
    "INCIDENT_ROWS_FRAGMENT_LIST",
    "OPEN_INCIDENT_FORM_FRAGMENT",
];

const INCIDENT_SLOTS: &[&str] = &[
    "STATIC_CSS",
    "TOPBAR_FRAGMENT",
    "DOCUMENT_TITLE_TEXT",
    "HEADING_TITLE_TEXT",
    "INCIDENT_LIFECYCLE_TEXT",
    "INCIDENT_LIFECYCLE_TOKEN",
    "PAGE_NOTICE_FRAGMENT",
    "WINDOW_REQUESTED_TEXT",
    "WINDOW_EFFECTIVE_TEXT",
    "WINDOW_OBSERVED_TEXT",
    "WINDOW_OBSERVED_DATETIME_ATTRIBUTE",
    "WINDOW_LIFECYCLE_TEXT",
    "WINDOW_LIFECYCLE_TOKEN",
    "AUDIT_CHANNEL_FRAGMENT",
    "LOG_CHANNEL_FRAGMENT",
    "METRIC_CHANNEL_FRAGMENT",
    "OPERATOR_SECTION_STATE_TEXT",
    "OPERATOR_SECTION_STATE_TOKEN",
    "OPERATOR_MARKS_FRAGMENT_LIST",
    "NOTE_FORM_FRAGMENT",
    "RESOLVE_FORM_FRAGMENT",
    "RETURN_PATH",
];

const TOPBAR_SLOTS: &[&str] = &[
    "TOPBAR_PAGE_TITLE_TEXT",
    "GATEWAY_CONTEXT_TEXT",
    "GATEWAY_CONTEXT_TOKEN",
    "PORTAL_URL",
    "LOGOUT_URL",
];

const INLINE_NOTICE_SLOTS: &[&str] = &[
    "NOTICE_ID_ATTRIBUTE",
    "NOTICE_KIND_TOKEN",
    "NOTICE_HEADING_TEXT",
    "NOTICE_MESSAGE_TEXT",
];

const WINDOW_CHOICE_SLOTS: &[&str] = &[
    "WINDOW_CHOICE_PATH",
    "WINDOW_CHOICE_TEXT",
    "WINDOW_CHOICE_CURRENT_TOKEN",
    "WINDOW_CHOICE_ARIA_CURRENT_ATTRIBUTE",
];

const DISCLOSURE_SLOTS: &[&str] = &["DISCLOSURE_SUMMARY_TEXT", "DISCLOSURE_BODY_TEXT"];

const FEED_CHANNEL_SLOTS: &[&str] = &[
    "CHANNEL_TOKEN",
    "SOURCE_LABEL_TEXT",
    "STATE_TEXT",
    "STATE_TOKEN",
    "STATE_DESCRIPTION_TEXT",
    "COVERAGE_TEXT",
    "ACQUIRED_COUNT_TEXT",
    "ELIGIBLE_DISTINCT_COUNT_TEXT",
    "DISPLAYED_COUNT_TEXT",
    "DISPLAY_ALLOCATION_TEXT",
    "BOUNDEDNESS_TEXT",
    "BOUNDEDNESS_TOKEN",
    "EVENT_ITEMS_FRAGMENT_LIST",
];

const EVENT_SLOTS: &[&str] = &[
    "CHANNEL_TOKEN",
    "RECORDED_TEXT",
    "RECORDED_DATETIME_ATTRIBUTE",
    "SEVERITY_TEXT",
    "SEVERITY_TOKEN",
    "TITLE_TEXT",
    "DETAIL_PREVIEW_TEXT",
    "MACHINE_VALUE_TEXT",
    "PROVENANCE_TEXT",
    "DISCLOSURE_FRAGMENT",
    "CONFLICT_FRAGMENT",
];

const INCIDENT_ROW_SLOTS: &[&str] = &[
    "INCIDENT_PATH",
    "TITLE_TEXT",
    "OPENED_TEXT",
    "OPENED_DATETIME_ATTRIBUTE",
    "ACTOR_SUBJECT_TEXT",
    "DISPLAY_IDENTITY_TEXT",
    "ACTOR_TRUTH_TOKEN",
    "LIFECYCLE_TEXT",
    "LIFECYCLE_TOKEN",
    "CURRENT_TEXT",
    "CURRENT_TOKEN",
];

const OPERATOR_MARK_SLOTS: &[&str] = &[
    "MARK_ID_ATTRIBUTE",
    "MARK_TYPE_TEXT",
    "MARK_TYPE_TOKEN",
    "ACTOR_SUBJECT_TEXT",
    "DISPLAY_IDENTITY_TEXT",
    "ACTOR_TRUTH_TOKEN",
    "RECORDED_TEXT",
    "RECORDED_DATETIME_ATTRIBUTE",
    "BODY_TEXT",
    "LIFECYCLE_TEXT",
    "PUBLIC_MARK_REF_TEXT",
    "AUDIT_TRUTH_TEXT",
];

const ERROR_SLOTS: &[&str] = &[
    "STATIC_CSS",
    "TOPBAR_FRAGMENT",
    "DOCUMENT_TITLE_TEXT",
    "HEADING_TITLE_TEXT",
    "STATUS_CODE_TEXT",
    "SAFE_MESSAGE_TEXT",
    "RECOVERY_PATH",
];

const OPEN_FORM_SLOTS: &[&str] = &[
    "OPEN_ACTION_PATH",
    "CSRF_VALUE_ATTRIBUTE",
    "OPEN_TITLE_VALUE_ATTRIBUTE",
    "OPEN_TITLE_INVALID_TOKEN",
    "OPEN_WINDOW_1_CHECKED_ATTRIBUTE",
    "OPEN_WINDOW_6_CHECKED_ATTRIBUTE",
    "OPEN_WINDOW_24_CHECKED_ATTRIBUTE",
    "OPEN_WINDOW_72_CHECKED_ATTRIBUTE",
    "OPEN_WINDOW_168_CHECKED_ATTRIBUTE",
    "OPEN_WINDOW_INVALID_TOKEN",
    "OPEN_ERROR_SUMMARY_FRAGMENT",
    "OPEN_TITLE_ERROR_TEXT",
    "OPEN_TITLE_ERROR_HIDDEN_ATTRIBUTE",
    "OPEN_WINDOW_ERROR_TEXT",
    "OPEN_WINDOW_ERROR_HIDDEN_ATTRIBUTE",
];

const NOTE_FORM_SLOTS: &[&str] = &[
    "NOTE_ACTION_PATH",
    "CSRF_VALUE_ATTRIBUTE",
    "MUTATION_INCIDENT_ID_VALUE_ATTRIBUTE",
    "NOTE_BODY_TEXT",
    "NOTE_BODY_INVALID_TOKEN",
    "NOTE_ERROR_SUMMARY_FRAGMENT",
    "NOTE_BODY_ERROR_TEXT",
    "NOTE_BODY_ERROR_HIDDEN_ATTRIBUTE",
];

const RESOLVE_FORM_SLOTS: &[&str] = &[
    "RESOLVE_ACTION_PATH",
    "CSRF_VALUE_ATTRIBUTE",
    "MUTATION_INCIDENT_ID_VALUE_ATTRIBUTE",
    "RESOLVE_EXPECTED_LIFECYCLE_VALUE_ATTRIBUTE",
    "RESOLVE_COMMAND_ID_VALUE_ATTRIBUTE",
    "RESOLVE_ERROR_SUMMARY_FRAGMENT",
];

const INVENTORY: [(&str, &str, &[&str]); 14] = [
    ("dashboard.html", DASHBOARD, DASHBOARD_SLOTS),
    ("incident.html", INCIDENT, INCIDENT_SLOTS),
    ("fragments/topbar.html", TOPBAR, TOPBAR_SLOTS),
    (
        "fragments/inline_notice.html",
        INLINE_NOTICE,
        INLINE_NOTICE_SLOTS,
    ),
    (
        "fragments/window_choice.html",
        WINDOW_CHOICE,
        WINDOW_CHOICE_SLOTS,
    ),
    ("fragments/disclosure.html", DISCLOSURE, DISCLOSURE_SLOTS),
    (
        "fragments/feed_channel.html",
        FEED_CHANNEL,
        FEED_CHANNEL_SLOTS,
    ),
    ("fragments/event.html", EVENT, EVENT_SLOTS),
    (
        "fragments/incident_row.html",
        INCIDENT_ROW,
        INCIDENT_ROW_SLOTS,
    ),
    ("fragments/note.html", OPERATOR_MARK, OPERATOR_MARK_SLOTS),
    ("fragments/error.html", ERROR_DOC, ERROR_SLOTS),
    (
        "fragments/open_incident_form.html",
        OPEN_FORM,
        OPEN_FORM_SLOTS,
    ),
    ("fragments/note_form.html", NOTE_FORM, NOTE_FORM_SLOTS),
    (
        "fragments/resolve_form.html",
        RESOLVE_FORM,
        RESOLVE_FORM_SLOTS,
    ),
];

fn slot(name: &str) -> String {
    format!("[[W33D:{name}]]")
}

fn pos(src: &str, needle: &str) -> usize {
    src.find(needle)
        .unwrap_or_else(|| panic!("missing `{needle}`"))
}

fn assert_order(doc: &str, steps: &[String]) {
    let mut cursor = 0usize;
    for step in steps {
        let p = pos(doc, step);
        assert!(p >= cursor, "`{step}` is out of order");
        cursor = p;
    }
}

fn markers(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = src;
    while let Some(start) = rest.find("[[W33D:") {
        let after = &rest[start + "[[W33D:".len()..];
        let end = after.find("]]").expect("unterminated marker");
        out.push(after[..end].to_string());
        rest = &after[end + 2..];
    }
    out
}

fn check_inventory(src: &str, template: &str, expected: &[&str]) {
    let mut found = markers(src);
    let mut want: Vec<String> = expected.iter().map(|s| (*s).to_string()).collect();
    found.sort();
    want.sort();
    assert_eq!(found, want, "marker inventory mismatch in {template}");
    assert_eq!(
        src.matches("[[").count(),
        expected.len(),
        "stray `[[` in {template}"
    );
    assert_eq!(
        src.matches("]]").count(),
        expected.len(),
        "stray `]]` in {template}"
    );
}

fn contains_inline_handler(src: &str) -> Option<String> {
    let lower = src.to_ascii_lowercase();
    let b = lower.as_bytes();
    let mut i = 0usize;
    while i + 3 < b.len() {
        if b[i] == b' ' && b[i + 1] == b'o' && b[i + 2] == b'n' {
            let mut j = i + 3;
            while j < b.len() && b[j].is_ascii_lowercase() {
                j += 1;
            }
            if j > i + 3 && j < b.len() && b[j] == b'=' {
                return Some(lower[i..=j].to_string());
            }
        }
        i += 1;
    }
    None
}

fn css_line_starts(css: &str, prefix: &str) -> bool {
    css.lines().any(|l| l.trim_start().starts_with(prefix))
}

#[test]
fn ui_template_marker_inventory_matches_step3() {
    for (name, src, expected) in INVENTORY {
        check_inventory(src, name, expected);
    }
    let total: usize = INVENTORY.iter().map(|(_, _, s)| s.len()).sum();
    assert_eq!(total, 139, "Step 3 freezes 139 marker occurrences");
    let rendered: usize = ALL_TEMPLATES
        .iter()
        .map(|(_, src)| markers(src).len())
        .sum();
    assert_eq!(
        rendered, 139,
        "templates must carry exactly the frozen markers"
    );
}

#[test]
fn ui_topbar_glyph_is_three_channel_gate_not_shield() {
    for needle in [
        "hd-glyph__stroke--audit",
        "hd-glyph__stroke--log",
        "hd-glyph__stroke--metric",
        "hd-glyph__tick--audit",
        "hd-glyph__tick--log",
        "hd-glyph__tick--metric",
        "hd-glyph__gate",
        "hd-glyph__notch",
        "stroke-dasharray",
        "<svg",
        "aria-hidden=\"true\"",
    ] {
        assert!(TOPBAR.contains(needle), "glyph missing `{needle}`");
    }
    assert!(
        pos(TOPBAR, "hd-glyph") < pos(TOPBAR, "hd-brand__word"),
        "glyph must precede the wordmark"
    );
    let lower = TOPBAR.to_ascii_lowercase();
    for banned in [
        "shield",
        "gradient",
        "fill=\"url(",
        "<script",
        "http",
        "<img",
    ] {
        assert!(
            !lower.contains(banned),
            "topbar contains prohibited `{banned}`"
        );
    }
}

#[test]
fn ui_dashboard_dom_order_is_single_authority() {
    let steps = [
        "hd-skip".to_string(),
        slot("TOPBAR_FRAGMENT"),
        "<h1 class=\"hd-title\">".to_string(),
        slot("PAGE_NOTICE_FRAGMENT"),
        "class=\"hd-gate\"".to_string(),
        slot("WINDOW_REQUESTED_TEXT"),
        slot("WINDOW_EFFECTIVE_TEXT"),
        slot("WINDOW_OBSERVED_TEXT"),
        slot("WINDOW_CHOICES_FRAGMENT"),
        slot("AUDIT_CHANNEL_FRAGMENT"),
        slot("LOG_CHANNEL_FRAGMENT"),
        slot("METRIC_CHANNEL_FRAGMENT"),
        "hd-registration".to_string(),
        "class=\"hd-index\"".to_string(),
        slot("INCIDENT_ROWS_FRAGMENT_LIST"),
        slot("OPEN_INCIDENT_FORM_FRAGMENT"),
    ];
    assert_order(DASHBOARD, &steps);
}

#[test]
fn ui_incident_dom_order_is_single_authority() {
    let steps = [
        "hd-skip".to_string(),
        slot("TOPBAR_FRAGMENT"),
        "<h1 class=\"hd-title\">".to_string(),
        slot("INCIDENT_LIFECYCLE_TOKEN"),
        slot("PAGE_NOTICE_FRAGMENT"),
        "class=\"hd-gate\"".to_string(),
        slot("WINDOW_REQUESTED_TEXT"),
        slot("AUDIT_CHANNEL_FRAGMENT"),
        slot("LOG_CHANNEL_FRAGMENT"),
        slot("METRIC_CHANNEL_FRAGMENT"),
        "hd-registration".to_string(),
        "class=\"hd-marks\"".to_string(),
        slot("OPERATOR_MARKS_FRAGMENT_LIST"),
        slot("NOTE_FORM_FRAGMENT"),
        slot("RESOLVE_FORM_FRAGMENT"),
        "hd-return".to_string(),
        slot("RETURN_PATH"),
    ];
    assert_order(INCIDENT, &steps);
}

#[test]
fn ui_audit_log_metric_order_never_changes() {
    for doc in [DASHBOARD, INCIDENT] {
        let audit = pos(doc, &slot("AUDIT_CHANNEL_FRAGMENT"));
        let log = pos(doc, &slot("LOG_CHANNEL_FRAGMENT"));
        let metric = pos(doc, &slot("METRIC_CHANNEL_FRAGMENT"));
        assert!(
            audit < log && log < metric,
            "audit → log → metric must hold"
        );
    }
    assert!(
        !css_line_starts(CSS, "order:"),
        "CSS must not reorder the lanes"
    );
    assert!(
        !css_line_starts(CSS, "direction:"),
        "CSS must not flip reading direction"
    );
    for banned in ["row-reverse", "column-reverse"] {
        assert!(
            !CSS.contains(banned),
            "CSS contains reorder mechanism `{banned}`"
        );
    }
}

#[test]
fn ui_state_boundedness_and_legacy_copy_is_exact() {
    const CAPTION: &str =
        "Registration marks indicate time adjacency only. Hindsight does not assert cause.";
    assert!(DASHBOARD.contains(CAPTION));
    assert!(INCIDENT.contains(CAPTION));
    assert!(OPERATOR_MARK.contains("Recorded in Hindsight"));
    assert!(RESOLVE_FORM.contains(
        "Resolving freezes the comparison window at one observation instant and records one durable resolution mark. A resolved incident cannot be reopened."
    ));
    for doc in [DASHBOARD, INCIDENT] {
        for term in ["Requested window", "Effective window", "Observed at"] {
            assert!(doc.contains(term), "gate is missing exact term `{term}`");
        }
    }
    // Truth copy is composed by Codex, never hardcoded by K3 templates.
    let codex_copy = [
        "Source unavailable",
        "Loaded successfully",
        "More known beyond this view",
        "End of selected window proven",
        "Completeness unknown",
        "Acquisition exceeded the size limit",
        "Response schema invalid",
        "Audit enqueue attempted",
        "No audit enqueue",
        "Legacy actor value",
        "Stable subject not recorded",
        "Display email not recorded",
        "Legacy value not recorded",
        "Legacy value not safely displayable",
        "Conflicting source assertions",
        "Ordering anchor only",
    ];
    for (name, src) in ALL_TEMPLATES {
        for copy in codex_copy {
            assert!(
                !src.contains(copy),
                "{name} hardcodes composed copy `{copy}`"
            );
        }
    }
    let forbidden = [
        "all caught up",
        "root cause",
        "causal",
        "confidence",
        "synchronized",
        "canonical severity",
        "verified actor",
        "verified source",
        "delivered",
        "enqueued",
        " live ",
    ];
    for (name, src) in ALL_TEMPLATES {
        let lower = src.to_ascii_lowercase();
        for copy in forbidden {
            assert!(
                !lower.contains(copy),
                "{name} contains forbidden copy `{copy}`"
            );
        }
    }
    let css_lower = CSS.to_ascii_lowercase();
    for copy in forbidden {
        assert!(
            !css_lower.contains(copy),
            "service.css contains forbidden copy `{copy}`"
        );
    }
}

#[test]
fn ui_failure_and_oversize_have_no_event_items() {
    assert_eq!(
        FEED_CHANNEL
            .matches("<ol class=\"hd-lane__events\">")
            .count(),
        1,
        "one channel renders exactly one event list"
    );
    assert!(FEED_CHANNEL.contains(&format!(">{}</ol>", slot("EVENT_ITEMS_FRAGMENT_LIST"))));
    assert_eq!(
        FEED_CHANNEL.matches("<li").count(),
        0,
        "the channel shell carries no static event item"
    );
    for copy in ["No events", "0 events", "no events"] {
        assert!(
            !FEED_CHANNEL.contains(copy),
            "channel shell must not pre-empt composed count copy `{copy}`"
        );
    }
    assert!(CSS.contains(".hd-lane__events:empty"));
    assert!(CSS.contains("data-state=\"oversize-truncated\""));
    assert!(CSS.contains("data-boundedness=\"not-applicable\""));
    assert!(EVENT.contains(&format!(">{}</ol>", slot("CONFLICT_FRAGMENT"))));
    assert!(EVENT.contains(&slot("DISCLOSURE_FRAGMENT")));
    for doc in [DASHBOARD, INCIDENT] {
        for channel in [
            "AUDIT_CHANNEL_FRAGMENT",
            "LOG_CHANNEL_FRAGMENT",
            "METRIC_CHANNEL_FRAGMENT",
        ] {
            assert_eq!(doc.matches(&slot(channel)).count(), 1);
        }
    }
}

#[test]
fn ui_operator_mark_cardinality_and_public_ref_slots_are_exact() {
    assert!(OPERATOR_MARK.contains("id=\"[[W33D:MARK_ID_ATTRIBUTE]]\""));
    assert_eq!(
        OPERATOR_MARK.matches(&slot("PUBLIC_MARK_REF_TEXT")).count(),
        1
    );
    assert_eq!(OPERATOR_MARK.matches(&slot("MARK_ID_ATTRIBUTE")).count(), 1);
    assert!(OPERATOR_MARK.contains("data-mark-kind=\"[[W33D:MARK_TYPE_TOKEN]]\""));
    assert!(OPERATOR_MARK.contains("data-actor-truth=\"[[W33D:ACTOR_TRUTH_TOKEN]]\""));
    assert!(
        !OPERATOR_MARK.to_ascii_lowercase().contains("command"),
        "a rendered mark never exposes command material"
    );
    assert_eq!(
        INCIDENT
            .matches(&slot("OPERATOR_MARKS_FRAGMENT_LIST"))
            .count(),
        1
    );
    assert!(RESOLVE_FORM.contains("name=\"command_id\""));
    assert!(RESOLVE_FORM.contains("name=\"expected_lifecycle\""));
    assert!(RESOLVE_FORM.contains("name=\"incident_id\""));
    assert!(!NOTE_FORM.contains("name=\"command_id\""));
    assert!(!OPEN_FORM.contains("name=\"incident_id\""));
}

#[test]
fn ui_native_forms_have_labels_fieldsets_and_error_links() {
    for (name, src, form_id, summary) in [
        (
            "open",
            OPEN_FORM,
            "open-incident-form",
            "OPEN_ERROR_SUMMARY_FRAGMENT",
        ),
        (
            "note",
            NOTE_FORM,
            "note-form",
            "NOTE_ERROR_SUMMARY_FRAGMENT",
        ),
        (
            "resolve",
            RESOLVE_FORM,
            "resolve-form",
            "RESOLVE_ERROR_SUMMARY_FRAGMENT",
        ),
    ] {
        assert!(src.contains(&format!("id=\"{form_id}\"")), "{name} form id");
        assert!(src.contains("method=\"post\""), "{name} method");
        assert!(
            src.contains("name=\"csrf_token\""),
            "{name} csrf hidden input"
        );
        assert!(src.contains("type=\"submit\""), "{name} submit");
        assert!(
            pos(src, &slot(summary)) < pos(src, "<form"),
            "{name} error summary must precede the form"
        );
    }
    assert!(OPEN_FORM.contains("action=\"[[W33D:OPEN_ACTION_PATH]]\""));
    assert!(NOTE_FORM.contains("action=\"[[W33D:NOTE_ACTION_PATH]]\""));
    assert!(RESOLVE_FORM.contains("action=\"[[W33D:RESOLVE_ACTION_PATH]]\""));

    // Open form: persistent label, description, inline error, and radio fieldset.
    assert!(OPEN_FORM.contains("<label class=\"hd-label\" for=\"open-title\">"));
    assert!(OPEN_FORM.contains("id=\"open-title\""));
    assert!(OPEN_FORM.contains("name=\"title\""));
    assert!(OPEN_FORM.contains("aria-describedby=\"open-title-hint open-title-error\""));
    assert!(OPEN_FORM.contains("aria-invalid=\"[[W33D:OPEN_TITLE_INVALID_TOKEN]]\""));
    assert!(OPEN_FORM.contains(
        "id=\"open-title-error\"[[W33D:OPEN_TITLE_ERROR_HIDDEN_ATTRIBUTE]]>[[W33D:OPEN_TITLE_ERROR_TEXT]]</p>"
    ));
    assert!(OPEN_FORM.contains("<fieldset"));
    assert!(OPEN_FORM.contains("<legend"));
    assert!(OPEN_FORM.contains("id=\"open-window\""));
    assert!(OPEN_FORM.contains("aria-describedby=\"open-window-hint open-window-error\""));
    assert_eq!(OPEN_FORM.matches("name=\"window_hours\"").count(), 5);
    assert_eq!(OPEN_FORM.matches("type=\"radio\"").count(), 5);
    let radio_ids = [
        "open-window-1",
        "open-window-6",
        "open-window-24",
        "open-window-72",
        "open-window-168",
    ];
    let radio_values = ["1", "6", "24", "72", "168"];
    let mut cursor = 0usize;
    for (id, value) in radio_ids.iter().zip(radio_values.iter()) {
        let p = pos(OPEN_FORM, &format!("id=\"{id}\""));
        assert!(p >= cursor, "radio order must stay 1, 6, 24, 72, 168");
        cursor = p;
        assert!(
            OPEN_FORM.contains(&format!("for=\"{id}\"")),
            "radio {id} has a label"
        );
        assert!(
            OPEN_FORM.contains(&format!("value=\"{value}\"")),
            "radio {id} carries value {value}"
        );
    }
    for (id, checked) in [
        ("1", "OPEN_WINDOW_1_CHECKED_ATTRIBUTE"),
        ("6", "OPEN_WINDOW_6_CHECKED_ATTRIBUTE"),
        ("24", "OPEN_WINDOW_24_CHECKED_ATTRIBUTE"),
        ("72", "OPEN_WINDOW_72_CHECKED_ATTRIBUTE"),
        ("168", "OPEN_WINDOW_168_CHECKED_ATTRIBUTE"),
    ] {
        assert!(
            OPEN_FORM.contains(&format!("value=\"{id}\"[[W33D:{checked}]]>")),
            "checked marker for window {id} sits at the attribute boundary"
        );
    }
    assert!(OPEN_FORM.contains(
        "id=\"open-window-error\"[[W33D:OPEN_WINDOW_ERROR_HIDDEN_ATTRIBUTE]]>[[W33D:OPEN_WINDOW_ERROR_TEXT]]</p>"
    ));

    // Note form: bound textarea with preserved value and inline error.
    assert!(NOTE_FORM.contains("<textarea"));
    assert!(NOTE_FORM.contains("<label class=\"hd-label\" for=\"note-body\">"));
    assert!(NOTE_FORM.contains("id=\"note-body\""));
    assert!(NOTE_FORM.contains("name=\"body\""));
    assert!(NOTE_FORM.contains(">[[W33D:NOTE_BODY_TEXT]]</textarea>"));
    assert!(NOTE_FORM.contains("aria-invalid=\"[[W33D:NOTE_BODY_INVALID_TOKEN]]\""));
    assert!(NOTE_FORM.contains("aria-describedby=\"note-body-hint note-body-error\""));
    assert!(NOTE_FORM.contains(
        "id=\"note-body-error\"[[W33D:NOTE_BODY_ERROR_HIDDEN_ATTRIBUTE]]>[[W33D:NOTE_BODY_ERROR_TEXT]]</p>"
    ));
    assert!(NOTE_FORM.contains(
        "<input type=\"hidden\" name=\"incident_id\" value=\"[[W33D:MUTATION_INCIDENT_ID_VALUE_ATTRIBUTE]]\">"
    ));

    // Resolve form: hidden typed fields only, no free input.
    assert!(!RESOLVE_FORM.contains("type=\"text\""));
    assert!(!RESOLVE_FORM.contains("<textarea"));
    assert!(RESOLVE_FORM.contains("value=\"[[W33D:RESOLVE_EXPECTED_LIFECYCLE_VALUE_ATTRIBUTE]]\""));
    assert!(RESOLVE_FORM.contains("value=\"[[W33D:RESOLVE_COMMAND_ID_VALUE_ATTRIBUTE]]\""));

    // The notice fragment is a single alert landmark with a composable id.
    assert!(INLINE_NOTICE.contains("id=\"[[W33D:NOTICE_ID_ATTRIBUTE]]\""));
    assert!(INLINE_NOTICE.contains("role=\"alert\""));
    assert!(INLINE_NOTICE.contains("data-notice-kind=\"[[W33D:NOTICE_KIND_TOKEN]]\""));
}

#[test]
fn ui_semantic_lists_times_landmarks_and_one_h1() {
    for doc in [DASHBOARD, INCIDENT, ERROR_DOC] {
        assert_eq!(doc.matches("<h1").count(), 1, "exactly one h1 per document");
        assert!(doc.contains("<main"), "main landmark");
        assert!(doc.contains("href=\"#hd-main\""), "skip link target");
        assert!(doc.contains("id=\"hd-main\""), "skip link destination");
        assert!(doc.contains("<!DOCTYPE html>"));
        assert!(doc.contains("<html lang=\"en\">"));
    }
    assert!(TOPBAR.contains("<header"), "topbar is the header landmark");
    assert!(
        DASHBOARD.contains("<nav"),
        "dashboard gate choices are a nav"
    );
    assert!(INCIDENT.contains("<nav"), "incident return is a nav");
    for (name, src) in [
        ("dashboard", DASHBOARD),
        ("incident", INCIDENT),
        ("feed_channel", FEED_CHANNEL),
        ("event", EVENT),
        ("open_form", OPEN_FORM),
    ] {
        assert!(
            src.contains("<ol"),
            "{name} keeps evidence and choices in ordered lists"
        );
    }
    for (name, src) in [
        ("dashboard", DASHBOARD),
        ("incident", INCIDENT),
        ("event", EVENT),
        ("incident_row", INCIDENT_ROW),
        ("operator_mark", OPERATOR_MARK),
    ] {
        assert!(src.contains("<time"), "{name} renders a real time element");
        assert!(
            src.contains("datetime=\"[[W33D:"),
            "{name} binds a machine datetime attribute"
        );
    }
    assert!(DISCLOSURE.contains("<details"));
    assert!(DISCLOSURE.contains("<summary"));
    assert!(
        FEED_CHANNEL.contains("<h2"),
        "lane source is a second-level heading"
    );
    assert!(
        OPERATOR_MARK.contains("<h3"),
        "mark type nests under the marks heading"
    );
}

#[test]
fn ui_active_window_and_current_case_are_programmatic() {
    assert!(WINDOW_CHOICE.contains("data-current=\"[[W33D:WINDOW_CHOICE_CURRENT_TOKEN]]\""));
    assert!(
        WINDOW_CHOICE.contains("aria-current=\"[[W33D:WINDOW_CHOICE_ARIA_CURRENT_ATTRIBUTE]]\"")
    );
    assert!(WINDOW_CHOICE.contains("href=\"[[W33D:WINDOW_CHOICE_PATH]]\""));
    assert!(INCIDENT_ROW.contains("data-current=\"[[W33D:CURRENT_TOKEN]]\""));
    assert!(INCIDENT_ROW.contains(&slot("CURRENT_TEXT")));
    assert!(CSS.contains(".hd-choice[data-current=\"current\"]"));
    assert!(CSS.contains(".hd-case[data-current=\"current\"]"));
}

#[test]
fn ui_token_hooks_are_closed_and_not_color_only() {
    // Markup hooks: every dynamic class-free data domain is present.
    assert!(FEED_CHANNEL.contains("data-channel=\"[[W33D:CHANNEL_TOKEN]]\""));
    assert!(FEED_CHANNEL.contains("data-state=\"[[W33D:STATE_TOKEN]]\""));
    assert!(FEED_CHANNEL.contains("data-boundedness=\"[[W33D:BOUNDEDNESS_TOKEN]]\""));
    assert!(EVENT.contains("data-severity=\"[[W33D:SEVERITY_TOKEN]]\""));
    assert!(DASHBOARD.contains("data-section-state=\"[[W33D:INCIDENT_SECTION_STATE_TOKEN]]\""));
    assert!(INCIDENT.contains("data-section-state=\"[[W33D:OPERATOR_SECTION_STATE_TOKEN]]\""));
    assert!(DASHBOARD.contains("data-window-lifecycle=\"[[W33D:WINDOW_LIFECYCLE_TOKEN]]\""));
    assert!(INCIDENT.contains("data-incident-lifecycle=\"[[W33D:INCIDENT_LIFECYCLE_TOKEN]]\""));
    assert!(OPERATOR_MARK.contains("data-mark-kind=\"[[W33D:MARK_TYPE_TOKEN]]\""));
    assert!(TOPBAR.contains("data-gateway-context=\"[[W33D:GATEWAY_CONTEXT_TOKEN]]\""));

    // CSS covers every token value of every domain it selects.
    for (domain, values) in [
        ("channel", vec!["audit", "log", "metric"]),
        (
            "state",
            vec![
                "configuration-absent-or-invalid",
                "unavailable",
                "non-success",
                "oversize-truncated",
                "invalid-schema",
                "loaded-empty",
                "loaded-non-empty",
            ],
        ),
        (
            "boundedness",
            vec![
                "known-more",
                "proven-end",
                "completeness-unknown",
                "not-applicable",
            ],
        ),
        (
            "section-state",
            vec![
                "loaded-known-more",
                "loaded-proven-end",
                "loaded-empty",
                "unavailable",
            ],
        ),
        ("window-lifecycle", vec!["moving", "frozen"]),
        ("incident-lifecycle", vec!["open", "resolved"]),
        (
            "severity",
            vec![
                "unknown",
                "producer-info",
                "producer-notice",
                "producer-warning",
                "producer-error",
                "derived-notice",
                "derived-warning",
            ],
        ),
        (
            "mark-kind",
            vec!["incident-opened", "note-added", "incident-resolved"],
        ),
        (
            "notice-kind",
            vec!["status", "validation-error", "stale-conflict"],
        ),
    ] {
        for value in values {
            if domain == "notice-kind" && value == "status" {
                continue; // status is the unmodified base treatment
            }
            assert!(
                CSS.contains(&format!("data-{domain}=\"{value}\"")),
                "CSS has no hook for data-{domain}=\"{value}\""
            );
        }
    }
    for hook in [
        "data-actor-truth=\"legacy-unclassified\"",
        "data-gateway-context=\"unavailable\"",
        "data-current=\"current\"",
        "aria-invalid=\"true\"",
    ] {
        assert!(CSS.contains(hook), "CSS is missing hook `{hook}`");
    }
    // Distinction is carried by geometry and line grammar, not color alone.
    for mechanism in [
        "border-style:dashed",
        "border-block-end:2px dotted",
        "3px double",
        "border-radius:50%",
        "rotate(45deg)",
        "clip-path:polygon",
        "font-style:italic",
    ] {
        assert!(
            CSS.contains(mechanism),
            "CSS lacks non-color mechanism `{mechanism}`"
        );
    }
    for (name, src) in ALL_TEMPLATES {
        let mut rest = src;
        while let Some(i) = rest.find("class=\"") {
            let after = &rest[i + 7..];
            let end = after.find('"').expect("unterminated class attribute");
            assert!(
                !after[..end].contains("[["),
                "{name} carries a dynamic class attribute"
            );
            rest = &after[end..];
        }
    }
}

#[test]
fn ui_no_script_remote_asset_inline_handler_or_legacy_marker() {
    for (name, src) in ALL_TEMPLATES {
        let lower = src.to_ascii_lowercase();
        for banned in [
            "<script",
            "<link",
            "<img",
            "<iframe",
            "<video",
            "<audio",
            "<object",
            "<embed",
            "<canvas",
            "http://",
            "https://",
            "@import",
            "@font-face",
            "url(",
            "{{",
            "}}",
        ] {
            assert!(!lower.contains(banned), "{name} contains `{banned}`");
        }
        assert!(
            contains_inline_handler(src).is_none(),
            "{name} contains an inline event handler"
        );
    }
    let css_lower = CSS.to_ascii_lowercase();
    for banned in [
        "http://",
        "https://",
        "@import",
        "@font-face",
        "url(",
        "linear-gradient",
        "radial-gradient",
        "@keyframes",
        "{{",
        "}}",
    ] {
        assert!(
            !css_lower.contains(banned),
            "service.css contains `{banned}`"
        );
    }
}

#[test]
fn ui_no_generic_cards_merge_causal_copy_or_prohibited_glyph() {
    let banned_words = [
        "card",
        "timeline",
        "rail",
        "shield",
        "gradient",
        "carousel",
        "kpi",
        "gauge",
        "radar",
        "glow",
        "neon",
        "starfield",
        "cluster",
        "score",
    ];
    for (name, src) in ALL_TEMPLATES {
        let lower = src.to_ascii_lowercase();
        for word in banned_words {
            assert!(
                !lower.contains(word),
                "{name} contains archetype word `{word}`"
            );
        }
    }
    let css_lower = CSS.to_ascii_lowercase();
    for word in banned_words {
        assert!(
            !css_lower.contains(word),
            "service.css contains archetype word `{word}`"
        );
    }
    // The three lanes never merge into one rail: one list per channel, three
    // distinct channel fragments per document.
    assert_eq!(
        FEED_CHANNEL.matches("hd-lane__events").count(),
        1,
        "a channel owns exactly one event list hook"
    );
    for doc in [DASHBOARD, INCIDENT] {
        for fragment in [
            "AUDIT_CHANNEL_FRAGMENT",
            "LOG_CHANNEL_FRAGMENT",
            "METRIC_CHANNEL_FRAGMENT",
        ] {
            assert_eq!(doc.matches(&slot(fragment)).count(), 1);
        }
    }
    // Adjacency is captioned, never connected.
    const CAPTION: &str =
        "Registration marks indicate time adjacency only. Hindsight does not assert cause.";
    assert!(DASHBOARD.contains(CAPTION));
    assert!(INCIDENT.contains(CAPTION));
    assert!(!css_lower.contains("@keyframes"), "no fake live motion");
    assert!(!TOPBAR.to_ascii_lowercase().contains("shield"));
    assert!(!TOPBAR.to_ascii_lowercase().contains("gradient"));
}

#[test]
fn ui_css_has_focus_forced_colors_reduced_motion_and_wrap_rules() {
    for needle in [
        ":focus-visible",
        "forced-colors:active",
        "prefers-reduced-motion:reduce",
        "transition:none !important",
        "overflow-wrap:anywhere",
        "word-break:break-word",
        "min-height:44px",
        "font-size:15px",
        "@media (min-width:700px)",
        "@media (min-width:900px)",
        "@media (max-width:400px)",
        "minmax(0,",
        "grid-template-columns:repeat(3,minmax(0,1fr))",
        "accent-color:var(--accent)",
    ] {
        assert!(CSS.contains(needle), "service.css is missing `{needle}`");
    }
}

#[test]
fn ui_error_template_is_full_safe_document() {
    let steps = [
        "<!DOCTYPE html>".to_string(),
        "<meta charset=\"utf-8\">".to_string(),
        "name=\"viewport\"".to_string(),
        "<title>[[W33D:DOCUMENT_TITLE_TEXT]]</title>".to_string(),
        "<style>[[W33D:STATIC_CSS]]</style>".to_string(),
        "hd-skip".to_string(),
        slot("TOPBAR_FRAGMENT"),
        "<main".to_string(),
        slot("STATUS_CODE_TEXT"),
        "<h1 class=\"hd-errorpage__title\">".to_string(),
        slot("SAFE_MESSAGE_TEXT"),
        "href=\"[[W33D:RECOVERY_PATH]]\"".to_string(),
    ];
    assert_order(ERROR_DOC, &steps);
    assert_eq!(ERROR_DOC.matches("<h1").count(), 1);
    let lower = ERROR_DOC.to_ascii_lowercase();
    for banned in ["<script", "http://", "https://", "url(", "{{"] {
        assert!(
            !lower.contains(banned),
            "error document contains `{banned}`"
        );
    }
}
