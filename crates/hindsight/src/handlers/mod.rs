//! HTTP handlers and typed presentation helpers.

pub mod health;
pub mod timeline;

use std::sync::OnceLock;

use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Response};

use crate::error::ErrorCondition;
use crate::view_contract::{
    token, ComposeError, Composer, EscapedText, ProductRelativePath, RenderedFragment, Slot,
    SlotValue, StaticCssValue, TemplateId, TokenDomain, TrustedStaticUrl,
};

pub const SERVICE_CSS: &str = include_str!("../../static/service.css");
pub const APP_CSS_PATH: &str = "/assets/hindsight-20260908.css";

static APP_CSS: OnceLock<String> = OnceLock::new();

pub fn app_css() -> &'static str {
    APP_CSS
        .get_or_init(|| {
            let mut css = String::with_capacity(odyssey::APP_CSS.len() + SERVICE_CSS.len());
            css.push_str(odyssey::APP_CSS);
            css.push_str(SERVICE_CSS);
            css
        })
        .as_str()
}

/// Long-lived, content-versioned Hindsight stylesheet.
pub async fn app_css_asset() -> Response {
    let mut response = app_css().into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/css; charset=utf-8"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

pub fn validate_templates() -> Result<(), ComposeError> {
    Composer::validate_all_templates()
}

pub fn render_topbar(
    page_title: &str,
    gateway_context: &str,
    authenticated: bool,
) -> Result<RenderedFragment, ComposeError> {
    Composer::render(
        TemplateId::Topbar,
        vec![
            (
                Slot::TopbarPageTitleText,
                SlotValue::Text(EscapedText::new(page_title)),
            ),
            (
                Slot::GatewayContextText,
                SlotValue::Text(EscapedText::new(gateway_context)),
            ),
            (
                Slot::GatewayContextToken,
                token(
                    TokenDomain::GatewayContext,
                    if authenticated {
                        "authenticated"
                    } else {
                        "unavailable"
                    },
                ),
            ),
            (
                Slot::PortalUrl,
                SlotValue::TrustedStaticUrl(TrustedStaticUrl::Portal),
            ),
            (
                Slot::LogoutUrl,
                SlotValue::TrustedStaticUrl(TrustedStaticUrl::Logout),
            ),
        ],
    )
}

pub(crate) fn render_error_document(
    condition: ErrorCondition,
    authenticated_gateway_context: bool,
) -> Result<String, ComposeError> {
    let status = condition.status();
    let topbar = render_topbar(
        "Hindsight",
        if authenticated_gateway_context {
            "Authenticated gateway context"
        } else {
            "Authentication context unavailable"
        },
        authenticated_gateway_context,
    )?;
    Composer::render(
        TemplateId::Error,
        vec![
            (
                Slot::StaticCss,
                SlotValue::StaticCss(StaticCssValue::application()),
            ),
            (Slot::TopbarFragment, SlotValue::Fragment(topbar)),
            (
                Slot::DocumentTitleText,
                SlotValue::Text(EscapedText::new(format!("{} · Hindsight", status.as_u16()))),
            ),
            (
                Slot::HeadingTitleText,
                SlotValue::Text(EscapedText::new(condition.heading())),
            ),
            (
                Slot::StatusCodeText,
                SlotValue::Text(EscapedText::new(status.as_u16().to_string())),
            ),
            (
                Slot::SafeMessageText,
                SlotValue::Text(EscapedText::new(condition.message())),
            ),
            (
                Slot::RecoveryPath,
                SlotValue::ProductPath(ProductRelativePath::Root),
            ),
        ],
    )
    .map(RenderedFragment::into_string)
}

pub fn fmt_datetime_s(seconds: i64) -> String {
    if seconds <= 0 {
        return "Time not recorded".to_string();
    }
    match time::OffsetDateTime::from_unix_timestamp(seconds) {
        Ok(value) => format!(
            "{} {}, {} {:02}:{:02}:{:02} UTC",
            month_abbr(value.month()),
            value.day(),
            value.year(),
            value.hour(),
            value.minute(),
            value.second(),
        ),
        Err(_) => "Time outside display range".to_string(),
    }
}

pub fn fmt_datetime_ms(milliseconds: i64) -> String {
    if milliseconds <= 0 {
        return "Time not recorded".to_string();
    }
    let seconds = milliseconds.div_euclid(1_000);
    let millis = milliseconds.rem_euclid(1_000);
    match time::OffsetDateTime::from_unix_timestamp(seconds) {
        Ok(value) => format!(
            "{} {}, {} {:02}:{:02}:{:02}.{:03} UTC",
            month_abbr(value.month()),
            value.day(),
            value.year(),
            value.hour(),
            value.minute(),
            value.second(),
            millis,
        ),
        Err(_) => "Time outside display range".to_string(),
    }
}

pub fn datetime_attribute_ms(milliseconds: i64) -> String {
    if milliseconds <= 0 {
        return String::new();
    }
    let seconds = milliseconds.div_euclid(1_000);
    let millis = milliseconds.rem_euclid(1_000);
    match time::OffsetDateTime::from_unix_timestamp(seconds) {
        Ok(value) => format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            value.year(),
            value.month() as u8,
            value.day(),
            value.hour(),
            value.minute(),
            value.second(),
            millis,
        ),
        Err(_) => String::new(),
    }
}

fn month_abbr(month: time::Month) -> &'static str {
    use time::Month::*;
    match month {
        January => "Jan",
        February => "Feb",
        March => "Mar",
        April => "Apr",
        May => "May",
        June => "Jun",
        July => "Jul",
        August => "Aug",
        September => "Sep",
        October => "Oct",
        November => "Nov",
        December => "Dec",
    }
}
