policy = Policy(
    default = true,
    default_src = [
        "'unsafe-eval'",
        "'unsafe-inline'",
        "data:",
        "filesystem:",
        "about:",
        "blob:",
        "ws:",
        "wss:"
    ],
    script_src = (
        "https://www.google-analytics.com",
        CSP.unsafe_inline,
        CSP.unsafe_eval,
    ),
    form_action = ("'self'"),
    style_src = "'self'",
    report_to = "default",
    report_uri = "/csp_report_endpoint"
)