const CSP_HEADER = "Content-Security-Policy"
const CSP_REPORT_ONLY_HEADER = "Content-Security-Policy-Report-Only"
const REPORT_MIMETYPES = ["application/json", "application/csp-report", "application/reports+json"] # https://www.w3.org/TR/reporting-1/#endpoint

# "'unsafe-dynamic'"
const wildcard          = "*"
const none              = "none"
const self              = "'self'"
const unsafe_inline     = "'unsafe-inline'"
const unsafe_eval       = "'unsafe-eval'"
const strict_dynamic    = "'strict-dynamic'"

#=
Data keywords
=#
const data          = "data:"
const mediastream   = "mediastream:"
const blob          = "blob:"
const filesystem    = "filesystem:"

const sandbox_values = [
    "allow-forms",
    "allow-same-origin",
    "allow-scripts",
    "allow-top-navigation",
    "allow-popups",
    "allow-allow-pointer-lock"
]

"""
    const DirectiveTypes

* Nothing: Directive will be absent from policy
* Empty Tuple or Set: Absent from header or only key is added to header
* True: only key is added to policy header
"""
const DirectiveTypes = Union{String, Set{String}, Vector{String}, Tuple, Bool}

const PolicyStore   = AbstractDict{String, DirectiveTypes}
const NonceStore    = OrderedDict{String, Union{Vector{String}, Tuple}}

const DEFAULT_POLICY = OrderedDict{String, DirectiveTypes}(
  "base-uri"                  => (none,),
  "child-src"                 => (),
  "connect-src"               => (),
  "default-src"               => (self,),
  "font-src"                  => (),
  "form-action"               => (),
  "frame-ancestors"           => (none,),
  "frame-src"                 => (), # fallback to default-src
  "img-src"                   => (), # fallback to default-src
  "manifest-src"              => (),
  "media-src"                 => (),
  "object-src"                => (none,),
  "prefetch-src"              => (),
  "report-to"                 => "default",
  "report-uri"                => (),
  "sandbox"                   => false, # default to true (?)
  "script-src"                => (strict_dynamic,), # to be used in conjunction with hash and nonce
  "script-src-attr"           => (),
  "script-src-elem"           => (),
  "style-src"                 => (), # fallback to default-src
  "style-src-attr"            => (),
  "style-src-elem"            => (),
  "upgrade-insecure-requests" => false,
  "worker-src"                => (),
  "trusted-types"             => (),
  "require-trusted-types-for" => ()
)

const DIRECTIVES = string.(keys(DEFAULT_POLICY))

const PERMISSIVE_SOURCES = [
    "'unsafe-eval'",
    "'unsafe-inline'",
    "data:",
    "filesystem:",
    "about:",
    "blob:",
    "ws:",
    "wss:"
]
