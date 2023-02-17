# CSP

A julia library to aid the integration of Content-Security-Policy headers into web applications.

**References** 
- [MDN CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [OWASP CSP](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [Strict CSP](https://web.dev/strict-csp/#what-is-a-strict-content-security-policy)
- [W3C CSP3](https://www.w3.org/TR/CSP3/)
- [csp.withgoogle](https://csp.withgoogle.com/docs/index.html)
- [CSP cheatsheet](https://scotthelme.co.uk/csp-cheat-sheet/)
- [CSP-Builder](https://github.com/paragonie/csp-builder)
- [django-csp](https://django-csp.readthedocs.io/en/latest/)

## Project status

The package is under active development and changes may occur.

### Roadmap

- Register package
- Improve support for csp-nonce and csp-hash
-  Improve default strict policy and improve overall configurability
- Handle CSP violation reports
- Export nginx and Apache header configurations

## Contributions, suggestions, questions

All are welcome, as well as feature requests and bug reports. Please open an issue, discussion topic or submit a PR.

## Table of Contents

1. [Installation](#installation)
2. [Usage examples](#usage-examples)
3. [Web example](#web-example)
4. [Import from JSON](#policy-from-a-json-file)
5. [API Reference](#api-reference)

## Installation

While unregistered, the package can be installed via package manager by specifying a URL to the repository
```
pkg> add https://github.com/charlieIT/CSP.jl
```

## Usage examples

### Build a Content Security Policy
```julia
using CSP
policy = Policy(
   # Set fallback for all fetch directives
    "default-src"=>"*",
    # Set valid sources of images and favicons
    "img-src"=>("'self'", "data:"),
    # Turn on https enforcement
    "upgrade-insecure-requests"=>true,
    # Custom directives are supported, if needed
    "some-custom-directive"=>["foo", "bar"]
)
```
```json
{
    "default-src": "*",
    "img-src": [
        "'self'",
        "data:"
    ],
    "upgrade-insecure-requests": true,
    "some-custom-directive": [
        "foo",
        "bar"
    ],
    "report-only": false
}
```
See also: [Policy](#policy), [Strict Policy](#strict-policy).

### Edit existing policy

Modify multiple directives at once
```julia
# Modify multiple directives at once
policy(
    # Pairs before kwargs
    "script-src" => ("'unsafe-inline'", "http://example.com"),
    img_src = ("'self'", "data:")
)
```
Modify single directive
```julia
# Modify individually via directive name
policy["img-src"] = CSP.wildcard # "*"
```

### Custom directives

Definition and manipulation of custom directives is supported.
```julia
using CSP

policy = Policy("custom"=>true, default=true) # Also apply default directives
policy["custom-directive"] = ("'self'", "blob:")
```
```json
{
    [...],
    "custom-directive": [
        "'self'",
        "blob:"
    ],
    "custom": true
}
```
```julia
policy(custom_header = ("*", "any"))
string(policy)
```
```text/plain
default-src 'self'; report-to default; custom; custom-directive 'self' blob:; custom-header any *;
```

### Build `http` header

**Content-Security-Policy** header
```julia
using CSP, HTTP

HTTP.Header(Policy(default=true))
```
```julia
"Content-Security-Policy" => "default-src 'self'; frame-ancestors none; base-uri none; report-to default; sandbox; script-src 'strict-dynamic'; object-src none"
```
**Report-Only** header
```julia
HTTP.Header(Policy("default-src"=>CSP.self, report_only=true))
```
```julia
"Content-Security-Policy-Report-Only" => "default-src 'self'; frame-ancestors none; base-uri none; report-to default; script-src 'strict-dynamic'; object-src none"
```

### Build `<meta>` element

Construction will automatically ignore directives that are not supported in the `<meta>` element. Currently `[frame-ancestors, report-uri, report-to, sandbox]`. 

See also [mdn csp directives](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP).
```julia
CSP.meta(Policy(report_to = "default", default_src="'self'"))
```
```xml
<meta http-equiv="Content-Security-Policy" content="default-src 'self'">
```

### Obtain CSP header as Dict
```julia
policy = csp("default-src"=>CSP.self, "img-src"=>(CSP.self, CSP.data), "report-uri"=>"/api/reports")

CSP.http(policy)
```
```
OrderedCollections.OrderedDict{String, Any} with 3 entries:
  "img-src"     => "data: 'self'"
  "default-src" => "'self'"
  "report-uri"  => "/api/reports"
```

## Web example

**Mockup** web application with dynamic CSP policies, that can also receive CSP violation reports.

The app allows route handlers to tailor the CSP Policy on each response.
```julia
using CSP, Dates, HTTP, JSON3, Random, Sockets

"""
A middleware that will set a restrictive default policy.

Allows route handlers to change the CSP Policy
"""
function CSPMiddleware(next)
    return function(request::HTTP.Request)

        function respond(response::HTTP.Response)
            timestamp = string(round(Int, datetime2unix(now())))
                
            # A default restrictive policy
            policy = csp(
                default = true, 
                default_src = "'self'", 
                script_src = "none",
                report_to = false,
                sandbox = true, 
                report_uri = "/reports/$timestamp") # report to specific endpoint

            if !isnothing(request.context)
                if haskey(request.context, :csp)
                    # Acquire the policy defined by the route and log
                    route_policy = request.context[:csp]
                    @info "Custom policy: $(string(route_policy))"

                    # Merge default with handler provided policy
                    policy = policy(route_policy.directives...)
                end 
            end
            # Check whether header was not yet defined
            if !HTTP.hasheader(response, CSP.CSP_HEADER)
                # Set CSP policy header
                HTTP.setheader(response, HTTP.Header(policy))
            end
            return response
        end
	return respond(next(request))
    end
end

"""
Handle posted CSP Reports
"""
function report(request::HTTP.Request)
    report = String(request.body)
    # Each report is posted to /reports/{timestamp}
    timestamp = Base.parse(Int, request.context[:params]["timestamp"])
    # Log timestamp as Date
    println(string("Timestamp: ", unix2datetime(timestamp)))
    # Log pretty json report
    JSON3.pretty(report)

    return HTTP.Response(200, report)
end

function restrictive(request::HTTP.Request)
    # Obtain a nonce
    nonce = CSP.csp_nonce()
    # Set a policy allowing scripts with our nonce, also enabling scripts and modals in sandbox mode
    request.context[:csp] = csp(script_src="'nonce-$nonce'", sandbox="allow-scripts allow-modals")

    html = """
    <html>
        <body>
            <!-- This will execute -->
            <script type="text/javascript", nonce='$nonce'>
                alert('I can execute!');
            </script>
            
            <!-- This should not execute -->
            <script type="text/javascript">
                alert('Not authorised!');
            </script>
        </body>
    </html>
    """
    return HTTP.Response(200, html)
end

function permissive(request::HTTP.Request)
    # Set permissive script-src to allow all inline scripts
    request.context[:csp] = csp("script-src"=>("'self'", "'unsafe-inline'"), "sandbox"=>false)

    html = """
    <html>
        <body>
            <div id="hello"></div>
            <script type="text/javascript">
                document.getElementById('hello').innerHTML = 'Scripts can execute!';
            </script>
            <script type="text/javascript">
                alert('Scripts can launch modals!');
            </script>
        </body>
    </html>
    """
    return HTTP.Response(200, html)
end

const csp_router = HTTP.Router()
HTTP.register!(csp_router, "GET", "/restrictive", restrictive)
HTTP.register!(csp_router, "GET", "/permissive", permissive)
# Handle incoming CSP reports
HTTP.register!(csp_router, "POST", "/reports/{timestamp}", report)

server = HTTP.serve!(csp_router |> CSPMiddleware, ip"0.0.0.0", 80)
```
See also: [web example](/examples/web).

## Policy from a JSON file

[Example configuration.json](/examples/conf.json)

```julia
policy = Policy("/path/to/conf.json")
```
```jldoctest
julia> policy["default-src"]

8-element Vector{String}:
 "'unsafe-eval'"
 "'unsafe-inline'"
 "data:"
 "filesystem:"
 "about:"
 "blob:"
 "ws:"
 "wss:"

julia> policy["script-src"]

3-element Vector{String}:
 "'unsafe-eval'"
 "'unsafe-inline'"
 "https://www.google-analytics.com"
```

# API Reference

## [Policy](@ref)

### Strict Policy 
```julia
const DEFAULT_POLICY
```
 _Work in progress._ A default, restrictive policy based on various CSP recommendations. Used when creating a Policy where `default = true`. 

**See also:** [OWASP CSP cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html), [mdn csp docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP), [csp.withgoogle.com](https://csp.withgoogle.com/docs/index.html), [CSP Is Dead, Long Live CSP!](https://storage.googleapis.com/pub-tools-public-publication-data/pdf/45542.pdf) and [strict-csp](https://web.dev/strict-csp/).

--------------------------------

```julia
const DirectiveTypes = Union{String, Set{String}, Vector{String}, Tuple, Bool}
```
Defines acceptable values of a directive.

`Empty` and `false` values are not considered when generating a CSP header.

----------------------------------------------------------

```julia
Policy(directives::AbstractDict, report_only=false)
```
| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `directives` | `Dict{String, DirectiveTypes}` | Set of directives that configure your policy
| `report_only` | `Bool` | **Optional**  Whether to define Policy as [report only](Content-Security-Policy-Report-Only). Defaults to `false`|

Default constructor. Policies are empty by default.
```julia
julia> Policy()
```
```json
{
    "report-only": false
}
```
------------------
```julia
Policy(directives::Pair...; default=false, report_only=false, kwargs...)
```
| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `directives` | `Pair{String,DirectiveTypes}` | Individual policies as a Pair.
| `default` | `Bool` | **Optional**  Whether to add default directives and default values. Defaults to `false`|
| `report_only` | `Bool` | **Optional**  Whether to define Policy as [report only](Content-Security-Policy-Report-Only). Defaults to `false`|
| `kwargs` | `Directives` | **Optional** Directives as keyword arguments. Automatically replaces `_` with `-` in known directives.|
```julia
Policy("script-src"=>"https://example.com/", "img-src"=>"*", report_only=true)
```
```json
{
    "img-src": "*",
    "script-src": "https://example.com/",
    "report-only": true
}
```
```julia
policy = Policy(
     # Set default-src
     default_src = CSP.self, # "'self'"
     # Set report-uri
     report_uri = "https://example.com",
     # Report endpoint
     report_to = "default",
     sandbox = "allow-downloads",
     # Turn on https enforcement
     upgrade_insecure_requests = true)
```
```json
{
    "upgrade-insecure-requests": true,
    "default-src": "'self'",
    "report-to": "default",
    "sandbox": "allow-downloads",
    "report-uri": "https://example.com",
    "report-only": false
}
```
-------------------------
```julia
Policy(json::String)
```
| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `json` | `String` | Path to json file, or json string |

Build a Policy from a JSON configuration.

See also: [Import from JSON](#policy-from-a-json-file)

----------------------------