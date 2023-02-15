using CSP

using CSP
policy = Policy(
	# Set fallback for all fetch directives
	"default-src"=>"*",
	# Set valid sources of images and favicons
	"img-src"=>("'self'", "data:"),
	# Turn on https enforcement
	"upgrade-insecure-requests"=>true,
	# Set custom directives, if needed
	"some-custom-directive"=>["foo", "bar"]
)

# Modify multiple directives at once
policy(
    # Pairs before kwargs
    "script-src" => ("'unsafe-inline'", "http://example.com"),
    img_src = ("'self'", "data:")
)

# Modify individually via header name
policy["img-src"] = CSP.wildcard # "*"

# Definition and manipulation of custom directives is supported.
policy = Policy(default=true)
policy(custom_header = ("*", "any"))
policy["custom-directive"] = true