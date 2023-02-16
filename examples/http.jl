using CSP, HTTP

HTTP.Header(Policy(default=true))
#=
"Content-Security-Policy" => "default-src 'self'; frame-ancestors none; base-uri none; report-to default; sandbox; script-src 'strict-dynamic'; object-src none"
=#

CSP.meta(Policy(report_to = "default", default=true))
#=
<meta http-equiv="Content-Security-Policy" content="base-uri none; default-src 'self'; object-src none; script-src 'strict-dynamic'">
=#

CSP.meta(Policy(report_to = "default", default_src="'self'"))
#=
<meta http-equiv=\Content-Security-Policy" content="default-src 'self'">
=#

policy = csp("default-src"=>CSP.self, "img-src"=>(CSP.self, CSP.data), "report-uri"=>"/api/reports")
CSP.http(policy)
#=
OrderedCollections.OrderedDict{String, Any} with 3 entries:
  "img-src"     => "data: 'self'"
  "default-src" => "'self'"
  "report-uri"  => "/api/reports"
=#