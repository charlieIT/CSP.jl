using CSP, Dates, HTTP, JSON3, Random, Sockets

#=
Simple web application with dynamic CSP policies, that can also receive CSP violation reports.

The example app will allow route handlers to tailor the CSP Policy on each response.
=#

"""
A middleware that will set a restrictive default policy.

Allows route handlers to change the CSP Policy, based on a page's specific use-case
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
function reports(request::HTTP.Request)
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
    # Set a policy allowing scripts with our nonce and enabling scripts and modals in sandbox mode
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
HTTP.register!(csp_router, "POST", "/reports/{timestamp}", reports)

server = HTTP.serve!(csp_router |> CSPMiddleware, ip"0.0.0.0", 80)

#= Example custom policy log for `restrictive endpoint`

[ Info: Custom policy: sandbox allow-scripts allow-modals; script-src 'nonce-c45e32868c90f16e0c7276bf11c3e5f7a0e9d59b4edba2989e9253358b2b1890'
=#

#= Example custom policy log for `permissive policy`

[ Info: Custom policy: script-src 'self' 'unsafe-inline'
=#

# Example Report log
#=
Timestamp: 2023-02-15T22:34:11
{
    "csp-report": {
        "document-uri": "http://127.0.0.1:80/restrictive",
        "referrer": "",
        "violated-directive": "script-src-elem",
        "effective-directive": "script-src-elem",
        "original-policy": "default-src 'self'; frame-ancestors none; report-uri /reports/1676500451; base-uri none; sandbox allow-scripts allow-modals; script-src 'nonce-42bdd9907bc461c4233174e70b6c2aac1e7804ad67128014504529a3b830b78b'; object-src none",
        "disposition": "enforce",
        "blocked-uri": "inline",
        "line-number": 10,
        "source-file": "http://127.0.0.1:80/restrictive",
        "status-code": 200,
        "script-sample": ""
    }
}
=#
