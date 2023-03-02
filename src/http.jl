"""
    http(::Policy; except, kwargs...)::OrderedDict

Build a `Dict` with keys matching CSP directive names, as used in http requests

Automatically ignores properties for which values are empty, false or nothing.

Dict values are the string representation of their value in the policy instance
"""
function http(policy::Policy; kwargs...)::OrderedDict
    # Enforce directive names to "-" separated names as per `https://www.w3.org/TR/CSP3/#grammardef-directive-name`
    directives = OrderedDict{Any, Any}([_directive_name(k)=>v for (k,v) in policy.directives])

    for (k,v) in directives
        value = compile(v)
        if isempty(value)
            pop!(directives, k)
        else
            directives[k] = value
        end
    end
    return directives
end

function HTTP.Header(policy::Policy)::HTTP.Header
    values = http(policy)
    # Is it a report only policy?
    header = policy.report_only ? CSP_REPORT_ONLY_HEADER : CSP_HEADER
    if policy.report_only && !haskey(values, "report-to")
        @warn "Defining Report-Only policy without `report-to` directive. Ref: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only"
    end
    return HTTP.Header(
        header,
        compile_group(values)
    )
end

function meta(policy::Policy; except=META_EXCLUDED)::String
    tmp = deepcopy(policy)
    tmp.directives = filter((kv)->!meta_excluded(kv.first, except), tmp.directives)
    base_str = """<meta http-equiv="Content-Security-Policy" content=\"{}\">"""
    return string(replace(base_str, "{}"=>compile(tmp)))
end
