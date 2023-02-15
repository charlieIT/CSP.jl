const META_EXCLUDED = ["frame-ancestors", "report-uri", "report-to", "report-only", "sandbox"]

function meta_excluded(header::String, exceptions=META_EXCLUDED)::Bool
    return  any(x->x in exceptions, [header, _directive_name(header)])
end
meta_excluded(prop::Symbol)::Bool = meta_excluded(string(prop))

"""
    http(::Policy; except, kwargs...)::OrderedDict

Build a `Dict` with keys matching CSP directive names, as used in http requests

Automatically ignores properties for which values are empty, false or nothing.

Dict values are the string representation of their value in the policy instance
"""
function http(policy::Policy; kwargs...)::OrderedDict
    # Enforce directive names to "-" separated names as per `https://www.w3.org/TR/CSP3/#grammardef-directive-name`
    directives = OrderedDict([_directive_name(k)=>v for (k,v) in policy.directives])
    for (key, value) in directives
        if isnothing(value) || value == false || isempty(value)
            pop!(directives, key)
            continue;
        end
        if any(x->isa(value, x), [Vector, Set, Tuple])
            value = filter(x->!isempty(x), Set(collect(value)))
            if isempty(value)
                pop!(directives, key)
            end
        end
        if any(x->isa(value, x), [Vector, Set, Tuple]) && !isempty(value)
            value = join(value, " ")
        end
        directives[key] = value
    end
    return directives
end

function headers(policy::Policy)::Vector{HTTP.Header}
    return [HTTP.Header(policy)]
end

function HTTP.Header(policy::Policy)::HTTP.Header
    values = Dict([k=>(v == true ? "" : v) for (k,v) in http(policy) if !isnothing(v) && v !== false && !isempty(v)])

    # Is it a report only policy?
    header = policy.report_only ? SubString(CSP_REPORT_ONLY_HEADER) : SubString(CSP_HEADER)
    if policy.report_only && !haskey(values, "report-to")
        @warn "Defining Report-Only policy without `report-to` directive. Ref: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only"
    end
    return HTTP.Header(
        header,
        SubString(_compile(values))
    )
end

function meta(policy::Policy; except=META_EXCLUDED)
    dict = http(policy)
    dict = filter((kv)->!meta_excluded(kv.first, except), dict)
    base_str = """<meta http-equiv="Content-Security-Policy" content=\"{}\">"""
    return string(replace(base_str, "{}"=>_compile(dict)))
end

function _compile(d::AbstractDict)
    return join([strip(join(pair, " ")) for pair in d], "; ")
end
