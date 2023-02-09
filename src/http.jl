const CSP_HEADER = "Content-Security-Policy"
const META_EXCLUDED = [:frame_ancestors, :report_uri, :report_to, :sandbox]

function Base.Dict(policy::Policy)
    return OrderedDict{String, Any}([string(prop)=>getproperty(policy, prop) for prop in fieldnames(Policy)])
end

"""
    http(::Policy; except, kwargs...)::OrderedDict

Build a `Dict` with keys matching CSP directive names, as used in http requests

Automatically ignores properties for which values are empty, false or nothing.

Dict values are the string representation of their value in the policy instance
"""
function http(policy::Policy; kwargs...)::OrderedDict
    return http(Dict(policy); kwargs...)
end

function http(policy::AbstractDict; except::Vector{Symbol}=Symbol[])::OrderedDict
    http = OrderedDict([_directive_name(k)=>v for (k,v) in policy if !(Symbol(k) in except)])
    for (key, value) in http
        if isnothing(value) || value == false || isempty(value)
            pop!(http, key)
            continue;
        end
        if any(x->isa(value, x), [Vector, Set, Tuple])
            value = filter(x->!isempty(x), Set(collect(value)))
            if isempty(value)
                pop!(http, key)
            end
        end
        if any(x->isa(value, x), [Vector, Set, Tuple]) && !isempty(value)
            value = join(value, " ")
        end
        http[key] = value
    end
    return http
end

function headers(policy::Policy; except::Vector{Symbol}=Symbol[])::Vector{HTTP.Header}
    values = Dict([k=>(v == true ? "" : v) for (k,v) in http(Dict(policy), except=except) if !isnothing(v) && v !== false && !isempty(v)])

    csp_header = HTTP.Header(
        SubString(CSP_HEADER),
        SubString(join([join(pair, " ") for pair in values], "; "))
    )
    return [csp_header]
end

function meta(policy::Policy; except=META_EXCLUDED)
    http = headers(policy, except=except)
    base_str = "<meta http-equiv=\"Content-Security-Policy\" content=\"{}\""
    csp_headers = filter(x->first(x) == "Content-Security-Policy", http)
    if isempty(csp_headers)
        return string(replace(base_str, "{}"=>""))
    end
    return string(replace(base_str, "{}"=>last(csp_headers[1])))
end
