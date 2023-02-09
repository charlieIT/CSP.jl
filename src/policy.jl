const wildcard      = "*"
const none          = "none"
const self          = "'self'"
const unsafe_inline = "'unsafe-inline'"
const unsafe_eval   = "'unsafe-eval'"

const sandbox_values = []

"""
    const DirectiveTypes

* Nothing: Directive will be absent from policy
* Empty Tuple or Set: 
* True: only key is added to policy header
"""
const DirectiveTypes = Union{Nothing, String, Set{String}, Vector{String}, Tuple}

"""
    const ReportToTypes

* String: JSON 
* Nothing: Directive will be absent from policy
* 
"""
const ReportToTypes  = Union{Nothing, String}

const SandboxTypes   = Union{Nothing, String, Bool}
const TrustedTypes   = Union{Bool, DirectiveTypes}

"""
    mutable struct Policy

Policy properties affect a content-security policy header

See also: `headers.jl`
"""
Base.@kwdef mutable struct Policy
    base_uri::DirectiveTypes            = nothing # do not set automatically, does not use default-src for fallback
    child_src::DirectiveTypes           = nothing
    connect_src::DirectiveTypes         = ()
    default_src::DirectiveTypes         = self
    font_src::DirectiveTypes            = ()
    form_action::DirectiveTypes         = nothing # does not use default-src for fallback
    frame_ancestors::DirectiveTypes     = nothing
    frame_src::DirectiveTypes           = nothing
    img_src::DirectiveTypes             = (self,) # (self, "data:")
    manifest_src::DirectiveTypes        = nothing
    media_src::DirectiveTypes           = nothing
    object_src::DirectiveTypes          = nothing
    prefetch_src::DirectiveTypes        = nothing
    # Reporting Directives
    # https://w3c.github.io/reporting/#group
    report_to::ReportToTypes            =  "default" # Nothing, String, # does not use default-src for fallback
    report_uri::DirectiveTypes          = nothing
    # local extension to handle and generate report-to response headers
    #report_groups::ReportGroups         = nothing
    # end Reporting Directives

    # Content-Security-Policy: sandbox; Content-Security-Policy: sandbox <value>;
    sandbox::SandboxTypes               =  nothing # does not use default-src for fallback
    script_src::DirectiveTypes          =  nothing
    script_src_attr::DirectiveTypes     =  nothing
    script_src_elem::DirectiveTypes     =  nothing
    style_src::DirectiveTypes           =  nothing
    style_src_attr::DirectiveTypes      =  nothing
    style_src_elem::DirectiveTypes      =  nothing
    upgrade_insecure_requests::Bool     =  false
    worker_src::DirectiveTypes          =  nothing
    # Trusted Types Directives
    trusted_types::TrustedTypes         =  nothing # Content-Security-Policy: trusted-types;
    require_trusted_types_for::DirectiveTypes = nothing
    # end trusted types
end

function (policy::Policy)(;kwargs...)
    [Base.setproperty!(policy, name, value) for (name,value) in Dict(kwargs...) if name in fieldnames(Policy)]
    return policy
end

function Base.getindex(policy::Policy, idx::String)
    idx = string(replace(idx, "-"=>"_"))
    if Symbol(idx) in fieldnames(Policy)
        return Base.getproperty(policy, Symbol(idx))
    end
end

function Base.setindex!(policy::Policy, value, idx::String)
    idx = string(replace(idx, "-"=>"_"))
    if Symbol(idx) in fieldnames(Policy)
        return Base.setproperty!(policy, Symbol(idx), value)
    end
end

function Base.string(policy::Policy)
    return last(first(headers(policy)))
end

function Policy(json::String)
    if isfile(json)
        json = String(read(json))
    end
    input = JSON3.read(json, Dict)
    return Base.convert(Policy, input)
end

function Base.convert(::Type{Policy}, d::AbstractDict)
    parsed = Dict{Any, Any}([Symbol(_to_prop_name(k))=>v for (k,v) in d])
    for (k,v) in parsed
        if isa(v, Vector) || isa(v, Set)
            v = Set{String}(string.(v))
        elseif !isa(v, Bool)
            v = string(v)
        end
        parsed[k] = v
    end
    return Policy(;parsed...)
end

"""
    DefaultPolicy(sources...)
"""
function Policy(
    sources...;
    font_src    = (),
    img_src     = (),
    script_src  = (),
    style_src   = (),
    kwargs...)

    return Policy(
        default_src =
            [
            "'unsafe-eval'",
            "'unsafe-inline'",
            "data:",
            "filesystem:",
            "about:",
            "blob:",
            "ws:",
            "wss:",
            string.(directives)...,],
        font_src    = font_src,
        img_src     = img_src,
        script_src  = script_src,
        style_src   = style_src,
        kwargs...
    )
end