mutable struct Policy
    directives::AbstractDict{String, DirectiveTypes}
    report_only::Bool
    #nonces::NonceStore
        
    function Policy(directives::AbstractDict, report_only::Bool=false)
        directives = Base.convert(OrderedDict{String, DirectiveTypes}, directives)
        return new(directives, report_only)
    end

    function Policy(; default::Bool=false, report_only::Bool=false, kwargs...)
        tmp = OrderedDict([get_directive(k)=>v for (k,v) in Dict(kwargs...)])
        if default
            tmp = merge(DEFAULT_POLICY, tmp)
        end
        return Policy(tmp, report_only)
    end

    function Policy(directives::Pair...; default::Bool=false, report_only::Bool=false)
        d = Dict{Any, Any}([Symbol(first(p))=>last(p) for p in collect(directives)])
        return Policy(;default=default, report_only=report_only, d...)
    end
end

function (policy::Policy)(pairs::Pair...; kwargs...)
    for (name, value) in merge(Dict(pairs), Dict(kwargs...))
        if hasproperty(Policy, Symbol(name))
            Base.setproperty!(policy, name, value)
        else
            name = get_directive(name)
            setindex!(getfield(policy, :directives), value, string(name))
        end
    end
    return policy
end

function Base.getindex(policy::Policy, idx::String)
    return getindex(getfield(policy, :directives), idx)
end
    
function Base.setindex!(policy::Policy, value, idx::String)
    return policy(;[(Symbol(idx), value)]...)
end

function hasproperty(::Type{Policy}, prop::Symbol)
    return prop in fieldnames(Policy)
end

function Base.getproperty(policy::Policy, key::Symbol)
    if hasproperty(Policy, key) 
        return getfield(policy, key)
    end
    return getindex(policy, string(key))
end

function Base.setproperty!(policy::Policy, prop::Symbol, value)
    if hasproperty(Policy, prop)
        return setfield!(policy, prop, value)
    end
    return setindex!(policy, value, string(prop))
end

function Base.Dict(policy::Policy)::Dict
    directives = Base.convert(Dict{String, Any}, getfield(policy, :directives))
    [directives[_directive_name(prop)] = getfield(policy, prop) for prop in fieldnames(Policy) if prop != :directives]
    return directives
end
    
function Base.string(policy::Policy)
    return last(HTTP.Header(policy))
end

function Policy(json::String)
    if isfile(json)
        json = String(read(json))
    end
    input = JSON3.read(json, Dict)
    return Base.convert(Policy, input)
end

function Base.convert(::Type{Policy}, d::AbstractDict)
    report_only = get(d, "report-only", get(d, "report_only", false))
    directives  = filter((kv)->!hasproperty(Policy, Symbol(kv.first)), d)
    for (k,v) in directives
        if isa(v, Vector) || isa(v, Set)
            v = collect(Set{String}(string.(v)))
        elseif !isa(v, Bool)
            v = string(v)
        end
        directives[k] = v
    end
    return Policy(directives...; report_only=report_only, default=false)
end