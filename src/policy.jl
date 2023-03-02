mutable struct Policy
    directives::AbstractDict{String, DirectiveTypes}
    report_only::Bool

    function Policy(directives::AbstractDict, report_only::Bool=false)
        directives = Base.convert(OrderedDict{String, DirectiveTypes}, directives)
        return new(directives, report_only)
    end

    function Policy(directives::Pair...; default::Bool=false, report_only::Bool=false, kwargs...)
        tmp = OrderedDict{Any, Any}([get_directive(k)=>v for (k,v) in Dict(kwargs...)])
        d = OrderedDict{Any, Any}([first(p)=>last(p) for p in collect(directives)])
        merge!(d, tmp) # merge kw based directive into directives
        if default
            d = merge(DEFAULT_POLICY, tmp)
        end
        return Policy(d, report_only)
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
    return getindex(policy, get_directive(key))
end

function Base.setproperty!(policy::Policy, prop::Symbol, value)
    if hasproperty(Policy, prop)
        return setfield!(policy, prop, value)
    end
    return setindex!(policy, value, get_directive(prop))
end

function Base.Dict(policy::Policy)::Dict
    directives = Base.convert(Dict{String, Any}, getfield(policy, :directives))
    [directives[_directive_name(prop)] = getfield(policy, prop) for prop in fieldnames(Policy) if prop != :directives]
    return directives
end

function Policy(json::String)
    if isfile(json)
        json = String(read(json))
    end
    input = JSON3.read(json, Dict)
    return Base.convert(Policy, input)
end

function Base.convert(::Type{Policy}, header::String)
    tmp = Policy(default=false)
    directives = string.(strip.(split(header, ";")))
    #parts = [match(r"(?-s)(\S+) +(.+)", x) for x in directives]
    for directive in directives
        dir, parts... = string.(split(directive, " "))
        value = parts
        if isempty(parts)
            value = true
        end
        tmp[string(dir)] = value
    end
    return tmp
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

"""
    compile(policy::Policy)::String
"""
function compile(policy::Policy)::String
    return compile_group(policy.directives)
end

function compile_group(directives::AbstractDict)::String
    elements = [strip(compiled) for compiled in [compile(p) for p in directives] if !isempty(compiled)]
    return join(string.(elements), "; ")
end

function compile(p::Pair)
    tmp = Pair(first(p), last(p)) # force values to specific types by constructing new Pair
    return compile(first(tmp), last(tmp))
end

# generic behaviour
function compile(dir::String, value)
    return string(dir, " ", compile(value))
end

function compile(dir::String, value::Bool)
    return value ? dir : ""
end
function compile(dir::String, value::Union{Set, Vector})
    val = compile(value)
    if !isempty(val)
        vals = join(string.([dir, val]), " ")
        return string(vals)
    end
    return ""
end
compile(::String,    value::Nothing) = ""
compile(dir::String, value::Tuple)   = compile(dir, collect(value))
compile(dir::String, value::String)  = compile(dir, [value])


#= Value compilation =#
function compile(value::Union{Vector, Set, Tuple})
    # filter nothing, empty or false elements in an input collection
    function filter_func(input)
        return filter(x->!isnothing(x) && !isempty(x) && x !== false, input)
    end

    vals = filter_func(unique(collect(value)))
    if isempty(value)
        return ""
    end
    vals = filter_func(compile.(vals))
    return join(compile.(vals), " ")
end

function compile(d::AbstractDict)
    return JSON3.write(d)
end
compile(value::String) = value
compile(value::Nothing) = ""
compile(value::Bool) = value === true ? true : ""
compile(any) = string(any)

function Base.string(policy::Policy)
    return string(compile(policy))
end
