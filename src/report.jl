using StructTypes

Base.@kwdef mutable struct ReportEndpoint
    url::String
    name::Union{Nothing, String}    = nothing
    failures::Union{Nothing, Int}   = nothing
end
# StructTypes.StructType(::Type{ReportEndpoint}) = StructTypes.Mutable()
# StructTypes.keywordargs(::Type{ReportEndpoint}) = (name=(nothing,), failures=(nothing,))
Base.Dict(endp::ReportEndpoint) = filter((kv)->!isnothing(kv.second), Dict(string.(fieldnames(ReportEndpoint)) .=> getfield.(Ref(endp), fieldnames(ReportEndpoint))))
Base.convert(::Type{ReportEndpoint}, endp::AbstractDict) = ReportEndpoint(;Dict([Symbol(k)=>v for (k,v) in endp])...)

"""
    struct ReportEndpoint

See also: [W3C CSP Reporting](https://www.w3.org/TR/reporting-1/#endpoint)
"""
Base.@kwdef mutable struct ReportGroup
    group::String                       = ""
    max_age::Int                        = 0
    include_subdomains::Bool            = false
    endpoints::Vector{ReportEndpoint}   = ReportEndpoint[]
end
function ReportGroup(name::String, url::String)
    return ReportGroup(group=name, endpoints=[ReportEndpoint(url=url)])
end
const EMPTY_GROUPS = ReportGroup[]

function Base.Dict(group::ReportGroup)
    base = Dict(string.(fieldnames(ReportGroup)) .=> getfield.(Ref(group), fieldnames(ReportGroup)))
    base["endpoints"] = Dict.(base["endpoints"])
    #[x["name"] = group.group for x in base["endpoints"] if isnothing(get(x, "name", nothing))]
    return filter((kv)-> kv.second != false, base)
end

StructTypes.StructType(::Type{ReportGroup}) = StructTypes.Mutable()
StructTypes.names(::Type{ReportGroup}) = (
    (:max_age,   Symbol("max-age")), 
    (:group,     :group),
    (:endpoints, :endpoints),
    (:include_subdomains,  Symbol("include-subdomains")),
)

const GroupTypes = Union{AbstractDict, ReportGroup}

Base.@kwdef mutable struct CSPReport
    blocked_uri::String                 = ""
    disposition::String                 = ""
    document_uri::String                = ""
    effective_directive::String         = "" 
    violated_directive::String          = "" 
    original_policy::String             = ""
    status_code::Int                    = 0
    line_number::Union{Nothing, Int}    = nothing
    column_number::Union{Nothing, Int}  = nothing
    sample::String                      = ""
    referrer::String                    = ""
    source_file::Union{Nothing, String} = nothing
end

StructTypes.StructType(::Type{CSPReport}) = StructTypes.Mutable()
StructTypes.names(::Type{CSPReport}) = (
    (:blocked_uri,          Symbol("blocked-uri")), 
    (:column_number,        Symbol("column-number")), 
    (:document_uri,         Symbol("document-uri")), 
    (:effective_directive,  Symbol("effective-directive")), 
    (:line_number,          Symbol("line-number")),
    (:original_policy,      Symbol("original-policy")), 
    (:referrer,             Symbol("referrer")), 
    (:source_file,          Symbol("source-file")), 
    (:status_code,          Symbol("status-code")), 
    (:violated_directive,   Symbol("violated-directive")), 
)
Base.Dict(report::CSPReport) = JSON3.read(JSON3.write(report), Dict)

function HTTP.Header(group::ReportGroup)::HTTP.Header
    return HTTP.Header(
        "Report-to",
        JSON3.write(Dict(group))
    )
end

function HTTP.Header(endpoint::ReportEndpoint)::HTTP.Header
    directive = ""
    if !isnothing(endpoint.name)
       directive = string(endpoint.name, "=", endpoint.url) 
    end
    return HTTP.Header(
        "Reporting-Endpoints",
        directive
    )
end

#=function report_to(policy)
    return []
end

function HTTP.Headers(policy::Policy)::Vector{HTTP.Header}
    header = [HTTP.Header(policy)]
    report_to_header = report_to(policy)
    if !isempty(report_to_header)
        push!(header, report_to_header)
    end
    return header
end
=#

