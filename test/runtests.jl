using CSP
using HTTP
using JSON3
using Test

@testset "CSP.Policy" begin 
    policy = Policy(default=true);
    @test !policy.upgrade_insecure_requests
    @test !policy.sandbox
    @test isempty(policy.trusted_types)

    for key in keys(policy.directives)
        http_name = CSP.get_directive(key)
        @test policy[http_name] == getproperty(policy, Symbol(key))
    end
end

# @testset "CSP Dict and http" begin 
#     policy = Policy(
#         default_src = CSP.self,
#         report_uri = "https://example.com",
#         sandbox = "allow-downloads",
#         report_to = "default",
#         frame_ancestors = CSP.wildcard,
#         upgrade_insecure_requests = true
#     )
#     dpolicy = Dict(policy)
#     @test all(x->Symbol(x) in fieldnames(Policy), keys(dpolicy))
#     hpolicy = CSP.http(policy)
#     for prop in fieldnames(Policy)
#         val = getproperty(policy, prop)
#         if isnothing(val) || isempty(val) || val == false
#             @test !(CSP._directive_name(prop) in keys(hpolicy))
#         end
#     end
# end

# @testset "CSP.headers" begin
#     policy = Policy(
#         default_src = nothing,
#         img_src = nothing,
#         report_to = nothing,
#     );
#     test_headers = CSP.headers(policy)
#     @test !isempty(test_headers)
#     csp_header = first(test_headers)
#     @test first(csp_header) == CSP.CSP_HEADER
#     @test isempty(last(csp_header))
#     @test policy["default-src"] === nothing

#     # update properties in-place
#     policy(
#         default_src = CSP.none,
#         report_uri = "https://example.com",
#         sandbox = "allow-downloads",
#         report_to = "default",
#         frame_ancestors = CSP.wildcard
#     )
    
#     csp_header = first(HTTP.Header(policy))
#     csp_directives = last(csp_header)
#     @test csp_directives == string(policy)
#     @test occursin("default-src none", csp_directives)
#     @test occursin("frame-ancestors *", csp_directives)
#     @test occursin("report-to default", csp_directives)
#     @test occursin("report-uri https://example.com", csp_directives)
#     @test occursin("sandbox allow-downloads", csp_directives)

#     csp_header = first(CSP.headers(policy, except=CSP.META_EXCLUDED))
#     csp_directives = last(csp_header)
#     @test csp_directives == "default-src none"

#     @testset "JSON serialization" begin
#         policy = Policy("assets/small.json")
#         cpolicy = Base.convert(Policy, JSON3.read(String(read("assets/small.json")), Dict))
#         @test policy["default-src"] == Set(["'self'"]) == cpolicy.default_src
#         @test isempty(policy["object-src"]) && isempty(cpolicy.object_src)
#         @test policy["upgrade-insecure-requests"] == cpolicy.upgrade_insecure_requests == true
#         @test policy.style_src == Set(["styles.example.com"])
#         @test all(x->x in ["'unsafe-eval'", "scripts.example.com"], policy["script-src"])
#     end
# end