using CSP
using HTTP
using JSON3
using Random
using Test

import CSP.compile
import CSP.compile_group
# constants
import CSP.data
import CSP.wildcard
import CSP.self
# Utils
import CSP.DIRECTIVES
import CSP._to_prop_name
import CSP._directive_name
import CSP.get_directive
import CSP.meta_excluded
import CSP.META_EXCLUDED

@testset "CSP Policy" begin
    policy = Policy(default=true);
    @test !policy.upgrade_insecure_requests
    @test !policy.sandbox
    @test isempty(policy.trusted_types)

    for key in keys(policy.directives)
        http_name = CSP.get_directive(key)
        @test policy[http_name] == getproperty(policy, Symbol(key))
    end

    @testset "Modify Policy" begin
        p = Policy(
            "img-src"=>(self, data),
            "object-src"=>[self],
            "report_uri"=>"/some/endpoint",
            "custom-header"=>false,
            "custom-directive"=>(1,true,"value"),
            default=true,
            report_only = true);

        p("object-src"=>wildcard)
        @test p.object_src == wildcard
        p(report_only = false)
        @test p.report_only == false
    end
end

@testset "Policy compilation" begin
    @test compile((1,2,false,true,"",Dict(),[], ["Foo", "Bar"])) == "1 2 Foo Bar"
    @test isempty(compile(String[]))
    @test isempty(compile(Set(String[])))
    @test compile(["A","","B"]) == "A B"
    @test compile(true) && isempty(compile(false)) && isempty(compile(nothing))
    _some_r = randstring(12)
    @test isempty(compile("")) && compile(_some_r) == _some_r &&
          isempty(compile("a"=>"")) && compile("a"=>_some_r) == "a $(_some_r)"
    @test compile("foo"=>true) == "foo" && isempty(compile("foo"=>false))
    _some_r = rand()
    @test compile(_some_r) == "$(_some_r)"

    policy = csp("default-src"=>self, "img-src"=>(self, data), "report-uri"=>"/api/reports")
    @test string(policy) == compile(policy) == compile_group(policy.directives)
    @test compile(policy) == "default-src 'self'; img-src 'self' data:; report-uri /api/reports"
end

@testset "Test utils" begin
    test_directives = replace.(DIRECTIVES, "-"=>"_")
    @test sort(test_directives) == sort(_to_prop_name.(DIRECTIVES))
    @test sort(test_directives) == sort(_to_prop_name.(Symbol.(DIRECTIVES)))

    @test sort(_directive_name.(test_directives)) == sort(DIRECTIVES)
    @test sort(_directive_name.(Symbol.(test_directives))) == sort(DIRECTIVES)

    [@test get_directive(d, "error") == d for d in DIRECTIVES]
    @test get_directive("a_b_custom", "error") == "error" &&
          get_directive("custom-header") == "custom-header"

    @test all(x->meta_excluded(x) && meta_excluded(Symbol(x)), META_EXCLUDED)
    @test all(x->meta_excluded(x), _to_prop_name.(META_EXCLUDED))
end
