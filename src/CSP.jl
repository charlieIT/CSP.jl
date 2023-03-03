"""
Content-Security-Policy: default-src 'self'; script-src https://example.com

is the same as:

Content-Security-Policy:
        connect-src 'self';
        font-src 'self';
        frame-src 'self';
        img-src 'self';
        manifest-src 'self';
        media-src 'self';
        object-src 'self';
        script-src https://example.com;
        style-src 'self';
        worker-src 'self'

[Content-Security-Policy @ mdn](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/default-src)
"""
module CSP

    export Policy, csp

    using HTTP
    using JSON3
    using OrderedCollections
    using Random
    using SHA

    include("constants.jl")
    include("utils.jl")
    include("policy.jl")
    include("http.jl") # headers and meta
    include("json.jl")
    include("nonce.jl")

    function csp(args...; kwargs...)
        return Policy(args...; kwargs...)
    end

end
