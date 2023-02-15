function csp_nonce()
    return bytes2hex(sha256(randstring(RandomDevice(), UInt8, 128)))
end

"""
    function none!(policy, directive::String)

Creates a `nonce`, applies it to policy[directive] and returns the nonce
"""
function nonce!(policy::Policy, key::String)::String
    value = policy[key]
    nonce = csp_nonce()
    
    nonce_str = "'nonce-$nonce'"
    if isnothing(value) || isa(value, Bool) || isempty(value)
        value = [nonce_str]
    else
        if isa(value, String)
            value = [value, nonce_str]
        else
            value = push!(collect(value), nonce_str)
        end
    end
    policy[key] = value
    return nonce
end
