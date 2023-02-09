using JSON3

function JSON3.write(policy::Policy, args...; kwargs...)
    return JSON3.write(http(Dict(policy)))
end

function JSON3.write(fname::String, policy::Policy, args...; kwargs...)
    open(fname, "w") do io
        JSON3.pretty(io, JSON3.write(policy, args...; kwargs...))
    end
end