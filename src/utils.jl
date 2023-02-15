function _to_prop_name(directive::String)::String
    return string(replace(directive, "-"=>"_"))
end
_to_prop_name(directive::Symbol) = _to_prop_name(string(directive))

function _directive_name(prop::String)::String
    return string(replace(prop, "_"=>"-"))
end
_directive_name(prop::Symbol) = _directive_name(string(prop))

function get_directive(key, default::String=string(key))::String
    key = _directive_name(string(key))
    if key in DIRECTIVES
        return key
    end
    return default
end