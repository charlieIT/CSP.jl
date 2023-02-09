function _to_prop_name(directive::String)
    return replace(directive, "-"=>"_")
end
_to_prop_name(directive::Symbol) = _to_prop_name(string(directive))

function _directive_name(prop::String)
    return replace(prop, "_"=>"-")
end
_directive_name(prop::Symbol) = _directive_name(string(prop))