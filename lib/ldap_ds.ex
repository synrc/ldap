defmodule LDAP.DS do
    @moduledoc "The LDAPv3 ASN.1 imported definitions."
    require Record
    Enum.each(Record.extract_all(from_lib: "ldap/include/LDAP.hrl"),
             fn {name, definition} -> Record.defrecord(name, definition) end)
end
