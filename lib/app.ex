defmodule LDAP do
   require Record
   Enum.each(Record.extract_all(from_lib: "ldap/include/LDAP.hrl"),
             fn {name, definition} -> Record.defrecord(name, definition) end)

end