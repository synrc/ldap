defmodule LDAP do
    use Application
    use Supervisor
    require Record
    Enum.each(Record.extract_all(from_lib: "ldap/include/LDAP.hrl"),
             fn {name, definition} -> Record.defrecord(name, definition) end)

   def init([]), do: {:ok, { {:one_for_one, 5, 10}, []} }
   def start(_type, _args) do
       :logger.add_handlers(:ldap)
       :supervisor.start_link({:local, __MODULE__}, __MODULE__, [])
   end

end