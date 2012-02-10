{application, eds,
 [
  {description, "Erlang Directory Server"},
  {vsn, "0.1.2"},
  {id, "eds"},
  {modules,      [tcp_listener, eds_ops, eds_fsm, eds_filter, eds_object, eds_msg, 'LDAP', rbtree]},
  {registered,   [tcp_server_sup, client_sup, ops_sup, tcp_listener]},
  {applications, [kernel, stdlib]},
  {mod, {eds_app, []}},
  {env, []}
 ]
}.
