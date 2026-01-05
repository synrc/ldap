import Config

config :ldap,
  port: 1489,
  instance: "D4252CF20538EC22",
  module: LDAP,
  logger_level: :info,
  logger: [{:handler, :default2, :logger_std_h,
            %{level: :info,
              id: :synrc,
              max_size: 2000,
              module: :logger_std_h,
              config: %{type: :file, file: ~c"ldap.log"},
              formatter: {:logger_formatter,
                          %{template: [:time,~c" ",:pid,~c" ",:module,~c" ",:msg,~c"\n"],
                            single_line: true,}}}}]


