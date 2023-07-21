use Mix.Config

config :ldap,
  logger_level: :info,
  logger: [{:handler, :default2, :logger_std_h,
            %{level: :info,
              id: :synrc,
              max_size: 2000,
              module: :logger_std_h,
              config: %{type: :file, file: 'ldap.log'},
              formatter: {:logger_formatter,
                          %{template: [:time,' ',:pid,' ',:module,' ',:msg,'\n'],
                            single_line: true,}}}}]


