DELETE FROM vpn_server_services
WHERE scope_type = 'global'
  AND service IN ('10.8.0.1:53/udp', '10.8.0.1:53/tcp');