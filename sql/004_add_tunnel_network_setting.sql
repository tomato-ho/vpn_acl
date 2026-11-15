INSERT INTO vpn_settings (name, value)
VALUES ('tunnel_network', '10.8.0.0/24')
ON DUPLICATE KEY UPDATE name = name;