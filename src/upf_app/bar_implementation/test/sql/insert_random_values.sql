-- Insert fake values into ipv4_headers table
INSERT INTO ipv4_headers (version, header_length, type_of_service, total_length, identification, flags, fragment_offset, time_to_live, protocol, header_checksum, source_ip, destination_ip) 
VALUES 
('4', (5 + FLOOR(RAND() * 4)), FLOOR(RAND() * 256), ((5 + FLOOR(RAND() * 4)) * 4), FLOOR(RAND() * 65536), (SELECT ELT(1 + FLOOR(RAND() * 4), 'SYN', 'ACK', 'FIN', 'RST')), FLOOR(RAND() * 8192), FLOOR(RAND() * 256), FLOOR(RAND() * 256), FLOOR(RAND() * 65536), CONCAT(FLOOR(RAND() * 256), '.', FLOOR(RAND() * 256), '.', FLOOR(RAND() * 256), '.', FLOOR(RAND() * 256)), CONCAT(FLOOR(RAND() * 256), '.', FLOOR(RAND() * 256), '.', FLOOR(RAND() * 256), '.', FLOOR(RAND() * 256)))
-- Add more fake values as needed

-- Insert fake values into tcp_headers table
INSERT INTO tcp_headers (ipv4_header_id, source_port, destination_port, sequence_number, acknowledgment_number, data_offset, reserved, flags, window_size, checksum, urgent_pointer) 
VALUES 
((FLOOR(RAND() * 10) + 1), FLOOR(RAND() * 65536), FLOOR(RAND() * 65536), FLOOR(RAND() * 4294967296), FLOOR(RAND() * 4294967296), (5 + FLOOR(RAND() * 4)), 0, (SELECT ELT(1 + FLOOR(RAND() * 4), 'SYN', 'ACK', 'FIN', 'RST')), FLOOR(RAND() * 65536), FLOOR(RAND() * 65536), FLOOR(RAND() * 65536))
-- Add more fake values as needed

-- Insert fake values into udp_headers table
INSERT INTO udp_headers (ipv4_header_id, source_port, destination_port, length, checksum) 
VALUES 
((FLOOR(RAND() * 10) + 1), FLOOR(RAND() * 65536), FLOOR(RAND() * 65536), (FLOOR(RAND() * 1472) + 28), FLOOR(RAND() * 65536))
-- Add more fake values as needed

-- Insert fake values into icmp_headers table
INSERT INTO icmp_headers (ipv4_header_id, type, code, checksum, rest_of_header) 
VALUES 
((FLOOR(RAND() * 10) + 1), FLOOR(RAND() * 256), FLOOR(RAND() * 256), FLOOR(RAND() * 65536), 'Some additional data')
-- Add more fake values as needed

-- Insert fake values into ethernet_headers table
INSERT INTO ethernet_headers (source_mac, destination_mac, protocol, ipv4_header_id) 
VALUES 
(CONCAT(HEX(FLOOR(RAND() * 256)), ':', HEX(FLOOR(RAND() * 256)), ':', HEX(FLOOR(RAND() * 256)), ':', HEX(FLOOR(RAND() * 256)), ':', HEX(FLOOR(RAND() * 256)), ':', HEX(FLOOR(RAND() * 256))), CONCAT(HEX(FLOOR(RAND() * 256)), ':', HEX(FLOOR(RAND() * 256)), ':', HEX(FLOOR(RAND() * 256)), ':', HEX(FLOOR(RAND() * 256)), ':', HEX(FLOOR(RAND() * 256)), ':', HEX(FLOOR(RAND() * 256))), 'IPv4', (FLOOR(RAND() * 10) + 1))
-- Add more fake values as needed

