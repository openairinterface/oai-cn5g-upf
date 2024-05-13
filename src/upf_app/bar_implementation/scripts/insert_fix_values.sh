#!/bin/bash

# Variables for MySQL connection
DB_USER="root"
DB_PASSWORD="1234"
DB_HOST="172.17.0.2"
DB_PORT="3306"
DB_NAME="database"

# Function to execute an INSERT query
perform_insert() {
    local query="$1"
    mysql -u $DB_USER -p$DB_PASSWORD -h $DB_HOST -P $DB_PORT $DB_NAME -e "$query"
}

# Insert fake values into the ipv4_headers table
perform_insert "INSERT INTO ipv4_headers (version, header_length, type_of_service, total_length, identification, flags, fragment_offset, time_to_live, protocol, header_checksum, source_ip, destination_ip) VALUES (4, 20, 0, 1500, 12345, 2, 0, 64, 6, 1234, '192.168.1.1', '192.168.1.2');"

# Insert fake values into the tcp_headers table
perform_insert "INSERT INTO tcp_headers (ipv4_header_id, source_port, destination_port, sequence_number, acknowledgment_number, data_offset, reserved, flags, window_size, checksum, urgent_pointer) VALUES (1, 1234, 80, 54321, 0, 8, 0, 'SYN', 5840, 0, 0);"

# Insert fake values into the udp_headers table
perform_insert "INSERT INTO udp_headers (ipv4_header_id, source_port, destination_port, length, checksum) VALUES (1, 1234, 53, 28, 0);"

# Insert fake values into the icmp_headers table
perform_insert "INSERT INTO icmp_headers (ipv4_header_id, type, code, checksum, rest_of_header) VALUES (1, 8, 0, 0, 'Some additional data');"

# Insert fake values into the ethernet_headers table
perform_insert "INSERT INTO ethernet_headers (source_mac, destination_mac, protocol, ipv4_header_id) VALUES ('00:0a:95:9d:68:16', '00:0a:95:9d:68:17', 'IPv4', 1);"

echo "Fake values inserted successfully."

