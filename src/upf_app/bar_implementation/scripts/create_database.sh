#!/bin/bash

# Variables for MySQL connection
DB_USER="root"
DB_PASSWORD="1234"
DB_HOST="172.17.0.2"  # Replace localhost with the IP address of your MySQL server
DB_PORT="3306"  # Replace 3306 with the port number of your MySQL server
DB_NAME="database"

# Create the database
if mysql -u $DB_USER -p$DB_PASSWORD -h $DB_HOST -P $DB_PORT -e "CREATE DATABASE IF NOT EXISTS \`$DB_NAME\`;"; then
    echo "Database $DB_NAME created successfully."
else
    echo "Error creating database $DB_NAME."
    exit 1
fi

# Use the database
if mysql -u $DB_USER -p$DB_PASSWORD -h $DB_HOST -P $DB_PORT -e "USE $DB_NAME;"; then
    echo "Using database $DB_NAME."
else
    echo "Error using database $DB_NAME."
    exit 1
fi

# Create the table for IPv4 headers
if mysql -u $DB_USER -p$DB_PASSWORD -h $DB_HOST -P $DB_PORT $DB_NAME <<EOF
CREATE TABLE IF NOT EXISTS ipv4_headers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    version TINYINT UNSIGNED,
    header_length TINYINT UNSIGNED,
    type_of_service TINYINT UNSIGNED,
    total_length SMALLINT UNSIGNED,
    identification SMALLINT UNSIGNED,
    flags TINYINT UNSIGNED,
    fragment_offset SMALLINT UNSIGNED,
    time_to_live TINYINT UNSIGNED,
    protocol TINYINT UNSIGNED,
    header_checksum SMALLINT UNSIGNED,
    source_ip VARCHAR(15),
    destination_ip VARCHAR(15)
);
EOF
then
    echo "Table ipv4_headers created successfully."
else
    echo "Error creating table ipv4_headers."
    exit 1
fi

# Create the table for TCP headers
if mysql -u $DB_USER -p$DB_PASSWORD -h $DB_HOST -P $DB_PORT $DB_NAME <<EOF
CREATE TABLE IF NOT EXISTS tcp_headers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ipv4_header_id INT,
    source_port SMALLINT UNSIGNED,
    destination_port SMALLINT UNSIGNED,
    sequence_number INT UNSIGNED,
    acknowledgment_number INT UNSIGNED,
    data_offset TINYINT UNSIGNED,
    reserved TINYINT UNSIGNED,
    flags VARCHAR(9),
    window_size SMALLINT UNSIGNED,
    checksum SMALLINT UNSIGNED,
    urgent_pointer SMALLINT UNSIGNED,
    FOREIGN KEY (ipv4_header_id) REFERENCES ipv4_headers(id)
);
EOF
then
    echo "Table tcp_headers created successfully."
else
    echo "Error creating table tcp_headers."
    exit 1
fi

# Create the table for UDP headers
if mysql -u $DB_USER -p$DB_PASSWORD -h $DB_HOST -P $DB_PORT $DB_NAME <<EOF
CREATE TABLE IF NOT EXISTS udp_headers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ipv4_header_id INT,
    source_port SMALLINT UNSIGNED,
    destination_port SMALLINT UNSIGNED,
    length SMALLINT UNSIGNED,
    checksum SMALLINT UNSIGNED,
    FOREIGN KEY (ipv4_header_id) REFERENCES ipv4_headers(id)
);
EOF
then
    echo "Table udp_headers created successfully."
else
    echo "Error creating table udp_headers."
    exit 1
fi

# Create the table for ICMP headers
if mysql -u $DB_USER -p$DB_PASSWORD -h $DB_HOST -P $DB_PORT $DB_NAME <<EOF
CREATE TABLE IF NOT EXISTS icmp_headers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ipv4_header_id INT,
    type TINYINT UNSIGNED,
    code TINYINT UNSIGNED,
    checksum SMALLINT UNSIGNED,
    rest_of_header VARCHAR(48),
    FOREIGN KEY (ipv4_header_id) REFERENCES ipv4_headers(id)
);
EOF
then
    echo "Table icmp_headers created successfully."
else
    echo "Error creating table icmp_headers."
    exit 1
fi

# Create the table for Ethernet headers
if mysql -u $DB_USER -p$DB_PASSWORD -h $DB_HOST -P $DB_PORT $DB_NAME <<EOF
CREATE TABLE IF NOT EXISTS ethernet_headers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    source_mac VARCHAR(17),
    destination_mac VARCHAR(17),
    protocol VARCHAR(20),
    ipv4_header_id INT,
    FOREIGN KEY (ipv4_header_id) REFERENCES ipv4_headers(id)
);
EOF
then
    echo "Table ethernet_headers created successfully."
else
    echo "Error creating table ethernet_headers."
    exit 1
fi

# Create the table for data
if mysql -u $DB_USER -p$DB_PASSWORD -h $DB_HOST -P $DB_PORT $DB_NAME <<EOF
CREATE TABLE IF NOT EXISTS data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ipv4_header_id INT,
    tcp_header_id INT,
    udp_header_id INT,
    icmp_header_id INT,
    ethernet_header_id INT,
    payload BLOB,
    FOREIGN KEY (ipv4_header_id) REFERENCES ipv4_headers(id),
    FOREIGN KEY (tcp_header_id) REFERENCES tcp_headers(id),
    FOREIGN KEY (udp_header_id) REFERENCES udp_headers(id),
    FOREIGN KEY (icmp_header_id) REFERENCES icmp_headers(id),
    FOREIGN KEY (ethernet_header_id) REFERENCES ethernet_headers(id)
);
EOF
then
    echo "Table data created successfully."
else
    echo "Error creating table data."
    exit 1
fi

# Display the list of databases
echo "List of databases:"
if mysql -u $DB_USER -p$DB_PASSWORD -h $DB_HOST -P $DB_PORT -e "SHOW DATABASES;"; then
    echo "List of databases displayed successfully."
else
    echo "Error displaying the list of databases."
fi

# Display the list of tables in the specified database
echo "List of tables in database $DB_NAME :"
if mysql -u $DB_USER -p$DB_PASSWORD -h $DB_HOST -P $DB_PORT $DB_NAME -e "SHOW TABLES;"; then
    echo "List of tables displayed successfully."
else
    echo "Error displaying the list of tables."
fi

echo "Database and tables created successfully."

