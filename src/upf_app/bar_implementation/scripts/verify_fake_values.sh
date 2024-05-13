#!/bin/bash

# Variables for MySQL connection
DB_USER="root"
DB_PASSWORD="1234"
DB_HOST="172.17.0.2"
DB_PORT="3306"
DB_NAME="database"

# Function to execute a SELECT query
perform_select() {
    local query="$1"
    mysql -u $DB_USER -p$DB_PASSWORD -h $DB_HOST -P $DB_PORT $DB_NAME -e "$query"
}

# Check fake values in the ipv4_headers table
echo "Content of the ipv4_headers table:"
perform_select "SELECT * FROM ipv4_headers;"

# Check fake values in the tcp_headers table
echo "Content of the tcp_headers table:"
perform_select "SELECT * FROM tcp_headers;"

# Check fake values in the udp_headers table
echo "Content of the udp_headers table:"
perform_select "SELECT * FROM udp_headers;"

# Check fake values in the icmp_headers table
echo "Content of the icmp_headers table:"
perform_select "SELECT * FROM icmp_headers;"

# Check fake values in the ethernet_headers table
echo "Content of the ethernet_headers table:"
perform_select "SELECT * FROM ethernet_headers;"

