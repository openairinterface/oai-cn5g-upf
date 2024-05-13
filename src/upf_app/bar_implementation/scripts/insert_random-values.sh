#!/bin/bash

# Variables for MySQL connection
DB_USER="root"
DB_PASSWORD="1234"
DB_HOST="172.17.0.2"
DB_PORT="3306"
DB_NAME="database"

# Function to execute SQL script
execute_sql_script() {
    local script_file="$1"
    mysql -u $DB_USER -p$DB_PASSWORD -h $DB_HOST -P $DB_PORT $DB_NAME < $script_file
}

# Execute SQL script to insert fake values
execute_sql_script "insertrandomvalues.sql"

