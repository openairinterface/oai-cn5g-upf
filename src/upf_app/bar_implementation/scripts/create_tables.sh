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

# Execute SQL script to create database and tables
execute_sql_script "create_tables.sql"

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

