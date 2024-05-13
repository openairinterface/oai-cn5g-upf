#!/bin/bash

# Variables for MySQL connection
DB_USER="root"
DB_PASSWORD="1234"
DB_NAME="database"
DB_HOST="172.17.0.2"  # IP address of your MySQL server
DB_PORT="3306"  # Port of your MySQL server

# Function to execute a SELECT query
perform_select() {
    local query="$1"
    mysql -u $DB_USER -p$DB_PASSWORD -h $DB_HOST -P $DB_PORT $DB_NAME -e "$query"
}

# Function to execute an UPDATE query
perform_update() {
    local query="$1"
    mysql -u $DB_USER -p$DB_PASSWORD -h $DB_HOST -P $DB_PORT $DB_NAME -e "$query"
}

# Function to execute a DELETE query
perform_delete() {
    local query="$1"
    mysql -u $DB_USER -p$DB_PASSWORD -h $DB_HOST -P $DB_PORT $DB_NAME -e "$query"
}

# Main function
main() {
    echo "1. SELECT"
    echo "2. UPDATE"
    echo "3. DELETE"
    read -p "Choose an operation (1/2/3): " choice

    case $choice in
        1)
            read -p "Enter the SELECT query: " select_query
            perform_select "$select_query"
            ;;
        2)
            read -p "Enter the UPDATE query: " update_query
            perform_update "$update_query"
            ;;
        3)
            read -p "Enter the DELETE query: " delete_query
            perform_delete "$delete_query"
            ;;
        *)
            echo "Invalid choice. Please choose a valid option."
            ;;
    esac
}

# Call the main function
main

