#include "Sqlite3Helper.hpp" // Include the header file for Sqlite3Helper class
#include "../sbi/DatabaseManager.hpp" // Include the header file for DatabaseManager class
#include <iostream> // Input/output stream

// Constructor
Sqlite3Helper::Sqlite3Helper() : db(nullptr) {} // Initialize the pointer to nullptr

// Destructor
Sqlite3Helper::~Sqlite3Helper() { // Clean up resources upon object destruction
    disconnect_from_database(); // Disconnect from the database
}

// Function to create a new database
int Sqlite3Helper::create_database(const std::string& db_name) {
    this->db_name = db_name; // Assign the database name
    DatabaseManager& dbManager = DatabaseManager::getInstance(); // Get the singleton instance of DatabaseManager

    // Retrieve the pointer to the SQLite database
    sqlite3* db = dbManager.createSqlite3Helper()->get_db();

    // Open the database
    int rc = sqlite3_open(db_name.c_str(), &db);
    if (rc != SQLITE_OK) { // Check if database opening was successful
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db)); // Print error message
    } else {
        fprintf(stderr, "Opened database successfully\n"); // Print success message
        this->db = db; // Assign the opened database to class member
    }

    return rc; // Return the result code
}

// Function to delete a database
int Sqlite3Helper::delete_database(const std::string& db_name) {
    int rc = remove(db_name.c_str()); // Remove the database file
    
    if (rc) { // Check if deletion was successful
        std::cerr << "Error deleting database" << std::endl; // Print error message
    } else {
        std::cout << "Database deleted successfully" << std::endl; // Print success message
    }

    return rc; // Return the result code
}

// Function to execute a SQL query
int Sqlite3Helper::execute_query(const std::string& query) {
    char* errMsg; // Error message buffer

    // Execute the query
    int rc = sqlite3_exec(db, query.c_str(), nullptr, nullptr, &errMsg);
    
    if (rc) { // Check if execution was successful
        std::cerr << "Error executing query: " << errMsg << std::endl; // Print error message
        sqlite3_free(errMsg); // Free error message buffer
    } else {
        std::cout << "Query Executed Successfully!" << std::endl; // Print success message
    }   

    return rc; // Return the result code
}

// Function to create a new table
int Sqlite3Helper::create_table(const std::string& table_name, const std::vector<std::string>& fields) {
    std::string query = "CREATE TABLE IF NOT EXISTS " + table_name + " ("; // SQL query to create table
    
    // Append fields to the query
    for (uint64_t i = 0; i < fields.size()-1; ++i) {
        query = query + fields[i] + ", ";
    }
    
    query = query + fields[fields.size() -1] + ");"; // Complete the query

    return execute_query(query); // Execute the query and return the result code
}

// Method to get the SQLite database object
sqlite3* Sqlite3Helper::get_db() const {
    return db; // Return the SQLite database object
}

// Method to display the name of the currently connected database
int Sqlite3Helper::show_database() {
    size_t found = this->db_name.find_last_of("/\\"); // Extract filename from path
    std::string filename = this->db_name.substr(found + 1); // Get filename
    std::cout << "Database name: " << filename << std::endl; // Print database name
    return SQLITE_OK; // Return OK status
}

// Method to display all tables in the database
int Sqlite3Helper::show_tables() {
    std::string query = "SELECT name FROM sqlite_master WHERE type='table' AND name != 'sqlite_sequence';"; // SQL query to select tables
    sqlite3_stmt* stmt; // Prepared statement

    // Prepare the query
    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Error preparing query: " << sqlite3_errmsg(db) << std::endl; // Print error message
        return SQLITE_ERROR; // Return error status
    }

    std::cout << "Tables in database:" << std::endl; // Print header
    // Iterate over results
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* table_name = sqlite3_column_text(stmt, 0); // Extract table name
        std::cout << "- " << table_name << std::endl; // Print table name
    }

    sqlite3_finalize(stmt); // Finalize the statement
    return SQLITE_OK; // Return OK status
}

// Method to delete a table
int Sqlite3Helper::delete_table(const std::string& table_name) {
    std::string query = "DROP TABLE IF EXISTS " + table_name + ";"; // SQL query to drop table
    return execute_query(query); // Execute the query and return the result code
}

// Method to insert data into a table
int Sqlite3Helper::insert_into_table(const std::string& table_name, const std::vector<std::string>& fields, const std::vector<std::string>& values) {
    if (fields.size() != values.size()) {
        std::cerr << "Error: Number of fields doesn't match number of values." << std::endl;
        return SQLITE_ERROR;
    }
    std::string query = "INSERT INTO " + table_name + " (";
    for (size_t i = 0; i < fields.size(); ++i) {
        query += fields[i];
        if (i != fields.size() - 1) {
            query += ",";
        }
    }
    query += ") VALUES (";
    for (size_t i = 0; i < values.size(); ++i) {
        query += "'" + values[i] + "'";
        if (i != values.size() - 1) {
            query += ",";
        }
    }
    query += ");";
    return execute_query(query);
}


// Method to delete data from a table
int Sqlite3Helper::delete_from_table(const std::string& table_name, const std::string& condition) {
    std::string query = "DELETE FROM " + table_name + " WHERE " + condition + ";"; // SQL query to delete data
    return execute_query(query); // Execute the query and return the result code
}

// Method to display the fields of a table
int Sqlite3Helper::show_table_fields(const std::string& table_name) {
    std::string query = "PRAGMA table_info(" + table_name + ");"; // SQL query to get table info
    sqlite3_stmt* stmt; // Prepared statement

    // Prepare the query
    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Error preparing query: " << sqlite3_errmsg(db) << std::endl; // Print error message
        return SQLITE_ERROR; // Return error status
    }

    std::cout << "Fields of table " << table_name << ":" << std::endl; // Print header
    // Iterate over results
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* field_name = sqlite3_column_text(stmt, 1); // Extract field name
        std::cout << "- " << reinterpret_cast<const char*>(field_name) << std::endl; // Print field name
    }

    sqlite3_finalize(stmt); // Finalize the statement
    return SQLITE_OK; // Return OK status
}

// Method to perform a join operation between two tables
int Sqlite3Helper::join(const std::string& table1, const std::string& table2, const std::string& on_condition) {
    std::string query = "SELECT * FROM " + table1 + " INNER JOIN " + table2 + " ON " + on_condition + ";"; // SQL query for join operation
    return execute_query(query); // Execute the query and return the result code
}

// Method to disconnect from the database
int Sqlite3Helper::disconnect_from_database() {
    if (db) { // Check if database object exists
        sqlite3_close(db); // Close the database
        db = nullptr; // Reset the pointer
    }
    return SQLITE_OK; // Return OK status
}
