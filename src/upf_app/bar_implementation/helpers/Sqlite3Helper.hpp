#ifndef SQLITE3HELPER_HPP
#define SQLITE3HELPER_HPP

#include <sqlite3.h> // SQLite3 library
#include <vector> // Standard vector container
#include <string> // Standard string class

class Sqlite3Helper {
public:
    // Constructor and destructor
    Sqlite3Helper(); // Constructor for initializing Sqlite3Helper object
    ~Sqlite3Helper(); // Destructor to clean up resources

    // Connect to SQLite3 server and database
    int create_database(const std::string& db_name); // Method to create a new SQLite database
    int delete_database(const std::string& db_name); // Method to delete an existing SQLite database

    // Other database operations
    int execute_query(const std::string& query); // Method to execute a SQL query
    sqlite3* get_db() const; // Method to get the SQLite database object
    int show_database(); // Method to display the name of the currently connected database
    int create_table(const std::string& table_name, const std::vector<std::string>& fields); // Method to create a new table
    int delete_table(const std::string& table_name); // Method to delete an existing table
    int insert_into_table(const std::string& table_name, const std::vector<std::string>& fields, const std::vector<std::string>& values);// Method to insert data into a table
    int delete_from_table(const std::string& table_name, const std::string& condition); // Method to delete data from a table
    int show_tables(); // Method to display all tables in the database
    int show_table_fields(const std::string& table_name); // Method to display the fields of a table
    int join(const std::string& table1, const std::string& table2, const std::string& on_condition); // Method to perform a join operation between two tables
    int disconnect_from_database(); // Method to disconnect from the database

private:
    sqlite3* db; // Pointer to the SQLite database object
    std::string db_name; // Name of the connected database
};

#endif // SQLITE3HELPER_HPP
