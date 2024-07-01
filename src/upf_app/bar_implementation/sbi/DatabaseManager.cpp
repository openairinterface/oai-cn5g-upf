#include "DatabaseManager.hpp"

// Implementation of static member initialization
std::unique_ptr<DatabaseManager> DatabaseManager::instance = nullptr; //a single pointer to create a Database Manager instance that is initialized to a null pointer

// Private constructor (of the DatabaseManager class, private to prevent direct creation of instances outside the class)
DatabaseManager::DatabaseManager() {
    sqliteHelper = std::make_unique<Sqlite3Helper>();  // Initialize the sqliteHelper
}

// Destructor
DatabaseManager::~DatabaseManager() {}

// Static method to get the singleton instance of DatabaseManager
DatabaseManager& DatabaseManager::getInstance() {
    if (!instance) {
        instance.reset(new DatabaseManager());//Creates a new instance of DatabaseManager and stores it in instance
    }
    return *instance;
}

// Method to create and return an instance of Sqlite3Helper using DatabaseManager
std::unique_ptr<Sqlite3Helper> DatabaseManager::createSqlite3Helper() {//Method that creates and returns a new Sqlite3Helper object.
    return std::make_unique<Sqlite3Helper>();
}

// Method to insert data into the database
int DatabaseManager::insertData(const std::string& tableName, const std::vector<std::string>& values) {
    if (!sqliteHelper) {//Checks if sqliteHelper is not initialized and, if necessary, use it with a new Sqlite3Helper object.
        sqliteHelper = std::make_unique<Sqlite3Helper>();
    }

    // Create an SQL query for inserting data
    std::string query = "INSERT INTO " + tableName + " VALUES (";//Creates a string to store the SQL query.

    for (size_t i = 0; i < values.size(); ++i) {
        query += "\"" + values[i] + "\"";//Appends each value in quotes to the SQL query
        if (i != values.size() - 1) {//Adds a comma between values, except after the last value.
            query += ", ";
        }
    }
    query += ");";

    // Execute the query
    sqliteHelper->execute_query(query);
    return 0;
}
