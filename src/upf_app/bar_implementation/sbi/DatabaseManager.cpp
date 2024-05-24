#include "DatabaseManager.hpp"

// Implementation of static member initialization
std::unique_ptr<DatabaseManager> DatabaseManager::instance = nullptr;

// Private constructor
DatabaseManager::DatabaseManager() {
    sqliteHelper = std::make_unique<Sqlite3Helper>();  // Initialize the sqliteHelper
}

// Destructor
DatabaseManager::~DatabaseManager() {}

// Static method to get the singleton instance of DatabaseManager
DatabaseManager& DatabaseManager::getInstance() {
    if (!instance) {
        instance.reset(new DatabaseManager());
    }
    return *instance;
}

// Method to create and return an instance of Sqlite3Helper using DatabaseManager
std::unique_ptr<Sqlite3Helper> DatabaseManager::createSqlite3Helper() {
    return std::make_unique<Sqlite3Helper>();
}

// Method to insert data into the database
int DatabaseManager::insertData(const std::string& tableName, const std::vector<std::string>& values) {
    if (!sqliteHelper) {
        sqliteHelper = std::make_unique<Sqlite3Helper>();
    }

    // Create an SQL query for inserting data
    std::string query = "INSERT INTO " + tableName + " VALUES (";

    for (size_t i = 0; i < values.size(); ++i) {
        query += "\"" + values[i] + "\"";
        if (i != values.size() - 1) {
            query += ", ";
        }
    }
    query += ");";

    // Execute the query
    sqliteHelper->execute_query(query);
    return 0;
}
