#ifndef DATABASEMANAGER_HPP
#define DATABASEMANAGER_HPP

#include "../database_code/Sqlite3Helper.hpp" // Include Sqlite3Helper.hpp to access the SQLite functionality

class DatabaseManager {
public:
    // Singleton pattern: static method to get the instance of DatabaseManager
    static DatabaseManager& getInstance() {
        static DatabaseManager instance; // Singleton instance
        return instance;
    }

    // Access method to get the Sqlite3Helper instance
    Sqlite3Helper& getSqlite3Helper() {
        return sqlite3Helper; // Return the reference to the Sqlite3Helper instance
    }

private:
    DatabaseManager() {} // Private constructor for singleton

    DatabaseManager(DatabaseManager const&) = delete; // Delete copy constructor
    void operator=(DatabaseManager const&) = delete; // Delete copy assignment operator

    Sqlite3Helper sqlite3Helper; // Instance of Sqlite3Helper for database operations
};

#endif // DATABASEMANAGER_HPP
