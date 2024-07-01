#ifndef DATABASEMANAGER_HPP
#define DATABASEMANAGER_HPP

#include "../helpers/Sqlite3Helper.hpp" // Include the header file for DatabaseManager
#include <memory> // Include the memory header for std::unique_ptr
#include <vector>
#include <string>

class DatabaseManager {
public:
    // Destructor
    ~DatabaseManager();

    // Static method to get the singleton instance of DatabaseManager
    static DatabaseManager& getInstance();

    // Method to create and return an instance of Sqlite3Helper using DatabaseManager
    std::unique_ptr<Sqlite3Helper> createSqlite3Helper();

    // Method to insert data into the database
    int insertData(const std::string& tableName, const std::vector<std::string>& values);


private:
    // Private constructor to enforce singleton pattern
    DatabaseManager();

    // Static pointer to the singleton instance
    static std::unique_ptr<DatabaseManager> instance;

    // Pointer to Sqlite3Helper instance
    std::unique_ptr<Sqlite3Helper> sqliteHelper;
};


#endif // DATABASEMANAGER_HPP
