#include "Sqlite3Helper.hpp"
#include "../sbi/DatabaseManager.hpp" 
#include <iostream>

// Constructor
Sqlite3Helper::Sqlite3Helper() : db(nullptr) {}

// Destructor
Sqlite3Helper::~Sqlite3Helper() {
    disconnect_from_database();
}


// Function to create a new database
int Sqlite3Helper::create_database(const std::string& db_name) {
    this->db_name = db_name; // Assign the database name to db_name
    DatabaseManager& dbManager = DatabaseManager::getInstance(); // Get the DatabaseManager instance

    // Retrieve the pointer to the SQLite database
    sqlite3* db = dbManager.getSqlite3Helper().get_db();

    // Open the database
    int rc = sqlite3_open(db_name.c_str(), &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
    } else {
        fprintf(stderr, "Opened database successfully\n");
        this->db = db; // Assign the opened database to class member db
    }

    return rc;
}


// Function to delete a database
int Sqlite3Helper::delete_database(const std::string& db_name) {
    int rc = remove(db_name.c_str());
    
    if (rc) {
        std::cerr << "Error deleting database" << std::endl;
    } else {
        std::cout << "Database deleted successfully" << std::endl;
    }

    return rc;
}


int Sqlite3Helper::execute_query(const std::string& query) {
    char* errMsg;

    int rc = sqlite3_exec(db, query.c_str(), nullptr, nullptr, &errMsg);
    
    if (rc) {
        std::cerr << "Error executing query: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    } else {
        std::cout << "Query Executed Successfully!" << std::endl;
    }   

    return rc;
}


int Sqlite3Helper::create_table(const std::string& table_name, const std::vector<std::string>& fields) {
    std::string query = "CREATE TABLE IF NOT EXISTS " + table_name + " (";
    
    for (uint64_t i = 0; i < fields.size()-1; ++i) {
        query = query + fields[i] + ", ";
    }
    
    query = query + fields[fields.size() -1] + ");";

    return execute_query(query);
}



sqlite3* Sqlite3Helper::get_db() const {
    return db;
}


int Sqlite3Helper::show_database() {
    size_t found = this->db_name.find_last_of("/\\"); // Use this->db_name to access the class member
    std::string filename = this->db_name.substr(found + 1);
    std::cout << "Database name: " << filename << std::endl;
    return SQLITE_OK;
}

int Sqlite3Helper::show_tables() {
    std::string query = "SELECT name FROM sqlite_master WHERE type='table' AND name != 'sqlite_sequence';";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Error preparing query: " << sqlite3_errmsg(db) << std::endl;
        return SQLITE_ERROR;
    }

    std::cout << "Tables in database:" << std::endl;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* table_name = sqlite3_column_text(stmt, 0);
        std::cout << "- " << table_name << std::endl;
    }

    sqlite3_finalize(stmt);
    return SQLITE_OK;
}

int Sqlite3Helper::delete_table(const std::string& table_name) {
    std::string query = "DROP TABLE IF EXISTS " + table_name + ";";
    return execute_query(query);
}

int Sqlite3Helper::insert_into_table(const std::string& table_name, const std::vector<std::string>& values) {
    std::string query = "INSERT INTO " + table_name + " VALUES (";
    for (size_t i = 0; i < values.size(); ++i) {
        query += "'" + values[i] + "'";
        if (i != values.size() - 1) {
            query += ", ";
        }
    }
    query += ");";

    return execute_query(query);
}

int Sqlite3Helper::delete_from_table(const std::string& table_name, const std::string& condition) {
    std::string query = "DELETE FROM " + table_name + " WHERE " + condition + ";";
    return execute_query(query);
}

int Sqlite3Helper::show_table_fields(const std::string& table_name) {
    std::string query = "PRAGMA table_info(" + table_name + ");";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Error preparing query: " << sqlite3_errmsg(db) << std::endl;
        return SQLITE_ERROR;
    }

    std::cout << "Fields of table " << table_name << ":" << std::endl;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* field_name = sqlite3_column_text(stmt, 1);
        std::cout << "- " << reinterpret_cast<const char*>(field_name) << std::endl;
    }

    sqlite3_finalize(stmt);
    return SQLITE_OK;
}

int Sqlite3Helper::join(const std::string& table1, const std::string& table2, const std::string& on_condition) {
    std::string query = "SELECT * FROM " + table1 + " INNER JOIN " + table2 + " ON " + on_condition + ";";
    return execute_query(query);
}

int Sqlite3Helper::disconnect_from_database() {
    if (db) {
        sqlite3_close(db);
        db = nullptr;
    }
    return SQLITE_OK;
}
