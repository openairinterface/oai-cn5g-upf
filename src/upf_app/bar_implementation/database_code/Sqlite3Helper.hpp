#ifndef SQLITE3HELPER_HPP
#define SQLITE3HELPER_HPP

#include <sqlite3.h>
#include <vector>
#include <string>

class Sqlite3Helper {
public:
    // Constructor and destructor
    Sqlite3Helper();
    ~Sqlite3Helper();

    // Connect to SQLite3 server and database
    int create_database(const std::string& db_name);
    int delete_database(const std::string& db_name);

    // Other database operations
    int execute_query(const std::string& query);
    sqlite3* get_db() const;
    int show_database();
    int create_table(const std::string& table_name, const std::vector<std::string>& fields);
    int delete_table(const std::string& table_name);
    int insert_into_table(const std::string& table_name, const std::vector<std::string>& values);
    int delete_from_table(const std::string& table_name, const std::string& condition);
    int show_tables();
    int show_table_fields(const std::string& table_name);
    int join(const std::string& table1, const std::string& table2, const std::string& on_condition);
    int disconnect_from_database();

private:
    sqlite3* db;
    std::string db_name;
};


#endif // SQLITE3HELPER_HPP
