#include "../../database_code/Sqlite3Helper.hpp"
#include "../../sbi/include/headers.hpp"
#include <iostream>

int main() {
    // Connect to the SQLite3 server
    Sqlite3Helper Sqlite3Helper;

    std::string db_name = "Buffer";

    int rc;

    // Create the database
    rc = Sqlite3Helper.create_database(db_name);    
    
    // Create the IPv4 Header table
    if (!rc)
        rc = Sqlite3Helper.create_table("ipv4_header", ipv4Fields);
    
    // Create the TCP Header table
    if (!rc)
        rc = Sqlite3Helper.create_table("tcp_header", tcpFields);
    
    // Create the UDP Header table
    
    if (!rc) 
        rc = Sqlite3Helper.create_table("udp_header", udpFields);

    // Create the ICMP Header table
    if (!rc)
        rc = Sqlite3Helper.create_table("icmp_header", icmpFields);

    // Create the Ethernet Header table
    if (!rc)    
        rc = Sqlite3Helper.create_table("eth_header", ethFields);
        
    // Create the GTPU table
     if(!rc) 
        rc = Sqlite3Helper.create_table("gtpu", gtpuFields);

     // Create the Data table
    if (!rc)
        rc = Sqlite3Helper.create_table("data_header", dataFields);



    // Display the tables
    std::cout << "+-------------------------+" << std::endl;
    std::cout << "|       Database Tables    |" << std::endl;
    std::cout << "+-------------------------+" << std::endl;
    if (Sqlite3Helper.show_tables() != SQLITE_OK) {
        std::cerr << "Error displaying the tables." << std::endl;
        return 1;
    }

    // Display the fields of the IPv4 Header table
    std::cout << "+-------------------------+" << std::endl;
    std::cout << "| IPv4 Fields of tcp_header|" << std::endl;
    std::cout << "+-------------------------+" << std::endl;
    if (Sqlite3Helper.show_table_fields("ipv4_header") != SQLITE_OK) {
        std::cerr << "Error displaying the fields of the TCP Header table." << std::endl;
        return 1;
    }


    // Display the fields of the TCP Header table
    std::cout << "+-------------------------+" << std::endl;
    std::cout << "| TCP Fields of tcp_header|" << std::endl;
    std::cout << "+-------------------------+" << std::endl;
    if (Sqlite3Helper.show_table_fields("tcp_header") != SQLITE_OK) {
        std::cerr << "Error displaying the fields of the TCP Header table." << std::endl;
        return 1;
    }

        // Display the fields of the UDP Header table
    std::cout << "+-------------------------+" << std::endl;
    std::cout << "| UDP Fields of udp_header|" << std::endl;
    std::cout << "+-------------------------+" << std::endl;
    if (Sqlite3Helper.show_table_fields("udp_header") != SQLITE_OK) {
        std::cerr << "Error displaying the fields of the UDP Header table." << std::endl;
        return 1;
    }

        // Display the fields of the ICMP Header table
    std::cout << "+-------------------------+" << std::endl;
    std::cout << "| ICMP Fields of icmp_header|" << std::endl;
    std::cout << "+-------------------------+" << std::endl;
    if (Sqlite3Helper.show_table_fields("icmp_header") != SQLITE_OK) {
        std::cerr << "Error displaying the fields of the ICMP Header table." << std::endl;
        return 1;
    }
        // Display the fields of the UDP Header table
    std::cout << "+-------------------------+" << std::endl;
    std::cout << "| ETH Fields of eth_header|" << std::endl;
    std::cout << "+-------------------------+" << std::endl;
    if (Sqlite3Helper.show_table_fields("eth_header") != SQLITE_OK) {
        std::cerr << "Error displaying the fields of the ETH Header table." << std::endl;
        return 1;
    }

    

        // Display the fields of the DATA Header table
    std::cout << "+-------------------------+" << std::endl;
    std::cout << "| Data Fields of data_header|" << std::endl;
    std::cout << "+-------------------------+" << std::endl;
    if (Sqlite3Helper.show_table_fields("data_header") != SQLITE_OK) {
        std::cerr << "Error displaying the fields of the data Header table." << std::endl;
        return 1;
    }


    // Disconnect from the database
    Sqlite3Helper.disconnect_from_database();
    std::cout << "Disconnected from the database successfully." << std::endl;

    return 0;
}
