#include "sbi/DatabaseManager.hpp"  // Include the database manager
#include "sbi/include/headers.hpp" // Include header files defining fields of tables
#include <iostream>
#include "sbi/PacketCapture.hpp"
#include "sbi/SplitPacket.hpp"
#include "sbi/Trigger.hpp"


int main() {

    // Get the unique instance of the database manager
    DatabaseManager& dbManager = DatabaseManager::getInstance();
    
    // Get a reference to the instance of Sqlite3Helper
    Sqlite3Helper& sqlite3Helper = dbManager.getSqlite3Helper();

    std::string db_name = "Buffer";

    int rc;
    
    // Create the database
    rc = sqlite3Helper.create_database(db_name);    
    
    // Create the IPv4 Header table
    if (!rc)
        rc = sqlite3Helper.create_table("ipv4_header", ipv4Fields);
    
    // Create the TCP Header table
    if (!rc)
        rc = sqlite3Helper.create_table("tcp_header", tcpFields);
    
    // Create the UDP Header table
    if (!rc) 
        rc = sqlite3Helper.create_table("udp_header", udpFields);

    // Create the ICMP Header table
    if (!rc)
        rc = sqlite3Helper.create_table("icmp_header", icmpFields);

    // Create the Ethernet Header table
    if (!rc)    
        rc = sqlite3Helper.create_table("eth_header", ethFields);
        
    // Create the GTPU table
    if(!rc) 
        rc = sqlite3Helper.create_table("gtpu", gtpuFields);

    // Create the Data table
    if (!rc)
        rc = sqlite3Helper.create_table("data_header", dataFields);

    // Capture  packets
    PacketCapture::capturePackets();


    return 0; // Return 0 to indicate successful execution
}
