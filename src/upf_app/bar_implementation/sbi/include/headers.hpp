#include <iostream>


std::vector<std::string> ipv4Fields = {
    "id INTEGER PRIMARY KEY AUTOINCREMENT",
    "version TINYINT UNSIGNED NOT NULL",
    "header_length TINYINT UNSIGNED NOT NULL",
    "type_of_service TINYINT UNSIGNED NOT NULL",
    "total_length SMALLINT UNSIGNED NOT NULL",
    "identification SMALLINT UNSIGNED NOT NULL",
    "flags TINYINT UNSIGNED NOT NULL",
    "fragment_offset SMALLINT UNSIGNED NOT NULL",
    "time_to_live TINYINT UNSIGNED NOT NULL",
    "protocol TINYINT UNSIGNED NOT NULL",
    "header_checksum SMALLINT UNSIGNED NOT NULL",
    "source_ip VARCHAR(15) NOT NULL",
    "destination_ip VARCHAR(15) NOT NULL"
};

std::vector<std::string> tcpFields = {
    "id INTEGER PRIMARY KEY AUTOINCREMENT",
    "source_port SMALLINT UNSIGNED NOT NULL",
    "destination_port SMALLINT UNSIGNED NOT NULL",
    "sequence_number INT UNSIGNED NOT NULL",
    "acknowledgment_number INT UNSIGNED NOT NULL",
    "header_length TINYINT UNSIGNED NOT NULL",
    "reserved TINYINT UNSIGNED NOT NULL",
    "flags TINYINT UNSIGNED NOT NULL",
    "window_size SMALLINT UNSIGNED NOT NULL",
    "checksum SMALLINT UNSIGNED NOT NULL",
    "urgent_pointer SMALLINT UNSIGNED NOT NULL",
    "ipv4_id INTEGER, FOREIGN KEY (ipv4_id) REFERENCES ipv4_header(id)"
    // Add other fields as needed
};

std::vector<std::string> udpFields = {
    "id INTEGER PRIMARY KEY AUTOINCREMENT",
    "source_port SMALLINT UNSIGNED NOT NULL",
    "destination_port SMALLINT UNSIGNED NOT NULL",
    "length SMALLINT UNSIGNED NOT NULL",
    "checksum SMALLINT UNSIGNED NOT NULL",
    "ipv4_id INTEGER, FOREIGN KEY (ipv4_id) REFERENCES ipv4_header(id)"
    // Add other fields as needed
};

std::vector<std::string> icmpFields = {
"id INTEGER PRIMARY KEY AUTOINCREMENT",
"type SMALLINT UNSIGNED NOT NULL",
"code SMALLINT UNSIGNED NOT NULL",
"checksum SMALLINT UNSIGNED NOT NULL",
"ipv4_id INTEGER, FOREIGN KEY (ipv4_id) REFERENCES ipv4_header(id)"
// Add other fields as needed
};

std::vector<std::string> gtpuFields = {
    "id INTEGER PRIMARY KEY AUTOINCREMENT",
    "source_ip VARCHAR(39)",
    "destination_ip VARCHAR(39)",
    "source_port INT",
    "destination_port INT",
    "length INT",
    "seid INT", // Id of session
    "teid INT", // Id of tunnel
    "message_type SMALLINT NOT NULL",
    "sequence_number SMALLINT NOT NULL",
    "ipv4_id INTEGER, FOREIGN KEY (ipv4_id) REFERENCES ipv4_header(id)"
    // Add other fields as needed
};

std::vector<std::string> ethFields = {
    "id INTEGER PRIMARY KEY AUTOINCREMENT",
    "source_mac VARCHAR(17) NOT NULL",
    "destination_mac VARCHAR(17) NOT NULL",
    "ethertype SMALLINT UNSIGNED NOT NULL",
    "ipv4_id INTEGER, FOREIGN KEY (ipv4_id) REFERENCES ipv4_header(id)"
    // Add other fields as needed
};

    std::vector<std::string> dataFields = {
    "id INTEGER PRIMARY KEY AUTOINCREMENT",
    "timestamp DATETIME",
    "data_payload BLOB",
    "ipv4_id INTEGER, FOREIGN KEY (ipv4_id) REFERENCES ipv4_header(id)"
    // Add other fields as needed
};
