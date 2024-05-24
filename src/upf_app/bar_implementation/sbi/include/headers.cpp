#include <iostream>
#include "headers.hpp"


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
    "tcp_options BLOB",
    "ipv4_id INTEGER, FOREIGN KEY (ipv4_id) REFERENCES ipv4_header(id)"
    // Add other fields as needed
};

std::vector<std::string> udpFields = {
    "id INTEGER PRIMARY KEY AUTOINCREMENT",
    "source_port SMALLINT UNSIGNED NOT NULL",
    "destination_port SMALLINT UNSIGNED NOT NULL",
    "length SMALLINT UNSIGNED NOT NULL",
    "checksum SMALLINT UNSIGNED NOT NULL",
    "udp_payload BLOB", 
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

std::vector<std::string> dnsFields = {
    "id INTEGER PRIMARY KEY AUTOINCREMENT",
    "transaction_id SMALLINT UNSIGNED NOT NULL",
    "flags SMALLINT UNSIGNED NOT NULL",
    "questions SMALLINT UNSIGNED NOT NULL",
    "answer_rrs SMALLINT UNSIGNED NOT NULL",
    "authority_rrs SMALLINT UNSIGNED NOT NULL",
    "additional_rrs SMALLINT UNSIGNED NOT NULL",
    "queries BLOB", // Stocker les requêtes DNS sous forme binaire
    "answers BLOB", // Stocker les réponses DNS sous forme binaire
    "authorities BLOB", // Stocker les autorités DNS sous forme binaire
    "additionals BLOB", // Stocker les enregistrements additionnels DNS sous forme binaire
    "udp_id INTEGER, FOREIGN KEY (udp_id) REFERENCES udp_header(id)"
};

std::vector<std::string> igmpFields = {
    "id INTEGER PRIMARY KEY AUTOINCREMENT",
    "igmp_version TINYINT UNSIGNED NOT NULL",
    "type TINYINT UNSIGNED NOT NULL",
    "max_resp_time TINYINT UNSIGNED NOT NULL",
    "checksum SMALLINT UNSIGNED NOT NULL",
    "multicast_address VARCHAR(15) NOT NULL",
    "s_flag BOOLEAN NOT NULL",
    "qrv TINYINT UNSIGNED NOT NULL",
    "qqic TINYINT UNSIGNED NOT NULL",
    "num_src TINYINT UNSIGNED NOT NULL"
};
  std::vector<std::string> icmpv6Fields = {
    "id INTEGER PRIMARY KEY AUTOINCREMENT",
    "icmpv6_type TINYINT UNSIGNED NOT NULL",
    "code TINYINT UNSIGNED NOT NULL",
    "checksum SMALLINT UNSIGNED NOT NULL",
    "max_resp_delay SMALLINT UNSIGNED NOT NULL",
    "reserved SMALLINT UNSIGNED NOT NULL",
    "multicast_address VARCHAR(39) NOT NULL" // 39 characters are sufficient to store IPv6 addresses
};

std::vector<std::string> nbnsFields = {
    "transaction_id SMALLINT UNSIGNED NOT NULL",
    "flags SMALLINT UNSIGNED NOT NULL",
    "opcode SMALLINT UNSIGNED NOT NULL",
    "recursion_desired SMALLINT UNSIGNED NOT NULL",
    "broadcast SMALLINT UNSIGNED NOT NULL",
    "questions SMALLINT UNSIGNED NOT NULL",
    "answer_rrs SMALLINT UNSIGNED NOT NULL",
    "authority_rrs SMALLINT UNSIGNED NOT NULL",
    "additional_rrs SMALLINT UNSIGNED NOT NULL"
};

std::vector<std::string> mdnsFields = {
    "transaction_id SMALLINT UNSIGNED NOT NULL",
    "flags SMALLINT UNSIGNED NOT NULL",
    "questions SMALLINT UNSIGNED NOT NULL",
    "answer_rrs SMALLINT UNSIGNED NOT NULL",
    "authority_rrs SMALLINT UNSIGNED NOT NULL",
    "additional_rrs SMALLINT UNSIGNED NOT NULL"
};
std::vector<std::string> smbFields = {
    "command SMALLINT UNSIGNED NOT NULL",
    "election_version SMALLINT UNSIGNED NOT NULL",
    "election_criteria INT UNSIGNED NOT NULL",
    "uptime VARCHAR(20) NOT NULL",
    "server_name VARCHAR(255) NOT NULL"
};
std::vector<std::string> quicFields = {
    "header_form BIT(1) NOT NULL",
    "fixed_bit BIT(1) NOT NULL",
    "packet_type BIT(2) NOT NULL",
    "version INT UNSIGNED NOT NULL",
    "destination_connection_id_length TINYINT UNSIGNED NOT NULL",
    "destination_connection_id VARCHAR(16) NOT NULL",
    "source_connection_id_length TINYINT UNSIGNED NOT NULL",
    "source_connection_id VARCHAR(6) NOT NULL",
    "length SMALLINT UNSIGNED NOT NULL",
    "remaining_payload BLOB", // Pour stocker les données restantes du paquet QUIC
    "ipv4_id INTEGER, FOREIGN KEY (ipv4_id) REFERENCES ipv4_header(id)"
    // Ajoutez d'autres champs au besoin
};


