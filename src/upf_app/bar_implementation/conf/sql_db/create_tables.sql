-- create_tables.sql

-- Création de la base de données
CREATE DATABASE IF NOT EXISTS `database`;

-- Utilisation de la base de données
USE `database`;

-- Création de la table ipv4_headers
CREATE TABLE IF NOT EXISTS ipv4_headers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    version TINYINT UNSIGNED,
    header_length TINYINT UNSIGNED,
    type_of_service TINYINT UNSIGNED,
    total_length SMALLINT UNSIGNED,
    identification SMALLINT UNSIGNED,
    flags TINYINT UNSIGNED,
    fragment_offset SMALLINT UNSIGNED,
    time_to_live TINYINT UNSIGNED,
    protocol TINYINT UNSIGNED,
    header_checksum SMALLINT UNSIGNED,
    source_ip VARCHAR(15),
    destination_ip VARCHAR(15)
);

-- Création de la table tcp_headers
CREATE TABLE IF NOT EXISTS tcp_headers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ipv4_header_id INT,
    source_port SMALLINT UNSIGNED,
    destination_port SMALLINT UNSIGNED,
    sequence_number INT UNSIGNED,
    acknowledgment_number INT UNSIGNED,
    data_offset TINYINT UNSIGNED,
    reserved TINYINT UNSIGNED,
    flags VARCHAR(9),
    window_size SMALLINT UNSIGNED,
    checksum SMALLINT UNSIGNED,
    urgent_pointer SMALLINT UNSIGNED,
    FOREIGN KEY (ipv4_header_id) REFERENCES ipv4_headers(id)
);

-- Création de la table udp_headers
CREATE TABLE IF NOT EXISTS udp_headers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ipv4_header_id INT,
    source_port SMALLINT UNSIGNED,
    destination_port SMALLINT UNSIGNED,
    length SMALLINT UNSIGNED,
    checksum SMALLINT UNSIGNED,
    FOREIGN KEY (ipv4_header_id) REFERENCES ipv4_headers(id)
);

-- Création de la table icmp_headers
CREATE TABLE IF NOT EXISTS icmp_headers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ipv4_header_id INT,
    type TINYINT UNSIGNED,
    code TINYINT UNSIGNED,
    checksum SMALLINT UNSIGNED,
    rest_of_header VARCHAR(48),
    FOREIGN KEY (ipv4_header_id) REFERENCES ipv4_headers(id)
);

-- Création de la table ethernet_headers
CREATE TABLE IF NOT EXISTS ethernet_headers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    source_mac VARCHAR(17),
    destination_mac VARCHAR(17),
    protocol VARCHAR(20),
    ipv4_header_id INT,
    FOREIGN KEY (ipv4_header_id) REFERENCES ipv4_headers(id)
);

-- Création de la table data
CREATE TABLE IF NOT EXISTS data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ipv4_header_id INT,
    tcp_header_id INT,
    udp_header_id INT,
    icmp_header_id INT,
    ethernet_header_id INT,
    payload BLOB,
    FOREIGN KEY (ipv4_header_id) REFERENCES ipv4_headers(id),
    FOREIGN KEY (tcp_header_id) REFERENCES tcp_headers(id),
    FOREIGN KEY (udp_header_id) REFERENCES udp_headers(id),
    FOREIGN KEY (icmp_header_id) REFERENCES icmp_headers(id),
    FOREIGN KEY (ethernet_header_id) REFERENCES ethernet_headers(id)
);

