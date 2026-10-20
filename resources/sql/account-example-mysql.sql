-- Host-owned demonstration schema. Binary equality preserves the documented local-part distinctions.
CREATE TABLE account_example (
    scope VARBINARY(256) NOT NULL,
    subject VARBINARY(256) NOT NULL,
    credential_version VARBINARY(256) NOT NULL,
    address_version VARBINARY(256) NOT NULL,
    address VARBINARY(254) NOT NULL,
    password VARBINARY(255) NULL,
    status VARBINARY(16) NOT NULL,
    verified BIGINT UNSIGNED NOT NULL,
    mfa_required BIGINT UNSIGNED NOT NULL,
    roles VARBINARY(4096) NOT NULL,
    PRIMARY KEY (scope,subject),
    UNIQUE KEY account_example_address (scope,address)
) ENGINE=InnoDB;
