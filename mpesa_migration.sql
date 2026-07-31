CREATE TABLE IF NOT EXISTS mpesa_payments (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    order_id INT NOT NULL,
    phone VARCHAR(12) NOT NULL,
    amount DECIMAL(12,2) NOT NULL,
    merchant_request_id VARCHAR(100) NULL,
    checkout_request_id VARCHAR(100) NOT NULL,
    status ENUM('pending', 'paid', 'failed') NOT NULL DEFAULT 'pending',
    result_code INT NULL,
    result_desc VARCHAR(255) NULL,
    receipt_number VARCHAR(100) NULL,
    paid_at VARCHAR(30) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_mpesa_checkout_request (checkout_request_id),
    KEY idx_mpesa_payments_order_id (order_id),
    CONSTRAINT fk_mpesa_payments_order
        FOREIGN KEY (order_id) REFERENCES orders(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
