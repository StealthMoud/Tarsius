CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    profile_desc TEXT
);

CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    price DECIMAL(10, 2) NOT NULL,
    image_url TEXT
);

CREATE TABLE IF NOT EXISTS comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    product_id INT,
    user_id INT,
    comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (product_id) REFERENCES products(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Seed internal metadata for SSRF tests
CREATE TABLE IF NOT EXISTS internal_metadata (
    id INT AUTO_INCREMENT PRIMARY KEY,
    key_name VARCHAR(255),
    key_value TEXT
);

-- Seed Data
INSERT INTO users (username, password, is_admin, profile_desc) VALUES 
('admin', 'admin123', TRUE, 'Administrator of the VulnStore.'),
('john', 'password', FALSE, 'Just a regular user posting comments.'),
('alice', 'alice123', FALSE, 'I love shopping here!');

INSERT INTO products (name, description, price, image_url) VALUES 
('Hacker Hoodie', 'A black hoodie for late night hacking.', 49.99, '/images/hoodie.jpg'),
('Mechanical Keyboard', 'Click clack, make some noise.', 129.99, '/images/keyboard.jpg'),
('Energy Drink', 'Liquid fuel for the brain.', 3.99, '/images/drink.jpg');

INSERT INTO comments (product_id, user_id, comment) VALUES 
(1, 2, 'Are these true to size?'),
(2, 3, 'Best keyboard I have ever owned!');

INSERT INTO internal_metadata (key_name, key_value) VALUES 
('aws_secret_key', 'AKIAIOSFODNN7EXAMPLE'),
('admin_panel_token', 'super-secret-backend-token-9988');
