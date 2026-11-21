-- Run once against the e-commerce database before deploying the updated API.
-- Existing products keep image_url and are treated as externally hosted images.
ALTER TABLE products
  MODIFY COLUMN image_url text NOT NULL,
  ADD COLUMN image_public_id varchar(255) DEFAULT NULL;
