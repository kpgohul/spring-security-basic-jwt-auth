INSERT INTO role (role, role_description)
VALUES ('ADMIN', 'Administrator role')
ON CONFLICT (role) DO NOTHING;

INSERT INTO role (role, role_description)
VALUES ('USER', 'Default user role')
ON CONFLICT (role) DO NOTHING;
