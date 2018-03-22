-- 
-- Matt Lavery
-- Password Complexity
-- 

-- create a login with a non-complex password
CREATE LOGIN testuser1 
	WITH PASSWORD = 'password' 
	, CHECK_POLICY = OFF
GO

select * from sys.server_principals
select * from sys.syslogins


-- Script out the login with the 
EXEC sp_help_revlogin

-- create the login with new name, same password, but CHECK_POLICY on
-- Login: testuser1
CREATE LOGIN [testuser1_new] WITH PASSWORD = 0x02005360DA697CFC79C7F60814BFBA1802328057CA941B99C90C2702935E04B0A4D8E700535C5B6EC16A5F784A97FD7D9E194C8CFC93E0880BAFE225A6AC1D25553CE235E8CD HASHED, DEFAULT_DATABASE = [master], CHECK_POLICY = ON, CHECK_EXPIRATION = OFF

-- you will still be able to create the login, and it will be successful as it is already hashed.