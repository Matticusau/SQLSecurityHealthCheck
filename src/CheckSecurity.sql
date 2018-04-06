USE [master]
GO

DECLARE @duration tinyint
	, @ptochecks bit
	, @custompath NVARCHAR(500)
	, @allow_xpcmdshell bit
	, @spn_check bit
	, @logdetail bit
	, @gen_scripts bit
	, @dbScope VARCHAR(256)
	

/* SQL Security Health Check - mlavery@microsoft.com (http://aka.ms/SQLSecurity;)
READ ME - Important options for executing SQLSecurityHealthCheck
Set @duration to the number of seconds between data collection points regarding perf counters, waits and latches. 
	Duration must be between 10s and 255s (4m 15s), with a default of 90s.
Set @ptochecks to OFF if you want to skip more performance tuning and optimization oriented checks.
Uncomment @custompath below and set the custom desired path for .ps1 files. 
	If not, default location for .ps1 files is the Log folder.
Set @allow_xpcmdshell to OFF if you want to skip checks that are dependant on xp_cmdshell. 
	Note that original server setting for xp_cmdshell would be left unchanged if tests were allowed.
Set @spn_check to OFF if you want to skip SPN checks.
Set @logdetail to OFF if you want to get just the summary info on issues in the Errorlog, rather than the full detail.
Set @gen_scripts to ON if you want to generate index related scripts.
	These include drops for Duplicate, Redundant, Hypothetical and Rarely Used indexes, as well as creation statements for FK and Missing Indexes.
Set @dbScope to the appropriate list of database IDs if there's a need to have a specific scope for database specific checks.
	Valid input should be numeric value(s) between single quotes, as follows: '1,6,15,123'
	Leave NULL for all databases
*/

SET @duration = 90
SET @ptochecks = 1 --(1 = ON; 0 = OFF)
--SET @custompath = 'C:\<temp_location>'
SET @allow_xpcmdshell = 1 --(1 = ON; 0 = OFF)
SET @spn_check = 0 --(1 = ON; 0 = OFF)
SET @logdetail = 0 --(1 = ON; 0 = OFF)
SET @gen_scripts = 0 --(1 = ON; 0 = OFF)
SET @dbScope = NULL --(NULL = All DBs)

/*
DESCRIPTION: This script checks for skews and possible issues in SQL Server Security Best Practices. 
			It is based on the BPCheck script (https://github.com/Microsoft/tigertoolbox/tree/master/BPCheck)

REFERENCE: For further guidance and articles on SQL Server security refer to the ReadMe file (https://github.com/Matticusau/SQLSecurityHealthCheck/blob/master/README.md)


DISCLAIMER:
This code is not supported under any Microsoft standard support program or service.
This code and information are provided "AS IS" without warranty of any kind, either expressed or implied.
The entire risk arising out of the use or performance of the script and documentation remains with you. 
Furthermore, Microsoft or the author shall not be liable for any damages you may sustain by using this information, whether direct, 
indirect, special, incidental or consequential, including, without limitation, damages for loss of business profits, business interruption, loss of business information 
or other pecuniary loss even if it has been advised of the possibility of such damages.
Read all the implementation and usage notes thoroughly.

Version     Date        Who         What
v0.1.0.0    20/03/2018  MLavery     Initial release

PURPOSE: Checks SQL Server in scope for some of most common skewed Best Practices. Valid from SQL Server 2005 onwards.
	- Contains the following information:
	|- Uptime
	|- Windows Version and Architecture
	|- Disk space
	|- HA Information
	|- Linked servers info
	|- Instance info
	|- Resource Governor info
	|- Logon triggers
	|- Database Information
	|- Database file autogrows last 72h
	|- Database triggers
	|- Enterprise features usage
	|- Backups
	|- System Configuration
	- And performs the following checks (* means only when @ptochecks is ON):
	|- Processor
		|- Number of available Processors for this instance vs. MaxDOP setting
		|- Processor Affinity in NUMA architecture
		|- Additional Processor information
			|- Processor utilization rate in the last 2 hours *
	|- Memory
		|- Server Memory
		|- RM Task *
		|- Clock hands *
		|- Buffer Pool Consumers from Buffer Descriptors *
		|- Memory Allocations from Memory Clerks *
		|- Memory Consumers from In-Memory OLTP Engine *
		|- Memory Allocations from In-Memory OLTP Engine *
		|- OOM
		|- LPIM
	|- Pagefile
		|- Pagefile
	|- I/O
		|- I/O Stall subsection (wait for 5s) *
		|- Pending disk I/O Requests subsection (wait for a max of 5s) *
	|- Server
		|- Power plan
		|- NTFS block size in volumes that hold database files <> 64KB
		|- Disk Fragmentation Analysis (if enabled)
		|- Cluster Quorum Model
		|- Cluster QFE node equality
		|- Cluster NIC Binding order
	|- Service Accounts
		|- Service Accounts Status
		|- Service Accounts and SPN registration
	|- Instance
		|- Recommended build check
		|- Backups
		|- Global trace flags
		|- System configurations
		|- IFI
		|- Full Text Configurations
		|- Deprecated features *
		|- Default data collections (default trace, blackbox trace, SystemHealth xEvent session, sp_server_diagnostics xEvent session)
	|- Database and tempDB
		|- User objects in master
		|- DBs with collation <> master
		|- DBs with skewed compatibility level
		|- User DBs with non-default options
		|- DBs with Sparse files
		|- DBs Autogrow in percentage
		|- DBs Autogrowth > 1GB in Logs or Data (when IFI is disabled)
		|- VLF
		|- Data files and Logs / tempDB and user Databases / Backups and Database files in same volume (Mountpoint aware)
		|- tempDB data file configurations
		|- tempDB Files autogrow of equal size
	|- Performance
		|- Perf counters, Waits and Latches (wait for 90s) *
		|- Worker thread exhaustion *
		|- Blocking Chains *
		|- Plan use ratio *
		|- Hints usage *
		|- Cached Query Plans issues *
		|- Inefficient Query Plans *
		|- Declarative Referential Integrity - Untrusted Constraints *
	|- Indexes and Statistics
		|- Statistics update *
		|- Statistics sampling *
		|- Hypothetical objects *
		|- Row Index Fragmentation Analysis (if enabled) *
		|- CS Index Health Analysis (if enabled) *
		|- XTP Index Health Analysis (if enabled) *
		|- Duplicate or Redundant indexes *
		|- Unused and rarely used indexes *
		|- Indexes with large keys (> 900 bytes) *
		|- Indexes with fill factor < 80 pct *
		|- Disabled indexes *
		|- Non-unique clustered indexes *
		|- Clustered Indexes with GUIDs in key *
		|- Foreign Keys with no Index *
		|- Indexing per Table *
		|- Missing Indexes *
	|- Naming Convention
		|- Objects naming conventions
	|- Security
		|- Password check
	|- Maintenance and Monitoring
		|- SQL Agent alerts for severe errors
		|- DBCC CHECKDB, Direct Catalog Updates and Data Purity
		|- AlwaysOn/Mirroring automatic page repair
		|- Suspect pages
		|- Replication Errors
		|- Errorlog based checks
		|- System health checks
			
IMPORTANT pre-requisites:
- Only a sysadmin/local host admin will be able to perform all checks.
- If you want to perform all checks under non-sysadmin credentials, then that login must be:
	Member of serveradmin server role or have the ALTER SETTINGS server permission; 
	Member of MSDB SQLAgentOperatorRole role, or have SELECT permission on the sysalerts table in MSDB;
	Granted EXECUTE permissions on the following extended sprocs to run checks: sp_OACreate, sp_OADestroy, sp_OAGetErrorInfo, xp_enumerrorlogs, xp_fileexist and xp_regenumvalues;
	Granted EXECUTE permissions on xp_msver;
	Granted the VIEW SERVER STATE permission;
	Granted the VIEW DATABASE STATE permission;
	Granted EXECUTE permissions on xp_cmdshell or a xp_cmdshell proxy account should exist to run checks that access disk or OS security configurations.
	Member of securityadmin role, or have EXECUTE permissions on sp_readerrorlog. 
 Otherwise some checks will be bypassed and warnings will be shown.
- Powershell must be installed to run checks that access disk configurations, as well as allow execution of remote signed or unsigned scripts.
*/

SET NOCOUNT ON;
SET ANSI_WARNINGS ON;
SET QUOTED_IDENTIFIER ON;
SET DATEFORMAT mdy;

RAISERROR (N'Starting Pre-requisites check', 10, 1) WITH NOWAIT

--------------------------------------------------------------------------------------------------------------------------------
-- Pre-requisites check
--------------------------------------------------------------------------------------------------------------------------------
	DECLARE @sqlcmd NVARCHAR(max), @params NVARCHAR(500), @sqlmajorver int

	-- get the major version
	SELECT @sqlmajorver = CONVERT(int, (@@microsoftversion / 0x1000000) & 0xff);

	-- is sysadmin
	IF (ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) = 0)
	BEGIN
		RAISERROR('[WARNING: Only a sysadmin can run ALL the checks]', 16, 1, N'sysadmin')
		--RETURN
	END;

	-- TO DO
	-- Check additional least priviliges that could be used and add checks. Like the bpcheck does.

	-- Test XPCmdShell and Powershell policy
	IF @allow_xpcmdshell = 1
	BEGIN
		IF ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) = 1 -- Is sysadmin
			OR ((ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) <> 1 
				AND (SELECT COUNT(credential_id) FROM sys.credentials WHERE name = '##xp_cmdshell_proxy_account##') > 0) -- Is not sysadmin but proxy account exists
				AND (SELECT COUNT(l.name)
				FROM sys.server_permissions p JOIN sys.server_principals l 
				ON p.grantee_principal_id = l.principal_id
					AND p.class = 100 -- Server
					AND p.state IN ('G', 'W') -- Granted or Granted with Grant
					AND l.is_disabled = 0
					AND p.permission_name = 'ALTER SETTINGS'
					AND QUOTENAME(l.name) = QUOTENAME(USER_NAME())) = 0) -- Is not sysadmin but has alter settings permission
			OR ((ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) <> 1 
				AND ((SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_regread') > 0 AND
				(SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_cmdshell') > 0)))
		BEGIN
			DECLARE @pstbl_avail TABLE ([KeyExist] int)
			BEGIN TRY
				INSERT INTO @pstbl_avail
				EXEC master.sys.xp_regread N'HKEY_LOCAL_MACHINE', N'SOFTWARE\Microsoft\PowerShell\1' -- check if Powershell is installed
			END TRY
			BEGIN CATCH
				SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
				SELECT @ErrorMessage = 'Could not determine if Powershell is installed - Error raised in TRY block. ' + ERROR_MESSAGE()
				RAISERROR (@ErrorMessage, 16, 1);
			END CATCH

			SELECT @sao = CAST([value] AS smallint) FROM sys.configurations (NOLOCK) WHERE [name] = 'show advanced options'
			SELECT @xcmd = CAST([value] AS smallint) FROM sys.configurations (NOLOCK) WHERE [name] = 'xp_cmdshell'
			SELECT @ole = CAST([value] AS smallint) FROM sys.configurations (NOLOCK) WHERE [name] = 'Ole Automation Procedures'

			RAISERROR ('|-Configuration options set for Powershell enablement verification', 10, 1) WITH NOWAIT
			IF @sao = 0
			BEGIN
				EXEC sp_configure 'show advanced options', 1; RECONFIGURE WITH OVERRIDE;
			END
			IF @xcmd = 0
			BEGIN
				EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE WITH OVERRIDE;
			END
			IF @ole = 0
			BEGIN
				EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE WITH OVERRIDE;
			END
			
			IF (SELECT [KeyExist] FROM @pstbl_avail) = 1
			BEGIN
				DECLARE @psavail_output TABLE ([PS_OUTPUT] VARCHAR(2048));
				INSERT INTO @psavail_output
				EXEC master.dbo.xp_cmdshell N'%WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Get-ExecutionPolicy"'
			
				SELECT @psavail = [PS_OUTPUT] FROM @psavail_output WHERE [PS_OUTPUT] IS NOT NULL;
			END
			ELSE
			BEGIN
				RAISERROR ('   [WARNING: Powershell is not installed. Install WinRM to proceed with PS based checks]',16,1);
			END
					
			IF (@psavail IS NOT NULL AND @psavail NOT IN ('RemoteSigned','Unrestricted'))
			RAISERROR ('   [WARNING: Execution of Powershell scripts is disabled on this system.
			To change the execution policy, type the following command in Powershell console: Set-ExecutionPolicy RemoteSigned
			The Set-ExecutionPolicy cmdlet enables you to determine which Windows PowerShell scripts (if any) will be allowed to run on your computer. Windows PowerShell has four different execution policies:
			Restricted - No scripts can be run. Windows PowerShell can be used only in interactive mode.
			AllSigned - Only scripts signed by a trusted publisher can be run.
			RemoteSigned - Downloaded scripts must be signed by a trusted publisher before they can be run.
				|- REQUIRED by BP Check
			Unrestricted - No restrictions; all Windows PowerShell scripts can be run.]',16,1);

			IF (@psavail IS NOT NULL AND @psavail IN ('RemoteSigned','Unrestricted'))
			BEGIN
				RAISERROR ('|- [INFORMATION: Powershell is installed and enabled for script execution]', 10, 1) WITH NOWAIT
				
				DECLARE @psver_output TABLE ([PS_OUTPUT] VARCHAR(1024));
				INSERT INTO @psver_output
				EXEC master.dbo.xp_cmdshell N'%WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Get-Host | Format-Table -Property Version"'
			
				-- Gets PS version, as commands issued to PS v1 do not support -File
				SELECT @psver = ISNULL(LEFT([PS_OUTPUT],1),2) FROM @psver_output WHERE [PS_OUTPUT] IS NOT NULL AND ISNUMERIC(LEFT([PS_OUTPUT],1)) = 1;
				
				SET @ErrorMessage = '|- [INFORMATION: Installed Powershell is version ' + CONVERT(CHAR(1), @psver) + ']'
				RAISERROR (@ErrorMessage, 10, 1) WITH NOWAIT
			END;
			
			IF @xcmd = 0
			BEGIN
				EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE WITH OVERRIDE;
			END
			IF @ole = 0
			BEGIN
				EXEC sp_configure 'Ole Automation Procedures', 0; RECONFIGURE WITH OVERRIDE;
			END
			IF @sao = 0
			BEGIN
				EXEC sp_configure 'show advanced options', 0; RECONFIGURE WITH OVERRIDE;
			END;
		END
		ELSE
		BEGIN
			RAISERROR('   [WARNING: Missing permissions for Powershell enablement verification]', 16, 1, N'sysadmin')
			--RETURN
		END
	END;


--------------------------------------------------------------------------------------------------------------------------------
-- Information gathering
--------------------------------------------------------------------------------------------------------------------------------

	RAISERROR (N'Starting Information section', 10, 1) WITH NOWAIT

	--------------------------------------------------------------------------------------------------------------------------------
	-- Uptime subsection
	--------------------------------------------------------------------------------------------------------------------------------
	RAISERROR (N'|-Starting Uptime', 10, 1) WITH NOWAIT
	IF @sqlmajorver < 10
	BEGIN
		SET @sqlcmd = N'SELECT @UpTimeOUT = DATEDIFF(mi, login_time, GETDATE()), @StartDateOUT = login_time FROM master..sysprocesses (NOLOCK) WHERE spid = 1';
	END
	ELSE
	BEGIN
		SET @sqlcmd = N'SELECT @UpTimeOUT = DATEDIFF(mi,sqlserver_start_time,GETDATE()), @StartDateOUT = sqlserver_start_time FROM sys.dm_os_sys_info (NOLOCK)';
	END

	SET @params = N'@UpTimeOUT VARCHAR(12) OUTPUT, @StartDateOUT DATETIME OUTPUT';

	EXECUTE sp_executesql @sqlcmd, @params, @UpTimeOUT=@UpTime OUTPUT, @StartDateOUT=@StartDate OUTPUT;

	SELECT 'Information' AS [Category], 'Uptime' AS [Information], GETDATE() AS [Current_Time], @StartDate AS Last_Startup, CONVERT(VARCHAR(4),@UpTime/60/24) + 'd ' + CONVERT(VARCHAR(4),@UpTime/60%24) + 'hr ' + CONVERT(VARCHAR(4),@UpTime%60) + 'min' AS Uptime


	--------------------------------------------------------------------------------------------------------------------------------
	-- Linked servers info subsection
	--------------------------------------------------------------------------------------------------------------------------------
	RAISERROR (N'|-Starting Linked servers info', 10, 1) WITH NOWAIT
	IF (SELECT COUNT(*) FROM sys.servers AS s INNER JOIN sys.linked_logins AS l (NOLOCK) ON s.server_id = l.server_id INNER JOIN sys.server_principals AS p (NOLOCK) ON p.principal_id = l.local_principal_id WHERE s.is_linked = 1) > 0
	BEGIN
		SET @sqlcmd = 'SELECT ''Information'' AS [Category], ''Linked_servers'' AS [Information], s.name, s.product, 
		s.provider, s.data_source, s.location, s.provider_string, s.catalog, s.connect_timeout, 
		s.query_timeout, s.is_linked, s.is_remote_login_enabled, s.is_rpc_out_enabled, 
		s.is_data_access_enabled, s.is_collation_compatible, s.uses_remote_collation, s.collation_name, 
		s.lazy_schema_validation, s.is_system, s.is_publisher, s.is_subscriber, s.is_distributor, 
		s.is_nonsql_subscriber' + CASE WHEN @sqlmajorver > 9 THEN ', s.is_remote_proc_transaction_promotion_enabled' ELSE '' END + ',
		s.modify_date, CASE WHEN l.local_principal_id = 0 THEN ''local or wildcard'' ELSE p.name END AS [local_principal], 
		CASE WHEN l.uses_self_credential = 0 THEN ''use own credentials'' ELSE ''use supplied username and pwd'' END AS uses_self_credential, 
		l.remote_name, l.modify_date AS [linked_login_modify_date]
	FROM sys.servers AS s (NOLOCK)
	INNER JOIN sys.linked_logins AS l (NOLOCK) ON s.server_id = l.server_id
	INNER JOIN sys.server_principals AS p (NOLOCK) ON p.principal_id = l.local_principal_id
	WHERE s.is_linked = 1'
		EXECUTE sp_executesql @sqlcmd
	END
	ELSE
	BEGIN
		SELECT 'Information' AS [Category], 'Linked_servers' AS [Information], '[None]' AS [Status]
	END;



	--------------------------------------------------------------------------------------------------------------------------------
	-- Instance info subsection
	--------------------------------------------------------------------------------------------------------------------------------
	RAISERROR (N'|-Starting Instance info', 10, 1) WITH NOWAIT
	DECLARE @port VARCHAR(15), @replication int, @RegKey NVARCHAR(255), @cpuaffin VARCHAR(255), @cpucount int, @numa int
	DECLARE @i int, @cpuaffin_fixed VARCHAR(300), @affinitymask NVARCHAR(64), @affinity64mask NVARCHAR(64), @cpuover32 int

	IF @sqlmajorver < 11 OR (@sqlmajorver = 10 AND @sqlminorver = 50 AND @sqlbuild < 2500)
	BEGIN
		IF (ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) = 1) OR ((SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_regread') = 1)
		BEGIN
			BEGIN TRY
				SELECT @RegKey = CASE WHEN CONVERT(VARCHAR(128), SERVERPROPERTY('InstanceName')) IS NULL THEN N'Software\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib\Tcp'
					ELSE N'Software\Microsoft\Microsoft SQL Server\' + CAST(SERVERPROPERTY('InstanceName') AS NVARCHAR(128)) + N'\MSSQLServer\SuperSocketNetLib\Tcp' END
				EXEC master.sys.xp_regread N'HKEY_LOCAL_MACHINE', @RegKey, N'TcpPort', @port OUTPUT, NO_OUTPUT
			END TRY
			BEGIN CATCH
				SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
				SELECT @ErrorMessage = 'Instance info subsection - Error raised in TRY block 1. ' + ERROR_MESSAGE()
				RAISERROR (@ErrorMessage, 16, 1);
			END CATCH
		END
		ELSE
		BEGIN
			RAISERROR('[WARNING: Missing permissions for full "Instance info" checks. Bypassing TCP port check]', 16, 1, N'sysadmin')
			--RETURN
		END
	END
	ELSE
	BEGIN
		BEGIN TRY
			/*
			SET @sqlcmd = N'SELECT @portOUT = MAX(CONVERT(VARCHAR(15),value_data)) FROM sys.dm_server_registry WHERE registry_key LIKE ''%MSSQLServer\SuperSocketNetLib\Tcp\%'' AND value_name LIKE N''%TcpPort%'' AND CONVERT(float,value_data) > 0;';
			SET @params = N'@portOUT VARCHAR(15) OUTPUT';
			EXECUTE sp_executesql @sqlcmd, @params, @portOUT = @port OUTPUT;
			IF @port IS NULL
			BEGIN
				SET @sqlcmd = N'SELECT @portOUT = CONVERT(VARCHAR(15),value_data) FROM sys.dm_server_registry WHERE registry_key LIKE ''%MSSQLServer\SuperSocketNetLib\Tcp\%'' AND value_name LIKE N''%TcpDynamicPort%'' AND CONVERT(float,value_data) > 0;';
				SET @params = N'@portOUT VARCHAR(15) OUTPUT';
				EXECUTE sp_executesql @sqlcmd, @params, @portOUT = @port OUTPUT;
			END
			*/
			SET @sqlcmd = N'SELECT @portOUT = MAX(CONVERT(VARCHAR(15),port)) FROM sys.dm_tcp_listener_states WHERE is_ipv4 = 1 AND [type] = 0 AND ip_address <> ''127.0.0.1'';';
			SET @params = N'@portOUT VARCHAR(15) OUTPUT';
			EXECUTE sp_executesql @sqlcmd, @params, @portOUT = @port OUTPUT;
			IF @port IS NULL
			BEGIN
				SET @sqlcmd = N'SELECT @portOUT = MAX(CONVERT(VARCHAR(15),port)) FROM sys.dm_tcp_listener_states WHERE is_ipv4 = 0 AND [type] = 0 AND ip_address <> ''127.0.0.1'';';
				SET @params = N'@portOUT VARCHAR(15) OUTPUT';
				EXECUTE sp_executesql @sqlcmd, @params, @portOUT = @port OUTPUT;
			END
		END TRY
		BEGIN CATCH
			SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
			SELECT @ErrorMessage = 'Instance info subsection - Error raised in TRY block 2. ' + ERROR_MESSAGE()
			RAISERROR (@ErrorMessage, 16, 1);
		END CATCH
	END


	--------------------------------------------------------------------------------------------------------------------------------
	-- Feature usage subsection
	--------------------------------------------------------------------------------------------------------------------------------
	IF @sqlmajorver > 9
	BEGIN
		RAISERROR (N'|-Starting Feature usage', 10, 1) WITH NOWAIT
		/*DECLARE @dbid int, @dbname VARCHAR(1000), @sqlcmd NVARCHAR(4000)*/

		IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblPerSku'))
		DROP TABLE #tblPerSku;
		IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblPerSku'))
		CREATE TABLE #tblPerSku ([DBName] sysname NULL, [Feature_Name] VARCHAR(100));
		
		UPDATE #tmpdbs0
		SET isdone = 0;

		UPDATE #tmpdbs0
		SET isdone = 1
		WHERE [state] <> 0 OR [dbid] < 5;

		UPDATE #tmpdbs0
		SET isdone = 1
		WHERE [role] = 2 AND secondary_role_allow_connections = 0;
		
		IF (SELECT COUNT(id) FROM #tmpdbs0 WHERE isdone = 0) > 0
		BEGIN
			WHILE (SELECT COUNT(id) FROM #tmpdbs0 WHERE isdone = 0) > 0
			BEGIN
				SELECT TOP 1 @dbname = [dbname], @dbid = [dbid] FROM #tmpdbs0 WHERE isdone = 0
				
				SET @sqlcmd = 'USE ' + QUOTENAME(@dbname) + ';
				SELECT ''' + REPLACE(@dbname, CHAR(39), CHAR(95)) + ''' AS [dbname], feature_name FROM sys.dm_db_persisted_sku_features (NOLOCK)
				UNION ALL
				SELECT ''' + REPLACE(@dbname, CHAR(39), CHAR(95)) + ''' AS [dbname], ''Change_Tracking'' AS feature_name FROM sys.change_tracking_databases (NOLOCK) WHERE database_id = DB_ID()
				UNION ALL
				SELECT TOP 1 ''' + REPLACE(@dbname, CHAR(39), CHAR(95)) + ''' AS [dbname], ''Fine_grained_auditing'' AS feature_name FROM sys.database_audit_specifications (NOLOCK)'

							IF @sqlmajorver >= 13
							SET @sqlcmd = @sqlcmd + CHAR(10) + 'UNION ALL
				SELECT TOP 1 ''' + REPLACE(@dbname, CHAR(39), CHAR(95)) + ''' AS [dbname], ''Polybase'' AS feature_name FROM sys.external_data_sources (NOLOCK)
				UNION ALL
				SELECT TOP 1 ''' + REPLACE(@dbname, CHAR(39), CHAR(95)) + ''' AS [dbname], ''Row_Level_Security'' AS feature_name FROM sys.security_policies (NOLOCK)
				UNION ALL
				SELECT TOP 1 ''' + REPLACE(@dbname, CHAR(39), CHAR(95)) + ''' AS [dbname], ''Always_Encrypted'' AS feature_name FROM sys.column_master_keys (NOLOCK)
				UNION ALL
				SELECT TOP 1 ''' + REPLACE(@dbname, CHAR(39), CHAR(95)) + ''' AS [dbname], ''Dynamic_Data_Masking'' AS feature_name FROM sys.masked_columns (NOLOCK) WHERE is_masked = 1'

				BEGIN TRY
					INSERT INTO #tblPerSku
					EXECUTE sp_executesql @sqlcmd
				END TRY
				BEGIN CATCH
					SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
					SELECT @ErrorMessage = 'Feature usage subsection - Error raised in TRY block. ' + ERROR_MESSAGE()
					RAISERROR (@ErrorMessage, 16, 1);
				END CATCH
				
				UPDATE #tmpdbs0
				SET isdone = 1
				WHERE [dbid] = @dbid
			END
		END;
		
		IF @sqlmajorver > 10 AND ((@sqlmajorver = 13 AND @sqlbuild < 4000) OR @sqlmajorver < 13) AND @IsHadrEnabled = 1
		BEGIN
			INSERT INTO #tblPerSku
			SELECT [dbname], 'Always_On' AS feature_name FROM #tmpdbs0 WHERE is_database_joined = 1;
		END;
		
		IF (SELECT COUNT(DISTINCT [name]) FROM master.sys.databases (NOLOCK) WHERE database_id NOT IN (2,3) AND source_database_id IS NOT NULL) > 0 -- Snapshot
		BEGIN
			INSERT INTO #tblPerSku
			SELECT DISTINCT [name], 'DB_Snapshot' AS feature_name FROM master.sys.databases (NOLOCK) WHERE database_id NOT IN (2,3) AND source_database_id IS NOT NULL;
		END;

		IF (SELECT COUNT(DISTINCT [name]) FROM master.sys.master_files (NOLOCK) WHERE database_id NOT IN (2,3) AND [type] = 2 and file_guid IS NOT NULL) > 0 -- Filestream
		BEGIN
			INSERT INTO #tblPerSku
			SELECT DISTINCT DB_NAME(database_id), 'Filestream' AS feature_name FROM sys.master_files (NOLOCK) WHERE database_id NOT IN (2,3) AND [type] = 2 and file_guid IS NOT NULL;	
		END;
		
		IF (SELECT COUNT([Feature_Name]) FROM #tblPerSku) > 0
		BEGIN
			SELECT 'Information' AS [Category], 'Feature_usage' AS [Check], '[INFORMATION: Some databases are using features that are not common to all editions]' AS [Comment]
			SELECT 'Information' AS [Category], 'Feature_usage' AS [Information], DBName AS [Database_Name], [Feature_Name]
			FROM #tblPerSku
			ORDER BY 2, 3
		END
		ELSE
		BEGIN
			SELECT 'Information' AS [Category], 'Feature_usage' AS [Check], '[NA]' AS [Comment]
		END
	END;

	--------------------------------------------------------------------------------------------------------------------------------
	-- System Configuration subsection
	--------------------------------------------------------------------------------------------------------------------------------
	RAISERROR (N'|-Starting System Configuration', 10, 1) WITH NOWAIT
	SELECT 'Information' AS [Category], 'All_System_Configurations' AS [Information],
		name AS [Name],
		configuration_id AS [Number],
		minimum AS [Minimum],
		maximum AS [Maximum],
		is_dynamic AS [Dynamic],
		is_advanced AS [Advanced],
		value AS [ConfigValue],
		value_in_use AS [RunValue],
		description AS [Description]
	FROM sys.configurations (NOLOCK)
	ORDER BY name OPTION (RECOMPILE);


--------------------------------------------------------------------------------------------------------------------------------
-- Checks
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'Starting Checks', 10, 1) WITH NOWAIT


	RAISERROR (N'|-Starting Service Accounts Checks', 10, 1) WITH NOWAIT
	--------------------------------------------------------------------------------------------------------------------------------
	-- Service Accounts Status subsection
	--------------------------------------------------------------------------------------------------------------------------------
	RAISERROR (N'  |-Starting Service Accounts Status', 10, 1) WITH NOWAIT
	IF (ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) = 1) 
		OR ((SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_regread') = 1 AND
			(SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_servicecontrol') = 1)
	BEGIN
		DECLARE @rc int, @profile NVARCHAR(128)
		DECLARE @sqlservice NVARCHAR(128), @sqlagentservice NVARCHAR(128), @dtsservice NVARCHAR(128), @ftservice NVARCHAR(128)
		DECLARE @browservice NVARCHAR(128), @olapservice NVARCHAR(128), @rsservice NVARCHAR(128)
		DECLARE @statussqlservice NVARCHAR(20), @statussqlagentservice NVARCHAR(20), @statusdtsservice NVARCHAR(20), @statusftservice NVARCHAR(20)
		DECLARE @statusbrowservice NVARCHAR(20), @statusolapservice NVARCHAR(20), @statusrsservice NVARCHAR(20)
		DECLARE @regkeysqlservice NVARCHAR(256), @regkeysqlagentservice NVARCHAR(256), @regkeydtsservice NVARCHAR(256), @regkeyftservice NVARCHAR(256)
		DECLARE @regkeybrowservice NVARCHAR(256), @regkeyolapservice NVARCHAR(256), @regkeyrsservice NVARCHAR(256)
		DECLARE @accntsqlservice NVARCHAR(128), @accntsqlagentservice NVARCHAR(128), @accntdtsservice NVARCHAR(128), @accntftservice NVARCHAR(128)
		DECLARE @accntbrowservice NVARCHAR(128), @accntolapservice NVARCHAR(128), @accntrsservice NVARCHAR(128)

		-- Get service names
		IF (@instancename IS NULL) 
		BEGIN
			IF @sqlmajorver < 11
			BEGIN
				SELECT @sqlservice = N'MSSQLServer' 
				SELECT @sqlagentservice = N'SQLServerAgent'
			END
			SELECT @olapservice = N'MSSQLServerOLAPService' 
			SELECT @rsservice = N'ReportServer' 
		END 
		ELSE 
		BEGIN
			IF @sqlmajorver < 11
			BEGIN
				SELECT @sqlservice = N'MSSQL$' + @instancename
				SELECT @sqlagentservice = N'SQLAgent$' + @instancename
			END 
			SELECT @olapservice = N'MSOLAP$' + @instancename
			SELECT @rsservice = N'ReportServer$' + @instancename 
		END

		IF @sqlmajorver = 9
		BEGIN
			SELECT @dtsservice = N'MsDtsServer'
		END
		ELSE
		BEGIN
			SELECT @dtsservice = N'MsDtsServer' + CONVERT(VARCHAR, @sqlmajorver) + '0'
		END

		IF (SELECT ISNULL(FULLTEXTSERVICEPROPERTY('IsFulltextInstalled'),0)) = 1
		BEGIN
			IF (@instancename IS NULL) AND @sqlmajorver = 10
			BEGIN 
				SELECT @ftservice = N'MSSQLFDLauncher'
			END 
			ELSE IF (@instancename IS NOT NULL) AND @sqlmajorver = 10
			BEGIN 
				SELECT @ftservice = N'MSSQLFDLauncher$' + @instancename
			END
			ELSE IF (@instancename IS NULL) AND @sqlmajorver = 9
			BEGIN 
				SELECT @ftservice = N'msftesql'
			END
			ELSE IF (@instancename IS NOT NULL) AND @sqlmajorver = 9 
			BEGIN 
				SELECT @ftservice = N'msftesql$' + @instancename
			END
		END

		SELECT @browservice = N'SQLBrowser'

		IF @sqlmajorver < 11
		BEGIN
			SELECT @regkeysqlservice = N'SYSTEM\CurrentControlSet\Services\' + @sqlservice
			SELECT @regkeysqlagentservice = N'SYSTEM\CurrentControlSet\Services\' + @sqlagentservice
			IF (SELECT ISNULL(FULLTEXTSERVICEPROPERTY('IsFulltextInstalled'),0)) = 1
			BEGIN
				SELECT @regkeyftservice = N'SYSTEM\CurrentControlSet\Services\' + @ftservice
			END
		END
		SELECT @regkeyolapservice = N'SYSTEM\CurrentControlSet\Services\' + @olapservice
		SELECT @regkeyrsservice = N'SYSTEM\CurrentControlSet\Services\' + @rsservice
		SELECT @regkeydtsservice = N'SYSTEM\CurrentControlSet\Services\' + @dtsservice
		SELECT @regkeybrowservice = N'SYSTEM\CurrentControlSet\Services\' + @browservice
		
		-- Service status
		IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#RegResult'))
		CREATE TABLE #RegResult (ResultValue bit)
		IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#ServiceStatus'))
		CREATE TABLE #ServiceStatus (ServiceStatus VARCHAR(128))

		IF @sqlmajorver < 11 OR (@sqlmajorver = 10 AND @sqlminorver = 50 AND @sqlbuild >= 2500)
		BEGIN
			BEGIN TRY
				INSERT INTO #RegResult (ResultValue)
				EXEC master.sys.xp_regread N'HKEY_LOCAL_MACHINE', @regkeysqlservice
				IF (SELECT TOP 1 ResultValue FROM #RegResult) = 1 
				BEGIN
					INSERT INTO #ServiceStatus (ServiceStatus)
					EXEC master.sys.xp_servicecontrol N'QUERYSTATE', @sqlservice
					SELECT @statussqlservice = ServiceStatus FROM #ServiceStatus
					TRUNCATE TABLE #ServiceStatus;
				END
				ELSE
				BEGIN
					SET @statussqlservice = 'Not Installed'
				END
				TRUNCATE TABLE #RegResult;
			END TRY
			BEGIN CATCH
				SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
				SELECT @ErrorMessage = 'Service Accounts and Status subsection - Error raised in TRY block 1. ' + ERROR_MESSAGE()
				RAISERROR (@ErrorMessage, 16, 1);
			END CATCH
		END
		ELSE
		BEGIN
			SET @sqlcmd = N'SELECT @statussqlserviceOUT = status_desc FROM sys.dm_server_services WHERE servicename LIKE ''SQL Server%'' AND servicename NOT LIKE ''SQL Server Agent%''';
			SET @params = N'@statussqlserviceOUT NVARCHAR(20) OUTPUT';
			EXECUTE sp_executesql @sqlcmd, @params, @statussqlserviceOUT=@statussqlservice OUTPUT;
			IF @statussqlservice IS NULL
			BEGIN
				SET @statussqlservice = 'Not Installed'
			END
		END

		IF @sqlmajorver < 11 OR (@sqlmajorver = 10 AND @sqlminorver = 50 AND @sqlbuild >= 2500)
		BEGIN
			BEGIN TRY
				INSERT INTO #RegResult (ResultValue)
				EXEC master.sys.xp_regread N'HKEY_LOCAL_MACHINE', @regkeysqlagentservice
				IF (SELECT TOP 1 ResultValue FROM #RegResult) = 1 
				BEGIN
					INSERT INTO #ServiceStatus (ServiceStatus)
					EXEC master.sys.xp_servicecontrol N'QUERYSTATE', @sqlagentservice
					SELECT @statussqlagentservice = ServiceStatus FROM #ServiceStatus
					TRUNCATE TABLE #ServiceStatus;
				END
				ELSE
				BEGIN
					SET @statussqlagentservice = 'Not Installed'
				END
				TRUNCATE TABLE #RegResult;
			END TRY
			BEGIN CATCH
				SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
				SELECT @ErrorMessage = 'Service Accounts and Status subsection - Error raised in TRY block 2. ' + ERROR_MESSAGE()
				RAISERROR (@ErrorMessage, 16, 1);
			END CATCH
		END
		ELSE
		BEGIN
			SET @sqlcmd = N'SELECT @statussqlagentserviceOUT = status_desc FROM sys.dm_server_services WHERE servicename LIKE ''SQL Server Agent%''';
			SET @params = N'@statussqlagentserviceOUT NVARCHAR(20) OUTPUT';
			EXECUTE sp_executesql @sqlcmd, @params, @statussqlagentserviceOUT=@statussqlagentservice OUTPUT;
			IF @statussqlagentservice IS NULL
			BEGIN
				SET @statussqlagentservice = 'Not Installed'
			END
		END

		IF @sqlmajorver < 11 OR (@sqlmajorver = 10 AND @sqlminorver = 50 AND @sqlbuild >= 2500)
		BEGIN
			IF (SELECT ISNULL(FULLTEXTSERVICEPROPERTY('IsFulltextInstalled'),0)) = 1
			BEGIN
				BEGIN TRY
					INSERT INTO #RegResult (ResultValue)
					EXEC master.sys.xp_regread N'HKEY_LOCAL_MACHINE', @regkeyftservice
					IF (SELECT TOP 1 ResultValue FROM #RegResult) = 1 
					BEGIN
						INSERT INTO #ServiceStatus (ServiceStatus)
						EXEC master.sys.xp_servicecontrol N'QUERYSTATE', @ftservice
						SELECT @statusftservice = ServiceStatus FROM #ServiceStatus
						TRUNCATE TABLE #ServiceStatus;
					END
					ELSE
					BEGIN
						SET @statusftservice = '[INFORMATION: Service is not installed]'
					END
					TRUNCATE TABLE #RegResult;
				END TRY
				BEGIN CATCH
					SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
					SELECT @ErrorMessage = 'Service Accounts and Status subsection - Error raised in TRY block 3. ' + ERROR_MESSAGE()
					RAISERROR (@ErrorMessage, 16, 1);
				END CATCH
			END
		END
		ELSE
		BEGIN
			SET @sqlcmd = N'SELECT @statusftserviceOUT = status_desc FROM sys.dm_server_services WHERE servicename LIKE ''SQL Full-text Filter Daemon Launcher%''';
			SET @params = N'@statusftserviceOUT NVARCHAR(20) OUTPUT';
			EXECUTE sp_executesql @sqlcmd, @params, @statusftserviceOUT=@statusftservice OUTPUT;
			IF @statusftservice IS NULL
			BEGIN
				SET @statusftservice = '[INFORMATION: Service is not installed]'
			END
		END

		BEGIN TRY
			INSERT INTO #RegResult (ResultValue)
			EXEC master.sys.xp_regread N'HKEY_LOCAL_MACHINE', @regkeyolapservice
			IF (SELECT TOP 1 ResultValue FROM #RegResult) = 1 
			BEGIN
				INSERT INTO #ServiceStatus (ServiceStatus)
				EXEC master.sys.xp_servicecontrol N'QUERYSTATE', @olapservice
				SELECT @statusolapservice = ServiceStatus FROM #ServiceStatus
				TRUNCATE TABLE #ServiceStatus;
			END
			ELSE
			BEGIN
				SET @statusolapservice = 'Not Installed'
			END
			TRUNCATE TABLE #RegResult;
		END TRY
			BEGIN CATCH
			SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
			SELECT @ErrorMessage = 'Service Accounts and Status subsection - Error raised in TRY block 4. ' + ERROR_MESSAGE()
			RAISERROR (@ErrorMessage, 16, 1);
		END CATCH

		BEGIN TRY
			INSERT INTO #RegResult (ResultValue)
			EXEC master.sys.xp_regread N'HKEY_LOCAL_MACHINE', @regkeyrsservice
			IF (SELECT TOP 1 ResultValue FROM #RegResult) = 1 
			BEGIN
				INSERT INTO #ServiceStatus (ServiceStatus)
				EXEC master.sys.xp_servicecontrol N'QUERYSTATE', @rsservice
				SELECT @statusrsservice = ServiceStatus FROM #ServiceStatus
				TRUNCATE TABLE #ServiceStatus;
			END
			ELSE
			BEGIN
				SET @statusrsservice = 'Not Installed'
			END
			TRUNCATE TABLE #RegResult;
		END TRY
		BEGIN CATCH
			SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
			SELECT @ErrorMessage = 'Service Accounts and Status subsection - Error raised in TRY block 5. ' + ERROR_MESSAGE()
			RAISERROR (@ErrorMessage, 16, 1);
		END CATCH

		BEGIN TRY
			INSERT INTO #RegResult (ResultValue)
			EXEC master.sys.xp_regread N'HKEY_LOCAL_MACHINE', @regkeydtsservice
			IF (SELECT TOP 1 ResultValue FROM #RegResult) = 1 
			BEGIN
				INSERT INTO #ServiceStatus (ServiceStatus)
				EXEC master.sys.xp_servicecontrol N'QUERYSTATE', @dtsservice
				SELECT @statusdtsservice = ServiceStatus FROM #ServiceStatus
				TRUNCATE TABLE #ServiceStatus;
			END
			ELSE
			BEGIN
				SET @statusdtsservice = 'Not Installed'
			END
			TRUNCATE TABLE #RegResult;
		END TRY
		BEGIN CATCH
			SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
			SELECT @ErrorMessage = 'Service Accounts and Status subsection - Error raised in TRY block 6. ' + ERROR_MESSAGE()
			RAISERROR (@ErrorMessage, 16, 1);
		END CATCH

		BEGIN TRY
			INSERT INTO #RegResult (ResultValue)
			EXEC master.sys.xp_regread N'HKEY_LOCAL_MACHINE', @regkeybrowservice
			IF (SELECT TOP 1 ResultValue FROM #RegResult) = 1 
			BEGIN
				INSERT INTO #ServiceStatus (ServiceStatus)
				EXEC master.sys.xp_servicecontrol N'QUERYSTATE', @browservice
				SELECT @statusbrowservice = ServiceStatus FROM #ServiceStatus
				TRUNCATE TABLE #ServiceStatus;
			END
			ELSE
			BEGIN
				SET @statusbrowservice = 'Not Installed'
			END
		END TRY
		BEGIN CATCH
			SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
			SELECT @ErrorMessage = 'Service Accounts and Status subsection - Error raised in TRY block 7. ' + ERROR_MESSAGE()
			RAISERROR (@ErrorMessage, 16, 1);
		END CATCH

		DROP TABLE #RegResult;
		DROP TABLE #ServiceStatus;

		-- Accounts
		IF @sqlmajorver < 11 OR (@sqlmajorver = 10 AND @sqlminorver = 50 AND @sqlbuild >= 2500)
		BEGIN
			BEGIN TRY
				EXEC master.sys.xp_regread N'HKEY_LOCAL_MACHINE', @regkeysqlservice, N'ObjectName', @accntsqlservice OUTPUT, NO_OUTPUT
				EXEC master.sys.xp_regread N'HKEY_LOCAL_MACHINE', @regkeysqlagentservice, N'ObjectName', @accntsqlagentservice OUTPUT, NO_OUTPUT
				EXEC master.sys.xp_regread N'HKEY_LOCAL_MACHINE', @regkeyftservice, N'ObjectName', @accntftservice OUTPUT, NO_OUTPUT
			END TRY
			BEGIN CATCH
				SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
				SELECT @ErrorMessage = 'Service Accounts and Status subsection - Error raised in TRY block 8. ' + ERROR_MESSAGE()
				RAISERROR (@ErrorMessage, 16, 1);
			END CATCH
		END
		ELSE
		BEGIN
			BEGIN TRY
				SET @sqlcmd = N'SELECT @accntsqlserviceOUT = service_account FROM sys.dm_server_services WHERE servicename LIKE ''SQL Server%'' AND servicename NOT LIKE ''SQL Server Agent%''';
				SET @params = N'@accntsqlserviceOUT NVARCHAR(128) OUTPUT';
				EXECUTE sp_executesql @sqlcmd, @params, @accntsqlserviceOUT=@accntsqlservice OUTPUT;
				SET @sqlcmd = N'SELECT @accntsqlagentserviceOUT = service_account FROM sys.dm_server_services WHERE servicename LIKE ''SQL Server Agent%''';
				SET @params = N'@accntsqlagentserviceOUT NVARCHAR(128) OUTPUT';
				EXECUTE sp_executesql @sqlcmd, @params, @accntsqlagentserviceOUT=@accntsqlagentservice OUTPUT;
				SET @sqlcmd = N'SELECT @accntftserviceOUT = service_account FROM sys.dm_server_services WHERE servicename LIKE ''SQL Full-text Filter Daemon Launcher%''';
				SET @params = N'@accntftserviceOUT NVARCHAR(128) OUTPUT';
				EXECUTE sp_executesql @sqlcmd, @params, @accntftserviceOUT=@accntftservice OUTPUT;
			END TRY
			BEGIN CATCH
				SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
				SELECT @ErrorMessage = 'Service Accounts and Status subsection - Error raised in TRY block 9. ' + ERROR_MESSAGE()
				RAISERROR (@ErrorMessage, 16, 1);
			END CATCH
		END
		
		BEGIN TRY
			EXEC master.sys.xp_regread N'HKEY_LOCAL_MACHINE', @regkeyolapservice, N'ObjectName', @accntolapservice OUTPUT, NO_OUTPUT
			EXEC master.sys.xp_regread N'HKEY_LOCAL_MACHINE', @regkeyrsservice, N'ObjectName', @accntrsservice OUTPUT, NO_OUTPUT
			EXEC master.sys.xp_regread N'HKEY_LOCAL_MACHINE', @regkeydtsservice, N'ObjectName', @accntdtsservice OUTPUT, NO_OUTPUT
			EXEC master.sys.xp_regread N'HKEY_LOCAL_MACHINE', @regkeybrowservice, N'ObjectName', @accntbrowservice OUTPUT, NO_OUTPUT
		END TRY
		BEGIN CATCH
			SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
			SELECT @ErrorMessage = 'Service Accounts and Status subsection - Error raised in TRY block 10. ' + ERROR_MESSAGE()
			RAISERROR (@ErrorMessage, 16, 1);
		END CATCH
		
		SELECT 'Service_Account_checks' AS [Category], 'Service_Status' AS [Check], 'SQL_Server' AS [Service], @statussqlservice AS [Status], @accntsqlservice AS [Account],
			CASE WHEN @statussqlservice = 'Not Installed' THEN '[INFORMATION: Service is not installed]'
				WHEN @statussqlservice LIKE 'Stopped%' THEN '[WARNING: Service is stopped]'
				WHEN @accntsqlservice IS NULL THEN '[WARNING: Could not detect account for check]' 
				WHEN @accntsqlservice = 'NT AUTHORITY\LOCALSERVICE' THEN '[WARNING: Running SQL Server under this account is not supported]'
				WHEN @clustered = 1 AND @accntsqlservice = 'NT AUTHORITY\SYSTEM' THEN '[WARNING: Running SQL Server under this account is not supported]' 
				WHEN @clustered = 1 AND @accntsqlservice = 'LocalSystem' THEN '[WARNING: Running SQL Server under this account is not supported]' 
				WHEN @clustered = 1 AND @accntsqlservice = 'NT AUTHORITY\NETWORKSERVICE' THEN '[WARNING: Running SQL Server under this account is not supported]' 
				WHEN @clustered = 0 AND @accntsqlservice = 'NT AUTHORITY\SYSTEM' THEN '[WARNING: Running SQL Server under this account is not recommended]' 
				WHEN @clustered = 0 AND @accntsqlservice = 'LocalSystem' THEN '[WARNING: Running SQL Server under this account is not recommended]' 
				WHEN @clustered = 0 AND @accntsqlservice = 'NT AUTHORITY\NETWORKSERVICE' THEN '[WARNING: Running SQL Server under this account is not recommended]'
				-- MSA for WS2008R2 or higher, SQL Server 2012 or higher, non-clustered (http://msdn.microsoft.com/en-us/library/ms143504(v=SQL.110).aspx#Default_Accts)
				WHEN @clustered = 0 AND @sqlmajorver >= 11 AND CONVERT(DECIMAL(3,1), @osver) >= 6.1 AND @accntsqlservice <> 'NT SERVICE\MSSQLSERVER' AND @accntsqlservice NOT LIKE 'NT SERVICE\MSSQL$%' THEN '[INFORMATION: SQL Server is not running with the default account]'
				ELSE '[OK]' 
			END AS [Deviation]
		UNION ALL
		SELECT 'Service_Account_checks' AS [Category], 'Service_Status' AS [Check], 'SQL_Server_Agent' AS [Service], @statussqlagentservice AS [Status], @accntsqlagentservice AS [Account],
			CASE WHEN @statussqlagentservice = 'Not Installed' THEN '[INFORMATION: Service is not installed]'
				WHEN @statussqlagentservice LIKE 'Stopped%' THEN '[WARNING: Service is stopped]'
				WHEN @accntsqlagentservice IS NULL THEN '[WARNING: Could not detect account for check]' 
				WHEN @accntsqlagentservice = 'NT AUTHORITY\LOCALSERVICE' THEN '[WARNING: Running SQL Server Agent under this account is not supported]'
				WHEN @accntsqlagentservice = @accntsqlservice THEN '[WARNING: Running SQL Server Agent under the same account as SQL Server is not recommended]' 
				WHEN @clustered = 1 AND @accntsqlagentservice = 'NT AUTHORITY\SYSTEM' THEN '[WARNING: Running SQL Server Agent under this account is not supported]' 
				WHEN @clustered = 1 AND @accntsqlagentservice = 'NT AUTHORITY\NETWORKSERVICE' THEN '[WARNING: Running SQL Server Agent under this account is not supported]' 
				WHEN @clustered = 0 AND @accntsqlagentservice = 'NT AUTHORITY\SYSTEM' THEN '[WARNING: Running SQL Server Agent under this account is not recommended]' 
				WHEN @clustered = 0 AND @accntsqlagentservice = 'NT AUTHORITY\NETWORKSERVICE' THEN '[WARNING: Running SQL Server Agent under this account is not recommended]' 
				WHEN @osver IS NULL THEN '[WARNING: Could not determine Windows version for check]'
				-- MSA for WS2008R2 or higher, SQL Server 2012 or higher, non-clustered (http://msdn.microsoft.com/en-us/library/ms143504(v=SQL.110).aspx#Default_Accts)
				WHEN @clustered = 0 AND @sqlmajorver >= 11 AND CONVERT(DECIMAL(3,1), @osver) >= 6.1 AND @accntsqlagentservice <> 'NT SERVICE\SQLSERVERAGENT' AND @accntsqlagentservice NOT LIKE 'NT SERVICE\SQLAGENT$%' THEN '[INFORMATION: SQL Server Agent is not running with the default account]'
				ELSE '[OK]' 
			END AS [Deviation]
		UNION ALL
		SELECT 'Service_Account_checks' AS [Category], 'Service_Status' AS [Check], 'SQL_Server_Analysis_Services' AS [Service], @statusolapservice AS [Status], @accntolapservice AS [Account],
			CASE WHEN @statusolapservice = 'Not Installed' THEN '[INFORMATION: Service is not installed]'
				WHEN @statusolapservice LIKE 'Stopped%' THEN '[WARNING: Service is stopped]'
				WHEN @accntolapservice IS NULL THEN '[WARNING: Could not detect account for check]' 
				WHEN @accntolapservice = @accntsqlservice THEN '[WARNING: Running SQL Server Analysis Services under the same account as SQL Server is not recommended]' 
				WHEN @clustered = 0 AND @sqlmajorver <= 10 AND @accntolapservice <> 'NT AUTHORITY\NETWORKSERVICE' AND @accntdtsservice <> 'NT AUTHORITY\LOCALSERVICE' THEN '[INFORMATION: SQL Server Analysis Services is not running with the default account]'
				WHEN @osver IS NULL THEN '[WARNING: Could not determine Windows version for check]'
				WHEN @clustered = 0 AND @sqlmajorver >= 11 AND CONVERT(DECIMAL(3,1), @osver) <= 6.0 AND @accntolapservice <> 'NT AUTHORITY\NETWORKSERVICE' THEN '[INFORMATION: SQL Server Analysis Services is not running with the default account]'
				-- MSA for WS2008R2 or higher, SQL Server 2005 or higher, non-clustered (http://msdn.microsoft.com/en-us/library/ms143504(v=SQL.110).aspx#Default_Accts)
				WHEN @clustered = 0 AND @sqlmajorver >= 11 AND CONVERT(DECIMAL(3,1), @osver) >= 6.1 AND @accntolapservice <> 'NT SERVICE\MSSQLServerOLAPService' AND @accntolapservice NOT LIKE 'NT SERVICE\MSOLAP$%' THEN '[INFORMATION: SQL Server Analysis Services is not running with the default account]'
				ELSE '[OK]' 
			END AS [Deviation]
		UNION ALL
		SELECT 'Service_Account_checks' AS [Category], 'Service_Status' AS [Check], 'SQL_Server_Integration_Services' AS [Service], @statusdtsservice AS [Status], @accntdtsservice AS [Account],
			CASE WHEN @statusdtsservice = 'Not Installed' THEN '[INFORMATION: Service is not installed]'
				WHEN @statusdtsservice LIKE 'Stopped%' THEN '[WARNING: Service is stopped]'
				WHEN @accntdtsservice IS NULL THEN '[WARNING: Could not detect account for check]' 
				WHEN @accntdtsservice = @accntsqlservice THEN '[WARNING: Running SQL Server Integration Services under the same account as SQL Server is not recommended]' 
				WHEN @osver IS NULL THEN '[WARNING: Could not determine Windows version for check]'
				WHEN CONVERT(DECIMAL(3,1), @osver) <= 6.0 AND @accntdtsservice <> 'NT AUTHORITY\NETWORKSERVICE' AND @accntdtsservice <> 'NT AUTHORITY\LOCALSYSTEM' THEN '[INFORMATION: SQL Server Integration Services is not running with the default account]'
				-- MSA for WS2008R2 or higher, SQL Server 2012 or higher (http://msdn.microsoft.com/en-us/library/ms143504(v=SQL.110).aspx#Default_Accts)
				WHEN @sqlmajorver >= 11 AND CONVERT(DECIMAL(3,1), @osver) >= 6.1 AND @accntdtsservice NOT IN ('NT SERVICE\MSDTSSERVER100', 'NT SERVICE\MSDTSSERVER110') THEN '[INFORMATION: SQL Server Integration Services is not running with the default account]'
				ELSE '[OK]' 
			END AS [Deviation]
		UNION ALL
		SELECT 'Service_Account_checks' AS [Category], 'Service_Status' AS [Check], 'SQL_Server_Reporting_Services' AS [Service], @statusrsservice AS [Status], @accntrsservice AS [Account],
			CASE WHEN @statusrsservice = 'Not Installed' THEN '[INFORMATION: Service is not installed]'
				WHEN @statusrsservice LIKE 'Stopped%' THEN '[WARNING: Service is stopped]'
				WHEN @accntrsservice IS NULL THEN '[WARNING: Could not detect account for check]' 
				WHEN @accntrsservice = @accntsqlservice THEN '[WARNING: Running SQL Server Reporting Services under the same account as SQL Server is not recommended]' 
				WHEN @clustered = 0 AND @sqlmajorver <= 10 AND @accntrsservice <> 'NT AUTHORITY\NETWORKSERVICE' AND @accntdtsservice <> 'NT AUTHORITY\LOCALSYSTEM' THEN '[INFORMATION: SQL Server Reporting Services is not running with the default account]'
				WHEN @osver IS NULL THEN '[WARNING: Could not determine Windows version for check]'
				WHEN @sqlmajorver >= 11 AND CONVERT(DECIMAL(3,1), @osver) <= 6.0 AND @accntrsservice <> 'NT AUTHORITY\NETWORKSERVICE' THEN '[INFORMATION: SQL Server Reporting Services is not running with the default account]'
				-- MSA for WS2008R2 or higher, SQL Server 2012 or higher (http://msdn.microsoft.com/en-us/library/ms143504(v=SQL.110).aspx#Default_Accts)
				WHEN @sqlmajorver >= 11 AND CONVERT(DECIMAL(3,1), @osver) >= 6.1 AND @accntrsservice <> 'NT SERVICE\ReportServer' AND @accntrsservice NOT LIKE 'NT SERVICE\ReportServer$%' THEN '[INFORMATION: SQL Server Reporting Services is not running with the default account]'
				ELSE '[OK]' 
			END AS [Deviation]
		UNION ALL
		SELECT 'Service_Account_checks' AS [Category], 'Service_Status' AS [Check], 'Full-Text' AS [Service], ISNULL(@statusftservice, 'Not Installed') AS [Status], ISNULL(@accntftservice,'') AS [Account], 
			CASE WHEN (SELECT ISNULL(FULLTEXTSERVICEPROPERTY('IsFulltextInstalled'),0)) = 1 THEN 
				CASE WHEN @statusftservice = 'Not Installed' THEN '[INFORMATION: Service is not installed]'
					WHEN @statusftservice LIKE 'Stopped%' THEN '[WARNING: Service is stopped]'
					WHEN @accntftservice IS NULL THEN '[WARNING: Could not detect account for check]' 
					WHEN @accntftservice = @accntsqlservice THEN '[WARNING: Running Full-Text Daemon under the same account as SQL Server is not recommended]' 
					WHEN @accntftservice = 'NT AUTHORITY\SYSTEM' THEN '[WARNING: Running Full-Text Service under this account is not recommended]' 
					WHEN @osver IS NULL THEN '[WARNING: Could not determine Windows version for check]'
					WHEN @sqlmajorver <= 10 AND @accntftservice = 'NT AUTHORITY\NETWORKSERVICE' THEN '[WARNING: Running Full-Text Service under this account is not recommended]' 
					WHEN @sqlmajorver <= 10 AND @accntftservice <> 'NT AUTHORITY\LOCALSERVICE' THEN '[WARNING: Full-Text Daemon is not running with the default account]'
					WHEN @sqlmajorver >= 11 AND CONVERT(DECIMAL(3,1), @osver) <= 6.0 AND @accntftservice <> 'NT AUTHORITY\LOCALSERVICE' THEN '[WARNING: Full-Text Daemon is not running with the default account]'
					-- MSA for WS2008R2 or higher, SQL Server 2012 or higher (http://msdn.microsoft.com/en-us/library/ms143504(v=SQL.110).aspx#Default_Accts)
					WHEN @sqlmajorver >= 11 AND CONVERT(DECIMAL(3,1), @osver) >= 6.1 AND @accntftservice <> 'NT SERVICE\MSSQLFDLauncher' AND @accntftservice NOT LIKE 'NT SERVICE\MSSQLFDLauncher$%' THEN '[WARNING: Full-Text Daemon is not running with the default account]'
				ELSE '[OK]' END 
			ELSE '[INFORMATION: Service is not installed]' 
			END AS [Deviation]
		UNION ALL
		SELECT 'Service_Account_checks' AS [Category], 'Service_Status' AS [Check], 'SQL_Server_Browser' AS [Service], @statusbrowservice AS [Status], @accntbrowservice AS [Account],
			CASE WHEN @statusbrowservice = 'Not Installed' THEN '[INFORMATION: Service is not installed]'
				WHEN @statusbrowservice LIKE 'Stopped%' AND @instancename IS NOT NULL THEN '[WARNING: Service is stopped on a named instance]'
				WHEN @statusbrowservice LIKE 'Stopped%' AND @instancename IS NULL THEN '[WARNING: Service is stopped]'
				WHEN @accntbrowservice IS NULL THEN '[WARNING: Could not detect account for check]' 
				WHEN @accntbrowservice = @accntsqlservice THEN '[WARNING: Running SQL Server Browser under the same account as SQL Server is not recommended]' 
				WHEN @accntbrowservice <> 'NT AUTHORITY\LOCALSERVICE' THEN '[WARNING: SQL Server Browser is not running with the default account]'
				ELSE '[OK]' 
			END AS [Deviation];
	END
	ELSE
	BEGIN
		RAISERROR('[WARNING: Only a sysadmin can run the "Service Accounts Status" checks. Otherwise, you must be a granted EXECUTE permissions on xp_regread and xp_servicecontrol. Bypassing check]', 16, 1, N'sysadmin')
		--RETURN
	END;

	--------------------------------------------------------------------------------------------------------------------------------
	-- Service Accounts and SPN registration subsection
	--------------------------------------------------------------------------------------------------------------------------------
	RAISERROR (N'  |-Starting Service Accounts and SPN registration', 10, 1) WITH NOWAIT
	IF @accntsqlservice IS NOT NULL AND @accntsqlservice NOT IN ('NT AUTHORITY\LOCALSERVICE','NT AUTHORITY\SYSTEM','LocalSystem','NT AUTHORITY\NETWORKSERVICE') AND @allow_xpcmdshell = 1 AND @spn_check = 1
	BEGIN
		IF ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) = 1 -- Is sysadmin
			OR ((ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) <> 1 
				AND (SELECT COUNT(credential_id) FROM sys.credentials WHERE name = '##xp_cmdshell_proxy_account##') > 0)) -- Is not sysadmin but proxy account exists
			OR ((ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) <> 1 
				AND (SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_cmdshell') > 0))
		BEGIN
			RAISERROR ('    |-Configuration options set for SPN check', 10, 1) WITH NOWAIT
			SELECT @sao = CAST([value] AS smallint) FROM sys.configurations (NOLOCK) WHERE [name] = 'show advanced options'
			SELECT @xcmd = CAST([value] AS smallint) FROM sys.configurations (NOLOCK) WHERE [name] = 'xp_cmdshell'
			IF @sao = 0
			BEGIN
				EXEC sp_configure 'show advanced options', 1; RECONFIGURE WITH OVERRIDE;
			END
			IF @xcmd = 0
			BEGIN
				EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE WITH OVERRIDE;
			END

			BEGIN TRY
				DECLARE /*@CMD NVARCHAR(4000),*/ @line int, @linemax int, @SPN VARCHAR(8000), @SPNMachine VARCHAR(8000)
				IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#xp_cmdshell_AcctSPNoutput'))
				DROP TABLE #xp_cmdshell_AcctSPNoutput;
				IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#xp_cmdshell_AcctSPNoutput'))
				CREATE TABLE #xp_cmdshell_AcctSPNoutput (line int IDENTITY(1,1) PRIMARY KEY, [Output] VARCHAR (8000));
				
				IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#xp_cmdshell_DupSPNoutput'))
				DROP TABLE #xp_cmdshell_DupSPNoutput;
				IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#xp_cmdshell_DupSPNoutput'))
				CREATE TABLE #xp_cmdshell_DupSPNoutput (line int IDENTITY(1,1) PRIMARY KEY, [Output] VARCHAR (8000));
				
				IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#FinalDupSPN'))
				DROP TABLE #FinalDupSPN;
				IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#FinalDupSPN'))
				CREATE TABLE #FinalDupSPN ([SPN] VARCHAR (8000), [Accounts] VARCHAR (8000));
				
				IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#ScopedDupSPN'))
				DROP TABLE #ScopedDupSPN;
				IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#ScopedDupSPN'))
				CREATE TABLE #ScopedDupSPN ([SPN] VARCHAR (8000), [Accounts] VARCHAR (8000));

				SELECT @CMD = N'SETSPN -P -L ' + @accntsqlservice 
				INSERT INTO #xp_cmdshell_AcctSPNoutput ([Output])
				EXEC master.dbo.xp_cmdshell @CMD;

				SET @CMD = N'SETSPN -P -X'
				INSERT INTO #xp_cmdshell_DupSPNoutput ([Output])
				EXEC master.dbo.xp_cmdshell @CMD;

				SELECT @SPNMachine = '%MSSQLSvc/' + CONVERT(NVARCHAR(100),SERVERPROPERTY('MachineName')) + '%';

				IF EXISTS (SELECT TOP 1 b.line FROM #xp_cmdshell_AcctSPNoutput a INNER JOIN #xp_cmdshell_DupSPNoutput b ON REPLACE(UPPER(a.[Output]),CHAR(9), '') = LEFT(REPLACE(UPPER(b.[Output]),CHAR(9), ''), LEN(REPLACE(UPPER(a.[Output]),' ', ''))))
				BEGIN
					DECLARE curSPN CURSOR FAST_FORWARD FOR SELECT b.line, REPLACE(a.[Output], CHAR(9), '') FROM #xp_cmdshell_AcctSPNoutput a INNER JOIN #xp_cmdshell_DupSPNoutput b ON REPLACE(UPPER(a.[Output]),CHAR(9), '') = LEFT(REPLACE(UPPER(b.[Output]),CHAR(9), ''), LEN(REPLACE(UPPER(a.[Output]),' ', ''))) WHERE a.[Output] LIKE '%MSSQLSvc%'
					OPEN curSPN
					FETCH NEXT FROM curSPN INTO @line, @SPN

					WHILE @@FETCH_STATUS = 0
					BEGIN
						SELECT TOP 1 @linemax = line FROM #xp_cmdshell_DupSPNoutput WHERE line > @line AND [Output] IS NULL;
						INSERT INTO #FinalDupSPN
						SELECT QUOTENAME(@SPN), QUOTENAME(REPLACE([Output], CHAR(9), '')) FROM #xp_cmdshell_DupSPNoutput WHERE line > @line AND line < @linemax;
					
						IF EXISTS (SELECT [Output] FROM #xp_cmdshell_DupSPNoutput WHERE line = @line AND [Output] LIKE @SPNMachine)
						BEGIN
							INSERT INTO #ScopedDupSPN
							SELECT QUOTENAME(@SPN), QUOTENAME(REPLACE([Output], CHAR(9), '')) FROM #xp_cmdshell_DupSPNoutput WHERE line > @line AND line < @linemax;
						END
						FETCH NEXT FROM curSPN INTO @line, @SPN
					END

					CLOSE curSPN
					DEALLOCATE curSPN
				END

				IF EXISTS (SELECT TOP 1 [Output] FROM #xp_cmdshell_AcctSPNoutput WHERE [Output] LIKE '%MSSQLSvc%')
				BEGIN				
					IF EXISTS (SELECT [Output] FROM #xp_cmdshell_AcctSPNoutput WHERE [Output] LIKE '%MSSQLSvc%' AND [Output] LIKE @SPNMachine)
					BEGIN
						SELECT 'Service_Account_checks' AS [Category], 'MSSQLSvc_SPNs_SvcAcct_CurrServer' AS [Check], '[OK]' AS [Deviation], QUOTENAME(REPLACE([Output], CHAR(9), '')) AS SPN FROM #xp_cmdshell_AcctSPNoutput WHERE [Output] LIKE @SPNMachine
					END
					ELSE
					BEGIN
						SELECT 'Service_Account_checks' AS [Category], 'MSSQLSvc_SPNs_SvcAcct_CurrServer' AS [Check], '[WARNING: There is no registered MSSQLSvc SPN for the current service account in the scoped server name, preventing the use of Kerberos authentication]' AS [Deviation];
					END

					IF EXISTS (SELECT [Output] FROM #xp_cmdshell_AcctSPNoutput WHERE [Output] LIKE '%MSSQLSvc%' AND [Output] NOT LIKE @SPNMachine)
					BEGIN
						SELECT 'Service_Account_checks' AS [Category], 'MSSQLSvc_SPNs_SvcAcct' AS [Check], '[INFORMATION: There are other MSSQLSvc SPNs registered for the current service account]' AS [Deviation], QUOTENAME(REPLACE([Output], CHAR(9), '')) AS SPN FROM #xp_cmdshell_AcctSPNoutput WHERE [Output] LIKE '%MSSQLSvc%' AND [Output] NOT LIKE @SPNMachine
					END
				END
				ELSE
				BEGIN
					SELECT 'Service_Account_checks' AS [Category], 'MSSQLSvc_SPNs_SvcAcct' AS [Check], '[WARNING: There is no registered MSSQLSvc SPN for the current service account, preventing the use of Kerberos authentication]' AS [Deviation];
				END

				IF (SELECT COUNT(*) FROM #ScopedDupSPN) > 0
				BEGIN
					SELECT 'Service_Account_checks' AS [Category], 'Dup_MSSQLSvc_SPNs_Acct_CurrServer' AS [Check], '[WARNING: There are duplicate registered MSSQLSvc SPNs in the domain, for the SPN in the scoped server name]' AS [Deviation], REPLACE([SPN], CHAR(9), ''), [Accounts] AS [Information] FROM #ScopedDupSPN
				END
				ELSE
				BEGIN
					SELECT 'Service_Account_checks' AS [Category], 'Dup_MSSQLSvc_SPNs_Acct_CurrServer' AS [Check], '[OK]' AS [Deviation];
				END

				IF (SELECT COUNT(*) FROM #FinalDupSPN) > 0
				BEGIN
					SELECT 'Service_Account_checks' AS [Category], 'Dup_MSSQLSvc_SPNs_Acct' AS [Check], '[WARNING: There are duplicate registered MSSQLSvc SPNs in the domain]' AS [Deviation], [SPN], [Accounts] FROM #FinalDupSPN
				END
				ELSE
				BEGIN
					SELECT 'Service_Account_checks' AS [Category], 'Dup_MSSQLSvc_SPNs_Acct' AS [Check], '[OK]' AS [Deviation];
				END
			END TRY
			BEGIN CATCH
				SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
				SELECT @ErrorMessage = 'Service Accounts and SPN registration subsection - Error raised in TRY block 9. ' + ERROR_MESSAGE()
				RAISERROR (@ErrorMessage, 16, 1);
			END CATCH
			
			IF @xcmd = 0
			BEGIN
				EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE WITH OVERRIDE;
			END
			IF @sao = 0
			BEGIN
				EXEC sp_configure 'show advanced options', 0; RECONFIGURE WITH OVERRIDE;
			END
		END
		ELSE
		BEGIN
			RAISERROR('[WARNING: Only a sysadmin can run the "Service Accounts and SPN registration" check. A regular user can also run this check if a xp_cmdshell proxy account exists. Bypassing check]', 16, 1, N'xp_cmdshellproxy')
			RAISERROR('[WARNING: If not sysadmin, then must be a granted EXECUTE permissions on the following extended sprocs to run checks: xp_cmdshell. Bypassing check]', 16, 1, N'extended_sprocs')
			--RETURN
		END
	END
	ELSE
	BEGIN
		RAISERROR('    |- [INFORMATION: "Service Accounts and SPN registration" check was skipped: either spn checks were not allowed, xp_cmdshell was not allowed or the service account is not a domain account.]', 10, 1, N'disallow_xp_cmdshell')
		--RETURN
	END;

	RAISERROR (N'|-Starting Instance Checks', 10, 1) WITH NOWAIT
	--------------------------------------------------------------------------------------------------------------------------------
	-- Recommended build check subsection
	--------------------------------------------------------------------------------------------------------------------------------
	RAISERROR (N'  |-Starting Recommended build check', 10, 1) WITH NOWAIT
	SELECT 'Instance_checks' AS [Category], 'Recommended_Build' AS [Check],
		CASE WHEN (@sqlmajorver = 9 AND @sqlbuild < 5000)
				OR (@sqlmajorver = 10 AND @sqlminorver = 0 AND @sqlbuild < 6000)
				OR (@sqlmajorver = 10 AND @sqlminorver = 50 AND @sqlbuild < 6000)
				OR (@sqlmajorver = 11 AND @sqlbuild < 7001)
				OR (@sqlmajorver = 12 AND @sqlbuild < 5000)
				OR (@sqlmajorver = 13 AND @sqlbuild < 4000)
			THEN '[WARNING: current service pack has been superseded in the current SQL Server version. Install the latest service pack as soon as possible.]'
			ELSE '[OK]'
		END AS [Deviation], 
		CASE WHEN @sqlmajorver = 9 THEN '2005'
			WHEN @sqlmajorver = 10 AND @sqlminorver = 0 THEN '2008'
			WHEN @sqlmajorver = 10 AND @sqlminorver = 50 THEN '2008R2'
			WHEN @sqlmajorver = 11 THEN '2012'
			WHEN @sqlmajorver = 12 THEN '2014'
			WHEN @sqlmajorver = 13 THEN '2016'
			WHEN @sqlmajorver = 14 THEN '2017'
		END AS [Product_Major_Version],
		CONVERT(VARCHAR(128), SERVERPROPERTY('ProductLevel')) AS Product_Level,
		CASE WHEN @sqlmajorver >= 13 OR (@sqlmajorver = 12 AND @sqlbuild >= 2556 AND @sqlbuild < 4100) OR (@sqlmajorver = 12 AND @sqlbuild >= 4427) THEN CONVERT(VARCHAR(128), SERVERPROPERTY('ProductBuildType')) ELSE 'NA' END AS Product_Build_Type,
		CASE WHEN @sqlmajorver >= 13 OR (@sqlmajorver = 12 AND @sqlbuild >= 2556 AND @sqlbuild < 4100) OR (@sqlmajorver = 12 AND @sqlbuild >= 4427) THEN CONVERT(VARCHAR(128), SERVERPROPERTY('ProductUpdateLevel')) ELSE 'NA' END AS Product_Update_Level,
		CASE WHEN @sqlmajorver >= 13 OR (@sqlmajorver = 12 AND @sqlbuild >= 2556 AND @sqlbuild < 4100) OR (@sqlmajorver = 12 AND @sqlbuild >= 4427) THEN CONVERT(VARCHAR(128), SERVERPROPERTY('ProductUpdateReference')) ELSE 'NA' END AS Product_Update_Ref_KB;

	--------------------------------------------------------------------------------------------------------------------------------
	-- Objects naming conventions subsection
	-- Refer to BOL for more information 
	-- (http://msdn.microsoft.com/en-us/library/dd172115(v=vs.100).aspx)
	-- (http://msdn.microsoft.com/en-us/library/dd172134.aspx)
	-- (http://msdn.microsoft.com/en-us/library/ms189822.aspx)
	--------------------------------------------------------------------------------------------------------------------------------
	RAISERROR (N'|-Starting Objects naming conventions Checks', 10, 1) WITH NOWAIT

	IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tmpobjectnames'))
	DROP TABLE #tmpobjectnames;
	IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tmpobjectnames'))
	CREATE TABLE #tmpobjectnames ([DBName] sysname, [schemaName] NVARCHAR(100), [Object] NVARCHAR(255), [Col] NVARCHAR(255), [type] CHAR(2), type_desc NVARCHAR(60));

	IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tmpfinalobjectnames'))
	DROP TABLE #tmpfinalobjectnames;
	IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tmpfinalobjectnames'))
	CREATE TABLE #tmpfinalobjectnames ([Deviation] tinyint, [DBName] sysname, [schemaName] NVARCHAR(100), [Object] NVARCHAR(255), [Col] NVARCHAR(255), type_desc NVARCHAR(60), [Comment] NVARCHAR(500) NULL);

	UPDATE #tmpdbs1
	SET isdone = 0

	WHILE (SELECT COUNT(id) FROM #tmpdbs1 WHERE isdone = 0) > 0
	BEGIN
		SELECT TOP 1 @dbname = [dbname], @dbid = [dbid] FROM #tmpdbs1 WHERE isdone = 0
		SET @sqlcmd = 'USE ' + QUOTENAME(@dbname) + ';
	SELECT ''' + REPLACE(@dbname, CHAR(39), CHAR(95)) + ''' AS [DBName], s.name, so.name, NULL, type, type_desc
	FROM sys.objects so 
	INNER JOIN sys.schemas s ON so.schema_id = s.schema_id
	WHERE so.is_ms_shipped = 0
	UNION ALL
	SELECT ''' + REPLACE(@dbname, CHAR(39), CHAR(95)) + ''' AS [DBName], s.name, so.name, sc.name, ''TC'' AS [type], ''TABLE_COLUMN'' AS [type_desc]
	FROM sys.columns sc 
	INNER JOIN sys.objects so ON sc.object_id = so.object_id
	INNER JOIN sys.schemas s ON so.schema_id = s.schema_id
	WHERE so.is_ms_shipped = 0'
		BEGIN TRY
			INSERT INTO #tmpobjectnames
			EXECUTE sp_executesql @sqlcmd
		END TRY
		BEGIN CATCH
			SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
			SELECT @ErrorMessage = 'Object naming conventions subsection - Error raised in TRY block in database ' + @dbname +'. ' + ERROR_MESSAGE()
			RAISERROR (@ErrorMessage, 16, 1);
		END CATCH
			
		UPDATE #tmpdbs1
		SET isdone = 1
		WHERE [dbid] = @dbid
	END;

	UPDATE #tmpdbs1
	SET isdone = 0

	CREATE INDEX IX1 ON #tmpobjectnames([type],[Object]);

	/* http://msdn.microsoft.com/en-us/library/dd172115(v=vs.100).aspx */
	INSERT INTO #tmpfinalobjectnames
	SELECT 1, [DBName], [schemaName], [Object], [Col], type_desc, NULL
	FROM #tmpobjectnames
	WHERE [type] = 'P' AND [Object] LIKE 'sp[_]%'
		AND [Object] NOT IN ('sp_alterdiagram','sp_creatediagram','sp_dropdiagram','sp_helpdiagramdefinition','sp_helpdiagrams','sp_renamediagram','sp_upgraddiagrams');

	/* http://msdn.microsoft.com/en-us/library/dd172134.aspx */
	INSERT INTO #tmpfinalobjectnames
	SELECT 2, [DBName], [schemaName], [Object], [Col], type_desc, CASE WHEN [Object] LIKE '% %' THEN 'Space - ' + QUOTENAME([Object]) ELSE NULL END COLLATE database_default AS [Comment]
	FROM #tmpobjectnames
	WHERE [type] <> 'S' AND [type] <> 'TC'
		AND ([Object] LIKE '% %' --space
		OR [Object] LIKE '%[[]%'
		OR [Object] LIKE '%]%'
		OR [Object] LIKE '%-%'
		OR [Object] LIKE '%.%'
		OR [Object] LIKE '%,%'
		OR [Object] LIKE '%;%'
		OR [Object] LIKE '%' + CHAR(34) + '%' --double quote
		OR [Object] LIKE '%' + CHAR(39) + '%'); --single quote

	INSERT INTO #tmpfinalobjectnames
	SELECT 3, [DBName], [schemaName], [Object], [Col], type_desc, CASE WHEN [Col] LIKE '% %' THEN 'Space - ' + QUOTENAME([Col]) ELSE NULL END COLLATE database_default AS [Comment]
	FROM #tmpobjectnames
	WHERE [type] = 'TC'
		AND ([Col] LIKE '% %' --space
		OR [Col] LIKE '%[[]%'
		OR [Col] LIKE '%]%'
		OR [Col] LIKE '%-%'
		OR [Col] LIKE '%.%'
		OR [Col] LIKE '%,%'
		OR [Col] LIKE '%;%'
		OR [Col] LIKE '%' + CHAR(34) + '%' --double quote
		OR [Col] LIKE '%' + CHAR(39) + '%'); --single quote

	/* http://msdn.microsoft.com/en-us/library/ms189822.aspx */
	INSERT INTO #tmpfinalobjectnames
	SELECT 4, [DBName], [schemaName], [Object], [Col], type_desc, NULL
	FROM #tmpobjectnames
	WHERE [type] <> 'S'
	AND ([Object] LIKE '% ABSOLUTE %' OR [Object] LIKE '% ABSOLUTE' OR [Object] = 'ABSOLUTE'
		OR [Object] LIKE '% ACTION %' OR [Object] LIKE '% ACTION' OR [Object] = 'ACTION'
		OR [Object] LIKE '% ADA %' OR [Object] LIKE '% ADA' OR [Object] = 'ADA'
		OR [Object] LIKE '% ADD %' OR [Object] LIKE '% ADD' OR [Object] = 'ADD'
		OR [Object] LIKE '% ADMIN %' OR [Object] LIKE '% ADMIN' OR [Object] = 'ADMIN'
		OR [Object] LIKE '% AFTER %' OR [Object] LIKE '% AFTER' OR [Object] = 'AFTER'
		OR [Object] LIKE '% AGGREGATE %' OR [Object] LIKE '% AGGREGATE' OR [Object] = 'AGGREGATE'
		OR [Object] LIKE '% ALIAS %' OR [Object] LIKE '% ALIAS' OR [Object] = 'ALIAS'
		OR [Object] LIKE '% ALL %' OR [Object] LIKE '% ALL' OR [Object] = 'ALL'
		OR [Object] LIKE '% ALLOCATE %' OR [Object] LIKE '% ALLOCATE' OR [Object] = 'ALLOCATE'
		OR [Object] LIKE '% ALTER %' OR [Object] LIKE '% ALTER' OR [Object] = 'ALTER'
		OR [Object] LIKE '% AND %' OR [Object] LIKE '% AND' OR [Object] = 'AND'
		OR [Object] LIKE '% ANY %' OR [Object] LIKE '% ANY' OR [Object] = 'ANY'
		OR [Object] LIKE '% ARE %' OR [Object] LIKE '% ARE' OR [Object] = 'ARE'
		OR [Object] LIKE '% ARRAY %' OR [Object] LIKE '% ARRAY' OR [Object] = 'ARRAY'
		OR [Object] LIKE '% AS %' OR [Object] LIKE '% AS' OR [Object] = 'AS'
		OR [Object] LIKE '% ASC %' OR [Object] LIKE '% ASC' OR [Object] = 'ASC'
		OR [Object] LIKE '% ASSERTION %' OR [Object] LIKE '% ASSERTION' OR [Object] = 'ASSERTION'
		OR [Object] LIKE '% AT %' OR [Object] LIKE '% AT' OR [Object] = 'AT'
		OR [Object] LIKE '% AUTHORIZATION %' OR [Object] LIKE '% AUTHORIZATION' OR [Object] = 'AUTHORIZATION'
		OR [Object] LIKE '% AVG %' OR [Object] LIKE '% AVG' OR [Object] = 'AVG'
		OR [Object] LIKE '% BACKUP %' OR [Object] LIKE '% BACKUP' OR [Object] = 'BACKUP'
		OR [Object] LIKE '% BEFORE %' OR [Object] LIKE '% BEFORE' OR [Object] = 'BEFORE'
		OR [Object] LIKE '% BEGIN %' OR [Object] LIKE '% BEGIN' OR [Object] = 'BEGIN'
		OR [Object] LIKE '% BETWEEN %' OR [Object] LIKE '% BETWEEN' OR [Object] = 'BETWEEN'
		OR [Object] LIKE '% BINARY %' OR [Object] LIKE '% BINARY' OR [Object] = 'BINARY'
		OR [Object] LIKE '% BIT %' OR [Object] LIKE '% BIT' OR [Object] = 'BIT'
		OR [Object] LIKE '% BIT_LENGTH %' OR [Object] LIKE '% BIT_LENGTH' OR [Object] = 'BIT_LENGTH'
		OR [Object] LIKE '% BLOB %' OR [Object] LIKE '% BLOB' OR [Object] = 'BLOB'
		OR [Object] LIKE '% BOOLEAN %' OR [Object] LIKE '% BOOLEAN' OR [Object] = 'BOOLEAN'
		OR [Object] LIKE '% BOTH %' OR [Object] LIKE '% BOTH' OR [Object] = 'BOTH'
		OR [Object] LIKE '% BREADTH %' OR [Object] LIKE '% BREADTH' OR [Object] = 'BREADTH'
		OR [Object] LIKE '% BREAK %' OR [Object] LIKE '% BREAK' OR [Object] = 'BREAK'
		OR [Object] LIKE '% BROWSE %' OR [Object] LIKE '% BROWSE' OR [Object] = 'BROWSE'
		OR [Object] LIKE '% BULK %' OR [Object] LIKE '% BULK' OR [Object] = 'BULK'
		OR [Object] LIKE '% BY %' OR [Object] LIKE '% BY' OR [Object] = 'BY'
		OR [Object] LIKE '% CALL %' OR [Object] LIKE '% CALL' OR [Object] = 'CALL'
		OR [Object] LIKE '% CASCADE %' OR [Object] LIKE '% CASCADE' OR [Object] = 'CASCADE'
		OR [Object] LIKE '% CASCADED %' OR [Object] LIKE '% CASCADED' OR [Object] = 'CASCADED'
		OR [Object] LIKE '% CASE %' OR [Object] LIKE '% CASE' OR [Object] = 'CASE'
		OR [Object] LIKE '% CAST %' OR [Object] LIKE '% CAST' OR [Object] = 'CAST'
		OR [Object] LIKE '% CATALOG %' OR [Object] LIKE '% CATALOG' OR [Object] = 'CATALOG'
		OR [Object] LIKE '% CHAR %' OR [Object] LIKE '% CHAR' OR [Object] = 'CHAR'
		OR [Object] LIKE '% CHAR_LENGTH %' OR [Object] LIKE '% CHAR_LENGTH' OR [Object] = 'CHAR_LENGTH'
		OR [Object] LIKE '% CHARACTER %' OR [Object] LIKE '% CHARACTER' OR [Object] = 'CHARACTER'
		OR [Object] LIKE '% CHARACTER_LENGTH %' OR [Object] LIKE '% CHARACTER_LENGTH' OR [Object] = 'CHARACTER_LENGTH'
		OR [Object] LIKE '% CHECK %' OR [Object] LIKE '% CHECK' OR [Object] = 'CHECK'
		OR [Object] LIKE '% CHECKPOINT %' OR [Object] LIKE '% CHECKPOINT' OR [Object] = 'CHECKPOINT'
		OR [Object] LIKE '% CLASS %' OR [Object] LIKE '% CLASS' OR [Object] = 'CLASS'
		OR [Object] LIKE '% CLOB %' OR [Object] LIKE '% CLOB' OR [Object] = 'CLOB'
		OR [Object] LIKE '% CLOSE %' OR [Object] LIKE '% CLOSE' OR [Object] = 'CLOSE'
		OR [Object] LIKE '% CLUSTERED %' OR [Object] LIKE '% CLUSTERED' OR [Object] = 'CLUSTERED'
		OR [Object] LIKE '% COALESCE %' OR [Object] LIKE '% COALESCE' OR [Object] = 'COALESCE'
		OR [Object] LIKE '% COLLATE %' OR [Object] LIKE '% COLLATE' OR [Object] = 'COLLATE'
		OR [Object] LIKE '% COLLATION %' OR [Object] LIKE '% COLLATION' OR [Object] = 'COLLATION'
		OR [Object] LIKE '% COLUMN %' OR [Object] LIKE '% COLUMN' OR [Object] = 'COLUMN'
		OR [Object] LIKE '% COMMIT %' OR [Object] LIKE '% COMMIT' OR [Object] = 'COMMIT'
		OR [Object] LIKE '% COMPLETION %' OR [Object] LIKE '% COMPLETION' OR [Object] = 'COMPLETION'
		OR [Object] LIKE '% COMPUTE %' OR [Object] LIKE '% COMPUTE' OR [Object] = 'COMPUTE'
		OR [Object] LIKE '% CONNECT %' OR [Object] LIKE '% CONNECT' OR [Object] = 'CONNECT'
		OR [Object] LIKE '% CONNECTION %' OR [Object] LIKE '% CONNECTION' OR [Object] = 'CONNECTION'
		OR [Object] LIKE '% CONSTRAINT %' OR [Object] LIKE '% CONSTRAINT' OR [Object] = 'CONSTRAINT'
		OR [Object] LIKE '% CONSTRAINTS %' OR [Object] LIKE '% CONSTRAINTS' OR [Object] = 'CONSTRAINTS'
		OR [Object] LIKE '% CONSTRUCTOR %' OR [Object] LIKE '% CONSTRUCTOR' OR [Object] = 'CONSTRUCTOR'
		OR [Object] LIKE '% CONTAINS %' OR [Object] LIKE '% CONTAINS' OR [Object] = 'CONTAINS'
		OR [Object] LIKE '% CONTAINSTABLE %' OR [Object] LIKE '% CONTAINSTABLE' OR [Object] = 'CONTAINSTABLE'
		OR [Object] LIKE '% CONTINUE %' OR [Object] LIKE '% CONTINUE' OR [Object] = 'CONTINUE'
		OR [Object] LIKE '% CONVERT %' OR [Object] LIKE '% CONVERT' OR [Object] = 'CONVERT'
		OR [Object] LIKE '% CORRESPONDING %' OR [Object] LIKE '% CORRESPONDING' OR [Object] = 'CORRESPONDING'
		OR [Object] LIKE '% COUNT %' OR [Object] LIKE '% COUNT' OR [Object] = 'COUNT'
		OR [Object] LIKE '% CREATE %' OR [Object] LIKE '% CREATE' OR [Object] = 'CREATE'
		OR [Object] LIKE '% CROSS %' OR [Object] LIKE '% CROSS' OR [Object] = 'CROSS'
		OR [Object] LIKE '% CUBE %' OR [Object] LIKE '% CUBE' OR [Object] = 'CUBE'
		OR [Object] LIKE '% CURRENT %' OR [Object] LIKE '% CURRENT' OR [Object] = 'CURRENT'
		OR [Object] LIKE '% CURRENT_DATE %' OR [Object] LIKE '% CURRENT_DATE' OR [Object] = 'CURRENT_DATE'
		OR [Object] LIKE '% CURRENT_PATH %' OR [Object] LIKE '% CURRENT_PATH' OR [Object] = 'CURRENT_PATH'
		OR [Object] LIKE '% CURRENT_ROLE %' OR [Object] LIKE '% CURRENT_ROLE' OR [Object] = 'CURRENT_ROLE'
		OR [Object] LIKE '% CURRENT_TIME %' OR [Object] LIKE '% CURRENT_TIME' OR [Object] = 'CURRENT_TIME'
		OR [Object] LIKE '% CURRENT_TIMESTAMP %' OR [Object] LIKE '% CURRENT_TIMESTAMP' OR [Object] = 'CURRENT_TIMESTAMP'
		OR [Object] LIKE '% CURRENT_USER %' OR [Object] LIKE '% CURRENT_USER' OR [Object] = 'CURRENT_USER'
		OR [Object] LIKE '% CURSOR %' OR [Object] LIKE '% CURSOR' OR [Object] = 'CURSOR'
		OR [Object] LIKE '% CYCLE %' OR [Object] LIKE '% CYCLE' OR [Object] = 'CYCLE'
		OR [Object] LIKE '% DATA %' OR [Object] LIKE '% DATA' OR [Object] = 'DATA'
		OR [Object] LIKE '% DATABASE %' OR [Object] LIKE '% DATABASE' OR [Object] = 'DATABASE'
		OR [Object] LIKE '% DATE %' OR [Object] LIKE '% DATE' OR [Object] = 'DATE'
		OR [Object] LIKE '% DAY %' OR [Object] LIKE '% DAY' OR [Object] = 'DAY'
		OR [Object] LIKE '% DBCC %' OR [Object] LIKE '% DBCC' OR [Object] = 'DBCC'
		OR [Object] LIKE '% DEALLOCATE %' OR [Object] LIKE '% DEALLOCATE' OR [Object] = 'DEALLOCATE'
		OR [Object] LIKE '% DEC %' OR [Object] LIKE '% DEC' OR [Object] = 'DEC'
		OR [Object] LIKE '% DECIMAL %' OR [Object] LIKE '% DECIMAL' OR [Object] = 'DECIMAL'
		OR [Object] LIKE '% DECLARE %' OR [Object] LIKE '% DECLARE' OR [Object] = 'DECLARE'
		OR [Object] LIKE '% DEFAULT %' OR [Object] LIKE '% DEFAULT' OR [Object] = 'DEFAULT'
		OR [Object] LIKE '% DEFERRABLE %' OR [Object] LIKE '% DEFERRABLE' OR [Object] = 'DEFERRABLE'
		OR [Object] LIKE '% DEFERRED %' OR [Object] LIKE '% DEFERRED' OR [Object] = 'DEFERRED'
		OR [Object] LIKE '% DELETE %' OR [Object] LIKE '% DELETE' OR [Object] = 'DELETE'
		OR [Object] LIKE '% DENY %' OR [Object] LIKE '% DENY' OR [Object] = 'DENY'
		OR [Object] LIKE '% DEPTH %' OR [Object] LIKE '% DEPTH' OR [Object] = 'DEPTH'
		OR [Object] LIKE '% DEREF %' OR [Object] LIKE '% DEREF' OR [Object] = 'DEREF'
		OR [Object] LIKE '% DESC %' OR [Object] LIKE '% DESC' OR [Object] = 'DESC'
		OR [Object] LIKE '% DESCRIBE %' OR [Object] LIKE '% DESCRIBE' OR [Object] = 'DESCRIBE'
		OR [Object] LIKE '% DESCRIPTOR %' OR [Object] LIKE '% DESCRIPTOR' OR [Object] = 'DESCRIPTOR'
		OR [Object] LIKE '% DESTROY %' OR [Object] LIKE '% DESTROY' OR [Object] = 'DESTROY'
		OR [Object] LIKE '% DESTRUCTOR %' OR [Object] LIKE '% DESTRUCTOR' OR [Object] = 'DESTRUCTOR'
		OR [Object] LIKE '% DETERMINISTIC %' OR [Object] LIKE '% DETERMINISTIC' OR [Object] = 'DETERMINISTIC'
		OR [Object] LIKE '% DIAGNOSTICS %' OR [Object] LIKE '% DIAGNOSTICS' OR [Object] = 'DIAGNOSTICS'
		OR [Object] LIKE '% DICTIONARY %' OR [Object] LIKE '% DICTIONARY' OR [Object] = 'DICTIONARY'
		OR [Object] LIKE '% DISCONNECT %' OR [Object] LIKE '% DISCONNECT' OR [Object] = 'DISCONNECT'
		OR [Object] LIKE '% DISK %' OR [Object] LIKE '% DISK' OR [Object] = 'DISK'
		OR [Object] LIKE '% DISTINCT %' OR [Object] LIKE '% DISTINCT' OR [Object] = 'DISTINCT'
		OR [Object] LIKE '% DISTRIBUTED %' OR [Object] LIKE '% DISTRIBUTED' OR [Object] = 'DISTRIBUTED'
		OR [Object] LIKE '% DOMAIN %' OR [Object] LIKE '% DOMAIN' OR [Object] = 'DOMAIN'
		OR [Object] LIKE '% DOUBLE %' OR [Object] LIKE '% DOUBLE' OR [Object] = 'DOUBLE'
		OR [Object] LIKE '% DROP %' OR [Object] LIKE '% DROP' OR [Object] = 'DROP'
		OR [Object] LIKE '% DUMMY %' OR [Object] LIKE '% DUMMY' OR [Object] = 'DUMMY'
		OR [Object] LIKE '% DUMP %' OR [Object] LIKE '% DUMP' OR [Object] = 'DUMP'
		OR [Object] LIKE '% DYNAMIC %' OR [Object] LIKE '% DYNAMIC' OR [Object] = 'DYNAMIC'
		OR [Object] LIKE '% EACH %' OR [Object] LIKE '% EACH' OR [Object] = 'EACH'
		OR [Object] LIKE '% ELSE %' OR [Object] LIKE '% ELSE' OR [Object] = 'ELSE'
		OR [Object] LIKE '% END %' OR [Object] LIKE '% END' OR [Object] = 'END'
		OR [Object] LIKE '% END-EXEC %' OR [Object] LIKE '% END-EXEC' OR [Object] = 'END-EXEC'
		OR [Object] LIKE '% EQUALS %' OR [Object] LIKE '% EQUALS' OR [Object] = 'EQUALS'
		OR [Object] LIKE '% ERRLVL %' OR [Object] LIKE '% ERRLVL' OR [Object] = 'ERRLVL'
		OR [Object] LIKE '% ESCAPE %' OR [Object] LIKE '% ESCAPE' OR [Object] = 'ESCAPE'
		OR [Object] LIKE '% EVERY %' OR [Object] LIKE '% EVERY' OR [Object] = 'EVERY'
		OR [Object] LIKE '% EXCEPT %' OR [Object] LIKE '% EXCEPT' OR [Object] = 'EXCEPT'
		OR [Object] LIKE '% EXCEPTION %' OR [Object] LIKE '% EXCEPTION' OR [Object] = 'EXCEPTION'
		OR [Object] LIKE '% EXEC %' OR [Object] LIKE '% EXEC' OR [Object] = 'EXEC'
		OR [Object] LIKE '% EXECUTE %' OR [Object] LIKE '% EXECUTE' OR [Object] = 'EXECUTE'
		OR [Object] LIKE '% EXISTS %' OR [Object] LIKE '% EXISTS' OR [Object] = 'EXISTS'
		OR [Object] LIKE '% EXIT %' OR [Object] LIKE '% EXIT' OR [Object] = 'EXIT'
		OR [Object] LIKE '% EXTERNAL %' OR [Object] LIKE '% EXTERNAL' OR [Object] = 'EXTERNAL'
		OR [Object] LIKE '% EXTRACT %' OR [Object] LIKE '% EXTRACT' OR [Object] = 'EXTRACT'
		OR [Object] LIKE '% FALSE %' OR [Object] LIKE '% FALSE' OR [Object] = 'FALSE'
		OR [Object] LIKE '% FETCH %' OR [Object] LIKE '% FETCH' OR [Object] = 'FETCH'
		OR [Object] LIKE '% FILE %' OR [Object] LIKE '% FILE' OR [Object] = 'FILE'
		OR [Object] LIKE '% FILLFACTOR %' OR [Object] LIKE '% FILLFACTOR' OR [Object] = 'FILLFACTOR'
		OR [Object] LIKE '% FIRST %' OR [Object] LIKE '% FIRST' OR [Object] = 'FIRST'
		OR [Object] LIKE '% FLOAT %' OR [Object] LIKE '% FLOAT' OR [Object] = 'FLOAT'
		OR [Object] LIKE '% FOR %' OR [Object] LIKE '% FOR' OR [Object] = 'FOR'
		OR [Object] LIKE '% FOREIGN %' OR [Object] LIKE '% FOREIGN' OR [Object] = 'FOREIGN'
		OR [Object] LIKE '% FORTRAN %' OR [Object] LIKE '% FORTRAN' OR [Object] = 'FORTRAN'
		OR [Object] LIKE '% FOUND %' OR [Object] LIKE '% FOUND' OR [Object] = 'FOUND'
		OR [Object] LIKE '% FREE %' OR [Object] LIKE '% FREE' OR [Object] = 'FREE'
		OR [Object] LIKE '% FREETEXT %' OR [Object] LIKE '% FREETEXT' OR [Object] = 'FREETEXT'
		OR [Object] LIKE '% FREETEXTTABLE %' OR [Object] LIKE '% FREETEXTTABLE' OR [Object] = 'FREETEXTTABLE'
		OR [Object] LIKE '% FROM %' OR [Object] LIKE '% FROM' OR [Object] = 'FROM'
		OR [Object] LIKE '% FULL %' OR [Object] LIKE '% FULL' OR [Object] = 'FULL'
		OR [Object] LIKE '% FULLTEXTTABLE %' OR [Object] LIKE '% FULLTEXTTABLE' OR [Object] = 'FULLTEXTTABLE'
		OR [Object] LIKE '% FUNCTION %' OR [Object] LIKE '% FUNCTION' OR [Object] = 'FUNCTION'
		OR [Object] LIKE '% GENERAL %' OR [Object] LIKE '% GENERAL' OR [Object] = 'GENERAL'
		OR [Object] LIKE '% GET %' OR [Object] LIKE '% GET' OR [Object] = 'GET'
		OR [Object] LIKE '% GLOBAL %' OR [Object] LIKE '% GLOBAL' OR [Object] = 'GLOBAL'
		OR [Object] LIKE '% GO %' OR [Object] LIKE '% GO' OR [Object] = 'GO'
		OR [Object] LIKE '% GOTO %' OR [Object] LIKE '% GOTO' OR [Object] = 'GOTO'
		OR [Object] LIKE '% GRANT %' OR [Object] LIKE '% GRANT' OR [Object] = 'GRANT'
		OR [Object] LIKE '% GROUP %' OR [Object] LIKE '% GROUP' OR [Object] = 'GROUP'
		OR [Object] LIKE '% GROUPING %' OR [Object] LIKE '% GROUPING' OR [Object] = 'GROUPING'
		OR [Object] LIKE '% HAVING %' OR [Object] LIKE '% HAVING' OR [Object] = 'HAVING'
		OR [Object] LIKE '% HOLDLOCK %' OR [Object] LIKE '% HOLDLOCK' OR [Object] = 'HOLDLOCK'
		OR [Object] LIKE '% HOST %' OR [Object] LIKE '% HOST' OR [Object] = 'HOST'
		OR [Object] LIKE '% HOUR %' OR [Object] LIKE '% HOUR' OR [Object] = 'HOUR'
		OR [Object] LIKE '% IDENTITY %' OR [Object] LIKE '% IDENTITY' OR [Object] = 'IDENTITY'
		OR [Object] LIKE '% IDENTITY_INSERT %' OR [Object] LIKE '% IDENTITY_INSERT' OR [Object] = 'IDENTITY_INSERT'
		OR [Object] LIKE '% IDENTITYCOL %' OR [Object] LIKE '% IDENTITYCOL' OR [Object] = 'IDENTITYCOL'
		OR [Object] LIKE '% IF %' OR [Object] LIKE '% IF' OR [Object] = 'IF'
		OR [Object] LIKE '% IGNORE %' OR [Object] LIKE '% IGNORE' OR [Object] = 'IGNORE'
		OR [Object] LIKE '% IMMEDIATE %' OR [Object] LIKE '% IMMEDIATE' OR [Object] = 'IMMEDIATE'
		OR [Object] LIKE '% IN %' OR [Object] LIKE '% IN' OR [Object] = 'IN'
		OR [Object] LIKE '% INCLUDE %' OR [Object] LIKE '% INCLUDE' OR [Object] = 'INCLUDE'
		OR [Object] LIKE '% INDEX %' OR [Object] LIKE '% INDEX' OR [Object] = 'INDEX'
		OR [Object] LIKE '% INDICATOR %' OR [Object] LIKE '% INDICATOR' OR [Object] = 'INDICATOR'
		OR [Object] LIKE '% INITIALIZE %' OR [Object] LIKE '% INITIALIZE' OR [Object] = 'INITIALIZE'
		OR [Object] LIKE '% INITIALLY %' OR [Object] LIKE '% INITIALLY' OR [Object] = 'INITIALLY'
		OR [Object] LIKE '% INNER %' OR [Object] LIKE '% INNER' OR [Object] = 'INNER'
		OR [Object] LIKE '% INOUT %' OR [Object] LIKE '% INOUT' OR [Object] = 'INOUT'
		OR [Object] LIKE '% INPUT %' OR [Object] LIKE '% INPUT' OR [Object] = 'INPUT'
		OR [Object] LIKE '% INSENSITIVE %' OR [Object] LIKE '% INSENSITIVE' OR [Object] = 'INSENSITIVE'
		OR [Object] LIKE '% INSERT %' OR [Object] LIKE '% INSERT' OR [Object] = 'INSERT'
		OR [Object] LIKE '% INT %' OR [Object] LIKE '% INT' OR [Object] = 'INT'
		OR [Object] LIKE '% INTEGER %' OR [Object] LIKE '% INTEGER' OR [Object] = 'INTEGER'
		OR [Object] LIKE '% INTERSECT %' OR [Object] LIKE '% INTERSECT' OR [Object] = 'INTERSECT'
		OR [Object] LIKE '% INTERVAL %' OR [Object] LIKE '% INTERVAL' OR [Object] = 'INTERVAL'
		OR [Object] LIKE '% INTO %' OR [Object] LIKE '% INTO' OR [Object] = 'INTO'
		OR [Object] LIKE '% IS %' OR [Object] LIKE '% IS' OR [Object] = 'IS'
		OR [Object] LIKE '% ISOLATION %' OR [Object] LIKE '% ISOLATION' OR [Object] = 'ISOLATION'
		OR [Object] LIKE '% ITERATE %' OR [Object] LIKE '% ITERATE' OR [Object] = 'ITERATE'
		OR [Object] LIKE '% JOIN %' OR [Object] LIKE '% JOIN' OR [Object] = 'JOIN'
		OR [Object] LIKE '% KEY %' OR [Object] LIKE '% KEY' OR [Object] = 'KEY'
		OR [Object] LIKE '% KILL %' OR [Object] LIKE '% KILL' OR [Object] = 'KILL'
		OR [Object] LIKE '% LANGUAGE %' OR [Object] LIKE '% LANGUAGE' OR [Object] = 'LANGUAGE'
		OR [Object] LIKE '% LARGE %' OR [Object] LIKE '% LARGE' OR [Object] = 'LARGE'
		OR [Object] LIKE '% LAST %' OR [Object] LIKE '% LAST' OR [Object] = 'LAST'
		OR [Object] LIKE '% LATERAL %' OR [Object] LIKE '% LATERAL' OR [Object] = 'LATERAL'
		OR [Object] LIKE '% LEADING %' OR [Object] LIKE '% LEADING' OR [Object] = 'LEADING'
		OR [Object] LIKE '% LEFT %' OR [Object] LIKE '% LEFT' OR [Object] = 'LEFT'
		OR [Object] LIKE '% LESS %' OR [Object] LIKE '% LESS' OR [Object] = 'LESS'
		OR [Object] LIKE '% LEVEL %' OR [Object] LIKE '% LEVEL' OR [Object] = 'LEVEL'
		OR [Object] LIKE '% LIKE %' OR [Object] LIKE '% LIKE' OR [Object] = 'LIKE'
		OR [Object] LIKE '% LIMIT %' OR [Object] LIKE '% LIMIT' OR [Object] = 'LIMIT'
		OR [Object] LIKE '% LINENO %' OR [Object] LIKE '% LINENO' OR [Object] = 'LINENO'
		OR [Object] LIKE '% LOAD %' OR [Object] LIKE '% LOAD' OR [Object] = 'LOAD'
		OR [Object] LIKE '% LOCAL %' OR [Object] LIKE '% LOCAL' OR [Object] = 'LOCAL'
		OR [Object] LIKE '% LOCALTIME %' OR [Object] LIKE '% LOCALTIME' OR [Object] = 'LOCALTIME'
		OR [Object] LIKE '% LOCALTIMESTAMP %' OR [Object] LIKE '% LOCALTIMESTAMP' OR [Object] = 'LOCALTIMESTAMP'
		OR [Object] LIKE '% LOCATOR %' OR [Object] LIKE '% LOCATOR' OR [Object] = 'LOCATOR'
		OR [Object] LIKE '% LOWER %' OR [Object] LIKE '% LOWER' OR [Object] = 'LOWER'
		OR [Object] LIKE '% MAP %' OR [Object] LIKE '% MAP' OR [Object] = 'MAP'
		OR [Object] LIKE '% MATCH %' OR [Object] LIKE '% MATCH' OR [Object] = 'MATCH'
		OR [Object] LIKE '% MAX %' OR [Object] LIKE '% MAX' OR [Object] = 'MAX'
		OR [Object] LIKE '% MIN %' OR [Object] LIKE '% MIN' OR [Object] = 'MIN'
		OR [Object] LIKE '% MINUTE %' OR [Object] LIKE '% MINUTE' OR [Object] = 'MINUTE'
		OR [Object] LIKE '% MODIFIES %' OR [Object] LIKE '% MODIFIES' OR [Object] = 'MODIFIES'
		OR [Object] LIKE '% MODIFY %' OR [Object] LIKE '% MODIFY' OR [Object] = 'MODIFY'
		OR [Object] LIKE '% MODULE %' OR [Object] LIKE '% MODULE' OR [Object] = 'MODULE'
		OR [Object] LIKE '% MONTH %' OR [Object] LIKE '% MONTH' OR [Object] = 'MONTH'
		OR [Object] LIKE '% NAMES %' OR [Object] LIKE '% NAMES' OR [Object] = 'NAMES'
		OR [Object] LIKE '% NATIONAL %' OR [Object] LIKE '% NATIONAL' OR [Object] = 'NATIONAL'
		OR [Object] LIKE '% NATURAL %' OR [Object] LIKE '% NATURAL' OR [Object] = 'NATURAL'
		OR [Object] LIKE '% NCHAR %' OR [Object] LIKE '% NCHAR' OR [Object] = 'NCHAR'
		OR [Object] LIKE '% NCLOB %' OR [Object] LIKE '% NCLOB' OR [Object] = 'NCLOB'
		OR [Object] LIKE '% NEW %' OR [Object] LIKE '% NEW' OR [Object] = 'NEW'
		OR [Object] LIKE '% NEXT %' OR [Object] LIKE '% NEXT' OR [Object] = 'NEXT'
		OR [Object] LIKE '% NO %' OR [Object] LIKE '% NO' OR [Object] = 'NO'
		OR [Object] LIKE '% NOCHECK %' OR [Object] LIKE '% NOCHECK' OR [Object] = 'NOCHECK'
		OR [Object] LIKE '% NONCLUSTERED %' OR [Object] LIKE '% NONCLUSTERED' OR [Object] = 'NONCLUSTERED'
		OR [Object] LIKE '% NONE %' OR [Object] LIKE '% NONE' OR [Object] = 'NONE'
		OR [Object] LIKE '% NOT %' OR [Object] LIKE '% NOT' OR [Object] = 'NOT'
		OR [Object] LIKE '% NULL %' OR [Object] LIKE '% NULL' OR [Object] = 'NULL'
		OR [Object] LIKE '% NULLIF %' OR [Object] LIKE '% NULLIF' OR [Object] = 'NULLIF'
		OR [Object] LIKE '% NUMERIC %' OR [Object] LIKE '% NUMERIC' OR [Object] = 'NUMERIC'
		OR [Object] LIKE '% OBJECT %' OR [Object] LIKE '% OBJECT' OR [Object] = 'OBJECT'
		OR [Object] LIKE '% OCTET_LENGTH %' OR [Object] LIKE '% OCTET_LENGTH' OR [Object] = 'OCTET_LENGTH'
		OR [Object] LIKE '% OF %' OR [Object] LIKE '% OF' OR [Object] = 'OF'
		OR [Object] LIKE '% OFF %' OR [Object] LIKE '% OFF' OR [Object] = 'OFF'
		OR [Object] LIKE '% OFFSETS %' OR [Object] LIKE '% OFFSETS' OR [Object] = 'OFFSETS'
		OR [Object] LIKE '% OLD %' OR [Object] LIKE '% OLD' OR [Object] = 'OLD'
		OR [Object] LIKE '% ON %' OR [Object] LIKE '% ON' OR [Object] = 'ON'
		OR [Object] LIKE '% ONLY %' OR [Object] LIKE '% ONLY' OR [Object] = 'ONLY'
		OR [Object] LIKE '% OPEN %' OR [Object] LIKE '% OPEN' OR [Object] = 'OPEN'
		OR [Object] LIKE '% OPENDATASOURCE %' OR [Object] LIKE '% OPENDATASOURCE' OR [Object] = 'OPENDATASOURCE'
		OR [Object] LIKE '% OPENQUERY %' OR [Object] LIKE '% OPENQUERY' OR [Object] = 'OPENQUERY'
		OR [Object] LIKE '% OPENROWSET %' OR [Object] LIKE '% OPENROWSET' OR [Object] = 'OPENROWSET'
		OR [Object] LIKE '% OPENXML %' OR [Object] LIKE '% OPENXML' OR [Object] = 'OPENXML'
		OR [Object] LIKE '% OPERATION %' OR [Object] LIKE '% OPERATION' OR [Object] = 'OPERATION'
		OR [Object] LIKE '% OPTION %' OR [Object] LIKE '% OPTION' OR [Object] = 'OPTION'
		OR [Object] LIKE '% OR %' OR [Object] LIKE '% OR' OR [Object] = 'OR'
		OR [Object] LIKE '% ORDER %' OR [Object] LIKE '% ORDER' OR [Object] = 'ORDER'
		OR [Object] LIKE '% ORDINALITY %' OR [Object] LIKE '% ORDINALITY' OR [Object] = 'ORDINALITY'
		OR [Object] LIKE '% OUT %' OR [Object] LIKE '% OUT' OR [Object] = 'OUT'
		OR [Object] LIKE '% OUTER %' OR [Object] LIKE '% OUTER' OR [Object] = 'OUTER'
		OR [Object] LIKE '% OUTPUT %' OR [Object] LIKE '% OUTPUT' OR [Object] = 'OUTPUT'
		OR [Object] LIKE '% OVER %' OR [Object] LIKE '% OVER' OR [Object] = 'OVER'
		OR [Object] LIKE '% OVERLAPS %' OR [Object] LIKE '% OVERLAPS' OR [Object] = 'OVERLAPS'
		OR [Object] LIKE '% PAD %' OR [Object] LIKE '% PAD' OR [Object] = 'PAD'
		OR [Object] LIKE '% PARAMETER %' OR [Object] LIKE '% PARAMETER' OR [Object] = 'PARAMETER'
		OR [Object] LIKE '% PARAMETERS %' OR [Object] LIKE '% PARAMETERS' OR [Object] = 'PARAMETERS'
		OR [Object] LIKE '% PARTIAL %' OR [Object] LIKE '% PARTIAL' OR [Object] = 'PARTIAL'
		OR [Object] LIKE '% PASCAL %' OR [Object] LIKE '% PASCAL' OR [Object] = 'PASCAL'
		OR [Object] LIKE '% PATH %' OR [Object] LIKE '% PATH' OR [Object] = 'PATH'
		OR [Object] LIKE '% PERCENT %' OR [Object] LIKE '% PERCENT' OR [Object] = 'PERCENT'
		OR [Object] LIKE '% PLAN %' OR [Object] LIKE '% PLAN' OR [Object] = 'PLAN'
		OR [Object] LIKE '% POSITION %' OR [Object] LIKE '% POSITION' OR [Object] = 'POSITION'
		OR [Object] LIKE '% POSTFIX %' OR [Object] LIKE '% POSTFIX' OR [Object] = 'POSTFIX'
		OR [Object] LIKE '% PRECISION %' OR [Object] LIKE '% PRECISION' OR [Object] = 'PRECISION'
		OR [Object] LIKE '% PREFIX %' OR [Object] LIKE '% PREFIX' OR [Object] = 'PREFIX'
		OR [Object] LIKE '% PREORDER %' OR [Object] LIKE '% PREORDER' OR [Object] = 'PREORDER'
		OR [Object] LIKE '% PREPARE %' OR [Object] LIKE '% PREPARE' OR [Object] = 'PREPARE'
		OR [Object] LIKE '% PRESERVE %' OR [Object] LIKE '% PRESERVE' OR [Object] = 'PRESERVE'
		OR [Object] LIKE '% PRIMARY %' OR [Object] LIKE '% PRIMARY' OR [Object] = 'PRIMARY'
		OR [Object] LIKE '% PRINT %' OR [Object] LIKE '% PRINT' OR [Object] = 'PRINT'
		OR [Object] LIKE '% PRIOR %' OR [Object] LIKE '% PRIOR' OR [Object] = 'PRIOR'
		OR [Object] LIKE '% PRIVILEGES %' OR [Object] LIKE '% PRIVILEGES' OR [Object] = 'PRIVILEGES'
		OR [Object] LIKE '% PROC %' OR [Object] LIKE '% PROC' OR [Object] = 'PROC'
		OR [Object] LIKE '% PROCEDURE %' OR [Object] LIKE '% PROCEDURE' OR [Object] = 'PROCEDURE'
		OR [Object] LIKE '% PUBLIC %' OR [Object] LIKE '% PUBLIC' OR [Object] = 'PUBLIC'
		OR [Object] LIKE '% RAISERROR %' OR [Object] LIKE '% RAISERROR' OR [Object] = 'RAISERROR'
		OR [Object] LIKE '% READ %' OR [Object] LIKE '% READ' OR [Object] = 'READ'
		OR [Object] LIKE '% READS %' OR [Object] LIKE '% READS' OR [Object] = 'READS'
		OR [Object] LIKE '% READTEXT %' OR [Object] LIKE '% READTEXT' OR [Object] = 'READTEXT'
		OR [Object] LIKE '% REAL %' OR [Object] LIKE '% REAL' OR [Object] = 'REAL'
		OR [Object] LIKE '% RECONFIGURE %' OR [Object] LIKE '% RECONFIGURE' OR [Object] = 'RECONFIGURE'
		OR [Object] LIKE '% RECURSIVE %' OR [Object] LIKE '% RECURSIVE' OR [Object] = 'RECURSIVE'
		OR [Object] LIKE '% REF %' OR [Object] LIKE '% REF' OR [Object] = 'REF'
		OR [Object] LIKE '% REFERENCES %' OR [Object] LIKE '% REFERENCES' OR [Object] = 'REFERENCES'
		OR [Object] LIKE '% REFERENCING %' OR [Object] LIKE '% REFERENCING' OR [Object] = 'REFERENCING'
		OR [Object] LIKE '% RELATIVE %' OR [Object] LIKE '% RELATIVE' OR [Object] = 'RELATIVE'
		OR [Object] LIKE '% REPLICATION %' OR [Object] LIKE '% REPLICATION' OR [Object] = 'REPLICATION'
		OR [Object] LIKE '% RESTORE %' OR [Object] LIKE '% RESTORE' OR [Object] = 'RESTORE'
		OR [Object] LIKE '% RESTRICT %' OR [Object] LIKE '% RESTRICT' OR [Object] = 'RESTRICT'
		OR [Object] LIKE '% RESULT %' OR [Object] LIKE '% RESULT' OR [Object] = 'RESULT'
		OR [Object] LIKE '% RETURN %' OR [Object] LIKE '% RETURN' OR [Object] = 'RETURN'
		OR [Object] LIKE '% RETURNS %' OR [Object] LIKE '% RETURNS' OR [Object] = 'RETURNS'
		OR [Object] LIKE '% REVOKE %' OR [Object] LIKE '% REVOKE' OR [Object] = 'REVOKE'
		OR [Object] LIKE '% RIGHT %' OR [Object] LIKE '% RIGHT' OR [Object] = 'RIGHT'
		OR [Object] LIKE '% ROLE %' OR [Object] LIKE '% ROLE' OR [Object] = 'ROLE'
		OR [Object] LIKE '% ROLLBACK %' OR [Object] LIKE '% ROLLBACK' OR [Object] = 'ROLLBACK'
		OR [Object] LIKE '% ROLLUP %' OR [Object] LIKE '% ROLLUP' OR [Object] = 'ROLLUP'
		OR [Object] LIKE '% ROUTINE %' OR [Object] LIKE '% ROUTINE' OR [Object] = 'ROUTINE'
		OR [Object] LIKE '% ROW %' OR [Object] LIKE '% ROW' OR [Object] = 'ROW'
		OR [Object] LIKE '% ROWCOUNT %' OR [Object] LIKE '% ROWCOUNT' OR [Object] = 'ROWCOUNT'
		OR [Object] LIKE '% ROWGUIDCOL %' OR [Object] LIKE '% ROWGUIDCOL' OR [Object] = 'ROWGUIDCOL'
		OR [Object] LIKE '% ROWS %' OR [Object] LIKE '% ROWS' OR [Object] = 'ROWS'
		OR [Object] LIKE '% RULE %' OR [Object] LIKE '% RULE' OR [Object] = 'RULE'
		OR [Object] LIKE '% SAVE %' OR [Object] LIKE '% SAVE' OR [Object] = 'SAVE'
		OR [Object] LIKE '% SAVEPOINT %' OR [Object] LIKE '% SAVEPOINT' OR [Object] = 'SAVEPOINT'
		OR [Object] LIKE '% SCHEMA %' OR [Object] LIKE '% SCHEMA' OR [Object] = 'SCHEMA'
		OR [Object] LIKE '% SCOPE %' OR [Object] LIKE '% SCOPE' OR [Object] = 'SCOPE'
		OR [Object] LIKE '% SCROLL %' OR [Object] LIKE '% SCROLL' OR [Object] = 'SCROLL'
		OR [Object] LIKE '% SEARCH %' OR [Object] LIKE '% SEARCH' OR [Object] = 'SEARCH'
		OR [Object] LIKE '% SECOND %' OR [Object] LIKE '% SECOND' OR [Object] = 'SECOND'
		OR [Object] LIKE '% SECTION %' OR [Object] LIKE '% SECTION' OR [Object] = 'SECTION'
		OR [Object] LIKE '% SELECT %' OR [Object] LIKE '% SELECT' OR [Object] = 'SELECT'
		OR [Object] LIKE '% SEQUENCE %' OR [Object] LIKE '% SEQUENCE' OR [Object] = 'SEQUENCE'
		OR [Object] LIKE '% SESSION %' OR [Object] LIKE '% SESSION' OR [Object] = 'SESSION'
		OR [Object] LIKE '% SESSION_USER %' OR [Object] LIKE '% SESSION_USER' OR [Object] = 'SESSION_USER'
		OR [Object] LIKE '% SET %' OR [Object] LIKE '% SET' OR [Object] = 'SET'
		OR [Object] LIKE '% SETS %' OR [Object] LIKE '% SETS' OR [Object] = 'SETS'
		OR [Object] LIKE '% SETUSER %' OR [Object] LIKE '% SETUSER' OR [Object] = 'SETUSER'
		OR [Object] LIKE '% SHUTDOWN %' OR [Object] LIKE '% SHUTDOWN' OR [Object] = 'SHUTDOWN'
		OR [Object] LIKE '% SIZE %' OR [Object] LIKE '% SIZE' OR [Object] = 'SIZE'
		OR [Object] LIKE '% SMALLINT %' OR [Object] LIKE '% SMALLINT' OR [Object] = 'SMALLINT'
		OR [Object] LIKE '% SOME %' OR [Object] LIKE '% SOME' OR [Object] = 'SOME'
		OR [Object] LIKE '% SPACE %' OR [Object] LIKE '% SPACE' OR [Object] = 'SPACE'
		OR [Object] LIKE '% SPECIFIC %' OR [Object] LIKE '% SPECIFIC' OR [Object] = 'SPECIFIC'
		OR [Object] LIKE '% SPECIFICTYPE %' OR [Object] LIKE '% SPECIFICTYPE' OR [Object] = 'SPECIFICTYPE'
		OR [Object] LIKE '% SQL %' OR [Object] LIKE '% SQL' OR [Object] = 'SQL'
		OR [Object] LIKE '% SQLCA %' OR [Object] LIKE '% SQLCA' OR [Object] = 'SQLCA'
		OR [Object] LIKE '% SQLCODE %' OR [Object] LIKE '% SQLCODE' OR [Object] = 'SQLCODE'
		OR [Object] LIKE '% SQLERROR %' OR [Object] LIKE '% SQLERROR' OR [Object] = 'SQLERROR'
		OR [Object] LIKE '% SQLEXCEPTION %' OR [Object] LIKE '% SQLEXCEPTION' OR [Object] = 'SQLEXCEPTION'
		OR [Object] LIKE '% SQLSTATE %' OR [Object] LIKE '% SQLSTATE' OR [Object] = 'SQLSTATE'
		OR [Object] LIKE '% SQLWARNING %' OR [Object] LIKE '% SQLWARNING' OR [Object] = 'SQLWARNING'
		OR [Object] LIKE '% START %' OR [Object] LIKE '% START' OR [Object] = 'START'
		OR [Object] LIKE '% STATE %' OR [Object] LIKE '% STATE' OR [Object] = 'STATE'
		OR [Object] LIKE '% STATEMENT %' OR [Object] LIKE '% STATEMENT' OR [Object] = 'STATEMENT'
		OR [Object] LIKE '% STATIC %' OR [Object] LIKE '% STATIC' OR [Object] = 'STATIC'
		OR [Object] LIKE '% STATISTICS %' OR [Object] LIKE '% STATISTICS' OR [Object] = 'STATISTICS'
		OR [Object] LIKE '% STRUCTURE %' OR [Object] LIKE '% STRUCTURE' OR [Object] = 'STRUCTURE'
		OR [Object] LIKE '% SUBSTRING %' OR [Object] LIKE '% SUBSTRING' OR [Object] = 'SUBSTRING'
		OR [Object] LIKE '% SUM %' OR [Object] LIKE '% SUM' OR [Object] = 'SUM'
		OR [Object] LIKE '% SYSTEM_USER %' OR [Object] LIKE '% SYSTEM_USER' OR [Object] = 'SYSTEM_USER'
		OR [Object] LIKE '% TABLE %' OR [Object] LIKE '% TABLE' OR [Object] = 'TABLE'
		OR [Object] LIKE '% TEMPORARY %' OR [Object] LIKE '% TEMPORARY' OR [Object] = 'TEMPORARY'
		OR [Object] LIKE '% TERMINATE %' OR [Object] LIKE '% TERMINATE' OR [Object] = 'TERMINATE'
		OR [Object] LIKE '% TEXTSIZE %' OR [Object] LIKE '% TEXTSIZE' OR [Object] = 'TEXTSIZE'
		OR [Object] LIKE '% THAN %' OR [Object] LIKE '% THAN' OR [Object] = 'THAN'
		OR [Object] LIKE '% THEN %' OR [Object] LIKE '% THEN' OR [Object] = 'THEN'
		OR [Object] LIKE '% TIME %' OR [Object] LIKE '% TIME' OR [Object] = 'TIME'
		OR [Object] LIKE '% TIMESTAMP %' OR [Object] LIKE '% TIMESTAMP' OR [Object] = 'TIMESTAMP'
		OR [Object] LIKE '% TIMEZONE_HOUR %' OR [Object] LIKE '% TIMEZONE_HOUR' OR [Object] = 'TIMEZONE_HOUR'
		OR [Object] LIKE '% TIMEZONE_MINUTE %' OR [Object] LIKE '% TIMEZONE_MINUTE' OR [Object] = 'TIMEZONE_MINUTE'
		OR [Object] LIKE '% TO %' OR [Object] LIKE '% TO' OR [Object] = 'TO'
		OR [Object] LIKE '% TOP %' OR [Object] LIKE '% TOP' OR [Object] = 'TOP'
		OR [Object] LIKE '% TRAILING %' OR [Object] LIKE '% TRAILING' OR [Object] = 'TRAILING'
		OR [Object] LIKE '% TRAN %' OR [Object] LIKE '% TRAN' OR [Object] = 'TRAN'
		OR [Object] LIKE '% TRANSACTION %' OR [Object] LIKE '% TRANSACTION' OR [Object] = 'TRANSACTION'
		OR [Object] LIKE '% TRANSLATE %' OR [Object] LIKE '% TRANSLATE' OR [Object] = 'TRANSLATE'
		OR [Object] LIKE '% TRANSLATION %' OR [Object] LIKE '% TRANSLATION' OR [Object] = 'TRANSLATION'
		OR [Object] LIKE '% TREAT %' OR [Object] LIKE '% TREAT' OR [Object] = 'TREAT'
		OR [Object] LIKE '% TRIGGER %' OR [Object] LIKE '% TRIGGER' OR [Object] = 'TRIGGER'
		OR [Object] LIKE '% TRIM %' OR [Object] LIKE '% TRIM' OR [Object] = 'TRIM'
		OR [Object] LIKE '% TRUE %' OR [Object] LIKE '% TRUE' OR [Object] = 'TRUE'
		OR [Object] LIKE '% TRUNCATE %' OR [Object] LIKE '% TRUNCATE' OR [Object] = 'TRUNCATE'
		OR [Object] LIKE '% UNDER %' OR [Object] LIKE '% UNDER' OR [Object] = 'UNDER'
		OR [Object] LIKE '% UNION %' OR [Object] LIKE '% UNION' OR [Object] = 'UNION'
		OR [Object] LIKE '% UNIQUE %' OR [Object] LIKE '% UNIQUE' OR [Object] = 'UNIQUE'
		OR [Object] LIKE '% UNKNOWN %' OR [Object] LIKE '% UNKNOWN' OR [Object] = 'UNKNOWN'
		OR [Object] LIKE '% UNNEST %' OR [Object] LIKE '% UNNEST' OR [Object] = 'UNNEST'
		OR [Object] LIKE '% UPDATE %' OR [Object] LIKE '% UPDATE' OR [Object] = 'UPDATE'
		OR [Object] LIKE '% UPDATETEXT %' OR [Object] LIKE '% UPDATETEXT' OR [Object] = 'UPDATETEXT'
		OR [Object] LIKE '% UPPER %' OR [Object] LIKE '% UPPER' OR [Object] = 'UPPER'
		OR [Object] LIKE '% USAGE %' OR [Object] LIKE '% USAGE' OR [Object] = 'USAGE'
		OR [Object] LIKE '% USE %' OR [Object] LIKE '% USE' OR [Object] = 'USE'
		OR [Object] LIKE '% USER %' OR [Object] LIKE '% USER' OR [Object] = 'USER'
		OR [Object] LIKE '% USING %' OR [Object] LIKE '% USING' OR [Object] = 'USING'
		OR [Object] LIKE '% VALUE %' OR [Object] LIKE '% VALUE' OR [Object] = 'VALUE'
		OR [Object] LIKE '% VALUES %' OR [Object] LIKE '% VALUES' OR [Object] = 'VALUES'
		OR [Object] LIKE '% VARCHAR %' OR [Object] LIKE '% VARCHAR' OR [Object] = 'VARCHAR'
		OR [Object] LIKE '% VARIABLE %' OR [Object] LIKE '% VARIABLE' OR [Object] = 'VARIABLE'
		OR [Object] LIKE '% VARYING %' OR [Object] LIKE '% VARYING' OR [Object] = 'VARYING'
		OR [Object] LIKE '% VIEW %' OR [Object] LIKE '% VIEW' OR [Object] = 'VIEW'
		OR [Object] LIKE '% WAITFOR %' OR [Object] LIKE '% WAITFOR' OR [Object] = 'WAITFOR'
		OR [Object] LIKE '% WHEN %' OR [Object] LIKE '% WHEN' OR [Object] = 'WHEN'
		OR [Object] LIKE '% WHENEVER %' OR [Object] LIKE '% WHENEVER' OR [Object] = 'WHENEVER'
		OR [Object] LIKE '% WHERE %' OR [Object] LIKE '% WHERE' OR [Object] = 'WHERE'
		OR [Object] LIKE '% WHILE %' OR [Object] LIKE '% WHILE' OR [Object] = 'WHILE'
		OR [Object] LIKE '% WITH %' OR [Object] LIKE '% WITH' OR [Object] = 'WITH'
		OR [Object] LIKE '% WITHOUT %' OR [Object] LIKE '% WITHOUT' OR [Object] = 'WITHOUT'
		OR [Object] LIKE '% WORK %' OR [Object] LIKE '% WORK' OR [Object] = 'WORK'
		OR [Object] LIKE '% WRITE %' OR [Object] LIKE '% WRITE' OR [Object] = 'WRITE'
		OR [Object] LIKE '% WRITETEXT %' OR [Object] LIKE '% WRITETEXT' OR [Object] = 'WRITETEXT'
		OR [Object] LIKE '% YEAR %' OR [Object] LIKE '% YEAR' OR [Object] = 'YEAR'
		OR [Object] LIKE '% ZONE %' OR [Object] LIKE '% ZONE' OR [Object] = 'ZONE');

	/* http://msdn.microsoft.com/en-us/library/ms186755.aspx */
	INSERT INTO #tmpfinalobjectnames
	SELECT 5, [DBName], [schemaName], [Object], [Col], type_desc, NULL
	FROM #tmpobjectnames
	WHERE [type] IN ('FN','FS','TF','IF') AND [Object] LIKE 'fn[_]%'
		AND [Object] NOT IN ('fn_diagram_objects');	
		
		
	IF (SELECT COUNT(*) FROM #tmpfinalobjectnames) > 0
	BEGIN
		SELECT 'Naming_checks' AS [Category], 'Object_Naming_Convention' AS [Check], '[WARNING: Reserved words or special characters have been found in object names]' AS [Deviation]
	END
	ELSE
	BEGIN
		SELECT 'Naming_checks' AS [Category], 'Object_Naming_Convention' AS [Check], '[OK]' AS [Deviation]
	END;

	IF (SELECT COUNT(*) FROM #tmpfinalobjectnames) > 0
	BEGIN
		SELECT 'Naming_checks' AS [Category], 'Object_Naming_Convention' AS [Check], 
			CASE [Deviation] WHEN 1 THEN '[sp_ as prefix for stored procedures]'
				WHEN 2 THEN '[Special character as part of object name]'
				WHEN 3 THEN '[Special character as part of column name]'
				WHEN 4 THEN '[Reserved words as part of object name]'
				WHEN 5 THEN '[fn_ as prefix for user defined functions]'
				END AS [Deviation], 
			[DBName] AS [Database_Name], [schemaName] AS [Schema_Name], [Object] AS [Object_Name], QUOTENAME([Col]) AS [Col], [type_desc] AS [Object_Type] 
		FROM #tmpfinalobjectnames
		ORDER BY [Deviation], type_desc, [DBName], [schemaName], [Object];
	END;



	RAISERROR (N'|-Starting Security Checks', 10, 1) WITH NOWAIT

	--------------------------------------------------------------------------------------------------------------------------------
	-- Password check subsection
	--------------------------------------------------------------------------------------------------------------------------------
	RAISERROR (N'  |-Starting Password check', 10, 1) WITH NOWAIT
	DECLARE @passwords TABLE ([Deviation] VARCHAR(15), [Name] sysname, [CreateDate] DATETIME)
	DECLARE @word TABLE (word NVARCHAR(50))
	INSERT INTO @word values (0)
	INSERT INTO @word values (1)
	INSERT INTO @word values (12)
	INSERT INTO @word values (123)
	INSERT INTO @word values (1234)
	INSERT INTO @word values (12345)
	INSERT INTO @word values (123456)
	INSERT INTO @word values (1234567)
	INSERT INTO @word values (12345678)
	INSERT INTO @word values (123456789)
	INSERT INTO @word values (1234567890)
	INSERT INTO @word values (11111)
	INSERT INTO @word values (111111)
	INSERT INTO @word values (1111111)
	INSERT INTO @word values (11111111)
	INSERT INTO @word values (21)
	INSERT INTO @word values (321)
	INSERT INTO @word values (4321)
	INSERT INTO @word values (54321)
	INSERT INTO @word values (654321)
	INSERT INTO @word values (7654321)
	INSERT INTO @word values (87654321)
	INSERT INTO @word values (987654321)
	INSERT INTO @word values (0987654321)
	INSERT INTO @word values ('pwd')
	INSERT INTO @word values ('Password')
	INSERT INTO @word values ('password')
	INSERT INTO @word values ('P@ssw0rd')
	INSERT INTO @word values ('p@ssw0rd')
	INSERT INTO @word values ('Teste')
	INSERT INTO @word values ('teste')
	INSERT INTO @word values ('Test')
	INSERT INTO @word values ('test')
	INSERT INTO @word values ('')
	INSERT INTO @word values ('p@wd')

	INSERT INTO @passwords
	SELECT DISTINCT 'Weak_Password' AS Deviation, RTRIM(s.name) AS [Name], createdate AS [CreateDate] 
	FROM @word d
		INNER JOIN master.sys.syslogins s ON PWDCOMPARE(RTRIM(RTRIM(d.word)), s.[password]) = 1
	UNION ALL
	SELECT 'NULL_Passwords' AS Deviation, RTRIM(name) AS [Name], createdate AS [CreateDate] 
	FROM master.sys.syslogins
	WHERE [password] IS NULL
		AND isntname = 0 
		AND name NOT IN ('MSCRMSqlClrLogin','##MS_SmoExtendedSigningCertificate##','##MS_PolicySigningCertificate##','##MS_SQLResourceSigningCertificate##','##MS_SQLReplicationSigningCertificate##','##MS_SQLAuthenticatorCertificate##','##MS_AgentSigningCertificate##','##MS_SQLEnableSystemAssemblyLoadingUser##')
	UNION ALL
	SELECT DISTINCT 'Name=Password' AS Deviation, RTRIM(s.name) AS [Name], createdate AS [CreateDate] 
	FROM master.sys.syslogins s 
	WHERE PWDCOMPARE(RTRIM(RTRIM(s.name)), s.[password]) = 1
	ORDER BY [Deviation], [Name]

	IF (SELECT COUNT([Deviation]) FROM @passwords) > 0
	BEGIN
		SELECT 'Security_checks' AS [Category], 'Password_checks' AS [Check], '[WARNING: Some user logins have weak passwords. Please review these as soon as possible]' AS [Deviation]
		SELECT 'Security_checks' AS [Category], 'Password_checks' AS [Information], [Deviation], [Name], [CreateDate]
		FROM @passwords
		ORDER BY [Deviation], [Name]
	END
	ELSE
	BEGIN
		SELECT 'Security_checks' AS [Category], 'Password_checks' AS [Check], '[OK]' AS [Deviation]
	END;

	RAISERROR (N'|-Starting Maintenance and Monitoring Checks', 10, 1) WITH NOWAIT










--------------------------------------------------------------------------------------------------------------------------------
-- Clean up temp objects 
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'Clearing up temporary objects', 10, 1) WITH NOWAIT

IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#dbinfo')) 
DROP TABLE #dbinfo;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#output_dbinfo')) 
DROP TABLE #output_dbinfo;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblIOStall')) 
DROP TABLE #tblIOStall;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tmpdbs1')) 
DROP TABLE #tmpdbs1;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tmpdbs0')) 
DROP TABLE #tmpdbs0;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblPerfCount')) 
DROP TABLE #tblPerfCount;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.tblPerfThresholds'))
DROP TABLE tempdb.dbo.tblPerfThresholds;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblHypObj')) 
DROP TABLE #tblHypObj;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblIxs1')) 
DROP TABLE #tblIxs1;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblIxs2')) 
DROP TABLE #tblIxs2;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblIxs3')) 
DROP TABLE #tblIxs3;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblIxs4')) 
DROP TABLE #tblIxs4;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblIxs5')) 
DROP TABLE #tblIxs5;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblIxs6')) 
DROP TABLE #tblIxs6;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblFK')) 
DROP TABLE #tblFK;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#dbcc')) 
DROP TABLE #dbcc;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#avail_logs')) 
DROP TABLE #avail_logs;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#log_info1')) 
DROP TABLE #log_info1;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#log_info2')) 
DROP TABLE #log_info2;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tmpobjectnames'))
DROP TABLE #tmpobjectnames;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tmpfinalobjectnames'))
DROP TABLE #tmpfinalobjectnames;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblWaits'))
DROP TABLE #tblWaits;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblFinalWaits'))
DROP TABLE #tblFinalWaits;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblLatches'))
DROP TABLE #tblLatches;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblFinalLatches'))
DROP TABLE #tblFinalLatches;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#IndexCreation'))
DROP TABLE #IndexCreation;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#IndexRedundant'))
DROP TABLE #IndexRedundant;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblBlkChains'))
DROP TABLE #tblBlkChains;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblStatsSamp'))
DROP TABLE #tblStatsSamp;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblSpinlocksBefore'))
DROP TABLE #tblSpinlocksBefore;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblSpinlocksAfter'))
DROP TABLE #tblSpinlocksAfter;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblFinalSpinlocks'))
DROP TABLE #tblFinalSpinlocks;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#pagerepair'))
DROP TABLE #pagerepair;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tmp_dm_io_virtual_file_stats'))
DROP TABLE #tmp_dm_io_virtual_file_stats;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tmp_dm_exec_query_stats')) 
DROP TABLE #tmp_dm_exec_query_stats;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#dm_exec_query_stats')) 
DROP TABLE #dm_exec_query_stats;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblPendingIOReq'))
DROP TABLE #tblPendingIOReq;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblPendingIO'))
DROP TABLE #tblPendingIO;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#qpwarnings')) 
DROP TABLE #qpwarnings;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblStatsUpd'))
DROP TABLE #tblStatsUpd;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblPerSku'))
DROP TABLE #tblPerSku;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblColStoreIXs'))
DROP TABLE #tblColStoreIXs;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#SystemHealthSessionData'))
DROP TABLE #SystemHealthSessionData;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tmpdbfiledetail'))
DROP TABLE #tmpdbfiledetail;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblHints'))
DROP TABLE #tblHints;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblTriggers'))
DROP TABLE #tblTriggers;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tmpIPS'))
DROP TABLE #tmpIPS;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblCode'))
DROP TABLE #tblCode;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblWorking'))
DROP TABLE #tblWorking;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tmpdbs_userchoice'))
DROP TABLE #tmpdbs_userchoice;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#xp_cmdshell_CluNodesOutput'))
DROP TABLE #xp_cmdshell_CluNodesOutput;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#xp_cmdshell_CluOutput'))
DROP TABLE #xp_cmdshell_CluOutput;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#xp_cmdshell_Nodes'))
DROP TABLE #xp_cmdshell_Nodes;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#xp_cmdshell_QFEOutput'))
DROP TABLE #xp_cmdshell_QFEOutput;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#xp_cmdshell_QFEFinal'))
DROP TABLE #xp_cmdshell_QFEFinal;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#RegResult'))
DROP TABLE #RegResult;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#ServiceStatus'))
DROP TABLE #ServiceStatus;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#xp_cmdshell_AcctSPNoutput'))
DROP TABLE #xp_cmdshell_AcctSPNoutput;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#xp_cmdshell_DupSPNoutput'))
DROP TABLE #xp_cmdshell_DupSPNoutput;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#FinalDupSPN'))
DROP TABLE #FinalDupSPN;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#ScopedDupSPN'))
DROP TABLE #ScopedDupSPN;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblDRI'))
DROP TABLE #tblDRI;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblInMemDBs'))
DROP TABLE #tblInMemDBs;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tmpXIS'))
DROP TABLE #tmpXIS;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tmpXNCIS'))
DROP TABLE #tmpXNCIS;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tmpIPS_CI'))
DROP TABLE #tmpIPS_CI;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tmp_dm_io_virtual_file_stats'))
DROP TABLE #tmp_dm_io_virtual_file_stats;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.##tmpdbsizes'))
DROP TABLE ##tmpdbsizes;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblDeprecated'))
DROP TABLE #tblDeprecated;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.#tblDeprecatedJobs'))
DROP TABLE #tblDeprecatedJobs;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID('tempdb.dbo.##tblKeywords'))
DROP TABLE ##tblKeywords;
EXEC ('USE tempdb; IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID(''tempdb.dbo.fn_perfctr'')) DROP FUNCTION dbo.fn_perfctr')
EXEC ('USE tempdb; IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID(''tempdb.dbo.fn_createindex_allcols'')) DROP FUNCTION dbo.fn_createindex_allcols')
EXEC ('USE tempdb; IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID(''tempdb.dbo.fn_createindex_keycols'')) DROP FUNCTION dbo.fn_createindex_keycols')
EXEC ('USE tempdb; IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [object_id] = OBJECT_ID(''tempdb.dbo.fn_createindex_includecols'')) DROP FUNCTION dbo.fn_createindex_includecols')
RAISERROR (N'All done!', 10, 1) WITH NOWAIT
GO