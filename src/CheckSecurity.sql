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

RAISERROR (N'Starting Pre-requisites section', 10, 1) WITH NOWAIT

