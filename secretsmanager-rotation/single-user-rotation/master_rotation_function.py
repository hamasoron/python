# Standard library (Python built-in modules)
import json
import logging
import os
import time
from typing import Dict, Optional, Any

# External library (Pre-installed in AWS Lambda runtime environment)
import boto3
from botocore.exceptions import ClientError
from botocore.client import BaseClient

# External library
import pymysql

# ============================================================================
# Configuration and Constants
# ============================================================================
# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variable keys - Optional: All have default values if not set
ENV_PASSWORD_LENGTH = 'PASSWORD_LENGTH'
ENV_EXCLUDE_CHARACTERS = 'EXCLUDE_CHARACTERS'
ENV_RDS_PASSWORD_PROPAGATION_WAIT = 'RDS_PASSWORD_PROPAGATION_WAIT'
ENV_DB_CONNECTION_TEST_RETRIES = 'DB_CONNECTION_TEST_RETRIES'
ENV_DB_CONNECTION_TEST_RETRY_DELAY = 'DB_CONNECTION_TEST_RETRY_DELAY'
ENV_DB_CA_BUNDLE_PATH = 'DB_CA_BUNDLE_PATH'

# Default values
DEFAULT_PASSWORD_LENGTH = 32
DEFAULT_EXCLUDE_CHARACTERS = '/@"\'\\'
DEFAULT_RDS_WAIT_TIME = 10
DEFAULT_CONNECTION_RETRIES = 3
DEFAULT_RETRY_DELAY = 5
DEFAULT_CONNECTION_TIMEOUT = 30

# MySQL Error Codes
MYSQL_ERROR_ACCESS_DENIED = 1045
MYSQL_ERROR_ACCESS_DENIED_DB = 1044
MYSQL_ERROR_CONNECTION_REFUSED = 2003
MYSQL_ERROR_UNKNOWN_HOST = 2005
MYSQL_ERROR_SERVER_GONE = 2006

# Secrets Manager version stages
VERSION_STAGE_CURRENT = 'AWSCURRENT'
VERSION_STAGE_PENDING = 'AWSPENDING'

# ============================================================================
# AWS Lambda Handler (First function called by AWS Secrets Manager)
# ============================================================================
# Entry point: lambda_handler()
#   → Routes to: create_secret, set_secret, test_secret, finish_secret
#
# ============================================================================
# Rotation Flow (Single-User Strategy)
# ============================================================================
# Step 1: createSecret
#   - Get AWSCURRENT secret value
#   - Generate new password
#   - Store new secret value as AWSPENDING version
#
# Step 2: setSecret
#   - Get AWSCURRENT and AWSPENDING secret values
#   - Update RDS master password via modify_db_cluster API
#   - Wait for RDS password propagation (default: 10 seconds)
#
# Step 3: testSecret
#   - Get AWSPENDING secret value
#   - Verify database connectivity with retry logic
#
# Step 4: finishSecret
#   - Get current version ID (AWSCURRENT)
#   - Promote AWSPENDING to AWSCURRENT (old AWSCURRENT to AWSPREVIOUS)
#
# ============================================================================
# Exception Handling Pattern
# ============================================================================
# 1. ClientError: AWS SDK errors (Secrets Manager, RDS)
# 2. ValueError: Missing or invalid parameters
# 3. pymysql.err.OperationalError: DB connection/auth errors
# 4. pymysql.err.MySQLError: General MySQL errors
# 5. Exception: Catch-all for unexpected errors

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Purpose:
        Entry point for AWS Secrets Manager secret rotation (Single-user strategy).
        Sends the rotation request to the appropriate step handler.

    Flow Summary:
        1. Validate required event parameters (Step, SecretId, ClientRequestToken).
        2. Initialize AWS Secrets Manager client.
        3. Send the rotation request to the appropriate step handler.
        4. Return success response or raise exception.

    Args:
        event (dict): Event data from AWS Secrets Manager
            Required keys:
                - Step: Rotation step (createSecret/setSecret/testSecret/finishSecret)
                - SecretId: ARN of the secret being rotated
                - ClientRequestToken: Unique version ID for this rotation
        context (object): Attributes and methods of Lambda function

    Returns:
        dict: Response with statusCode and body message

    Raises:
        ValueError: If required event parameters are missing or invalid step name
        Exception: For unexpected internal errors

    References:
        https://docs.aws.amazon.com/ja_jp/secretsmanager/latest/userguide/rotate-secrets_lambda.html
        https://docs.aws.amazon.com/ja_jp/lambda/latest/dg/python-context.html

    Example Event:
        {
            "Step": "createSecret",
            "SecretId": "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:MySecret-abc123",
            "ClientRequestToken": "e4bfd8c9-5b1a-4492-934d-2d7ac03ef6c5"
        }

    Note:
        AWS Secrets Manager automatically retries multiple times if the rotation process fails.
        The same error may appear in logs multiple times.
    """

    # Format the event received from AWS Secrets Manager for logging
    log_event = {
        "Step": event.get("Step"),
        "SecretId": event.get("SecretId", "N/A"),
        "RequestId": context.aws_request_id if context else "N/A"
    }
    logger.info(f"Master rotation event received: {json.dumps(log_event)}")

    # Validate that all required keys exist in the event
    try:
        step = event['Step']
        arn = event['SecretId']
        token = event['ClientRequestToken']
    except KeyError as e:
        logger.error(f"Missing required event parameter: {str(e)}")
        raise ValueError(f"Missing required event parameter: {str(e)}")
    
    # Initialize Secrets Manager client
    # Credentials are retrieved in order: Environment variables → AWS config files → IAM role(Lambda execution role)
    service_client = boto3.client('secretsmanager')

    # Execute the appropriate rotation step (main logic)
    try:
        if step == 'createSecret':
            create_secret(service_client, arn, token)
        elif step == 'setSecret':
            set_secret(service_client, arn, token)
        elif step == 'testSecret':
            test_secret(service_client, arn, token)
        elif step == 'finishSecret':
            finish_secret(service_client, arn, token)
        else:
            logger.error(f"Unknown step: {step}")
            raise ValueError(f"Unknown step: {step}")
            
        logger.info(f"Successfully completed master rotation step {step} for secret {arn}")
        return {"statusCode": 200, "body": f"Master rotation step {step} completed successfully"}

    except Exception as e:
        logger.error(f"Error during master rotation step {step}: {str(e)}", exc_info=True)
        raise 

# ============================================================================
# Secrets Manager Rotation Steps (Main Logic)
# ============================================================================
# Single-user rotation flow: createSecret → setSecret → testSecret → finishSecret
# Strategy: Updates master password directly using RDS modify_db_cluster API
#
# Function Dependencies:
#   create_secret()
#   ├── get_secret() ───────────────────────────────── Get AWSCURRENT secret value
#   └── create_new_secret_value() ──────────────────── Generate new password
#       └── get_random_password() ──────────────────── AWS Secrets Manager password generation
#
#   set_secret()
#   └── get_secret() ───────────────────────────────── Get AWSCURRENT and AWSPENDING secret values
#
#   test_secret()
#   ├── get_secret() ───────────────────────────────── Get AWSPENDING secret value
#   └── test_database_connection() ─────────────────── Verify new password with retry logic
#
#   finish_secret()
#   └── get_current_version() ──────────────────────── Get AWSCURRENT secret version ID

def create_secret(service_client: BaseClient, arn: str, token: str) -> None:
    """
    Purpose:
        Create a new secret version with AWSPENDING stage and a newly generated password.

    Flow Summary:
        1. Check if AWSPENDING version already exists for this token.
        2. Get current secret (AWSCURRENT) from Secrets Manager.
        3. Generate new secret with updated password.
        4. Store new secret with AWSPENDING stage.

    Args:
        service_client (BaseClient): Boto3 Secrets Manager client
        arn (str): ARN of the secret to rotate
        token (str): Client request token (version ID)

    Returns:
        None: Completes successfully or raises exception

    Raises:
        ClientError: If secret retrieval or storage fails
        Exception: For unexpected internal errors

    References:
        https://docs.aws.amazon.com/ja_jp/secretsmanager/latest/userguide/rotate-secrets_lambda-functions.html
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/secretsmanager/client/get_secret_value.html
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/secretsmanager/client/put_secret_value.html

    Note:
        If AWSPENDING already exists for the same token, this step is skipped.
    """

    try:
        # Skip if AWSPENDING already exists for the same token
        try:
            service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage=VERSION_STAGE_PENDING)
            logger.info(f"AWSPENDING version already exists for secret {arn} with token {token}, skipping.")
            return
        except service_client.exceptions.ResourceNotFoundException:
            # Expected - AWSPENDING doesn't exist yet, continue with creation
            pass
        except ClientError as e:
            if e.response['Error']['Code'] != 'ResourceNotFoundException':
                logger.error(f"Unexpected error checking AWSPENDING for {arn}: {e}")
                raise
        
        # Get AWSCURRENT secret value using get_secret function()
        # Generate new secret value using create_new_secret_value function()
        current_secret = get_secret(service_client, arn, version_stage=VERSION_STAGE_CURRENT)
        new_secret = create_new_secret_value(service_client, current_secret)
        
        # Store new secret as AWSPENDING version
        # The token becomes the version ID for this new secret version
        service_client.put_secret_value(
            SecretId=arn,
            ClientRequestToken=token,
            SecretString=json.dumps(new_secret),
            VersionStages=[VERSION_STAGE_PENDING]
        )
        logger.info(f"Successfully created new AWSPENDING version for secret {arn} with token {token}.")
    except ClientError as e:
        logger.error(f"ClientError in create_secret for ARN {arn}, token {token}: {e}", exc_info=True)
        raise
    except Exception as e:
        logger.error(f"Unexpected error in create_secret for ARN {arn}, token {token}: {e}", exc_info=True)
        raise

def set_secret(service_client: BaseClient, arn: str, token: str) -> None:
    """
    Purpose:
        Update the master user password in RDS/Aurora MySQL cluster using RDS modify_db_cluster API.

    Flow Summary:
        1. Get current (AWSCURRENT) and pending (AWSPENDING) secrets.
        2. Extract cluster identifier from current secret and new password from pending secret.
        3. Call RDS modify_db_cluster API to update master password.
        4. Wait for password propagation (default: 10 seconds).

    Args:
        service_client (BaseClient): Boto3 Secrets Manager client
        arn (str): ARN of the secret being rotated
        token (str): Client request token (version ID)

    Environment Variables:
        RDS_PASSWORD_PROPAGATION_WAIT: Wait time in seconds (default: 10)

    Returns:
        None: Completes successfully or raises exception

    Raises:
        ValueError: If cluster identifier or new password is missing
        ClientError: If AWS API calls fail (Secrets Manager or RDS)
        Exception: For unexpected internal errors

    References:
        https://docs.aws.amazon.com/ja_jp/secretsmanager/latest/userguide/rotate-secrets_lambda-functions.html
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds/client/modify_db_cluster.html

    Note:
        The wait time after password update is critical. RDS needs time to propagate
        the new password. Testing too soon will cause authentication errors and
        trigger unnecessary retries by Secrets Manager.
    """

    try:
        logger.info(f"Setting master user password using RDS modify-db-cluster API for secret {arn}")
        
        # Get current and pending master secrets
        try:
            current_secret = get_secret(service_client, arn, version_stage=VERSION_STAGE_CURRENT)
            pending_secret = get_secret(service_client, arn, token, VERSION_STAGE_PENDING)
        except ClientError as e:
            logger.error(f"Failed to retrieve secrets from Secrets Manager for {arn}: {e}")
            raise
        
        # Initialize RDS client
        rds_client = boto3.client('rds')
        
        # Extract cluster identifier from AWSCURRENT secret value and new password from AWSPENDING secret value
        cluster_identifier = current_secret.get('dbClusterIdentifier')
        new_password = pending_secret.get('password')
        
        # Validate required parameters
        if not cluster_identifier:
            raise ValueError("RDS cluster identifier not found in secret")
        
        if not new_password:
            raise ValueError("New master password not found in AWSPENDING secret")
        
        # Update RDS cluster master password
        logger.info(f"Updating master password for cluster: {cluster_identifier}")
        try:
            rds_client.modify_db_cluster(
                DBClusterIdentifier=cluster_identifier,
                MasterUserPassword=new_password,
                ApplyImmediately=True
            )
            logger.info(f"Master password updated successfully using RDS API for secret {arn}")
            
            # Wait for RDS password change to propagate (default: 10 seconds)
            wait_time = int(os.environ.get(ENV_RDS_PASSWORD_PROPAGATION_WAIT, DEFAULT_RDS_WAIT_TIME))
            logger.info(f"Waiting {wait_time} seconds for RDS password change to propagate...")
            time.sleep(wait_time)
            logger.info(f"Password propagation wait completed")
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'InvalidDBClusterStateFault':
                logger.error(f"DB cluster {cluster_identifier} is not in a valid state for password change: {e}")
            elif error_code == 'DBClusterNotFoundFault':
                logger.error(f"DB cluster {cluster_identifier} not found: {e}")
            else:
                logger.error(f"RDS API error while updating password: {e}")
            raise
            
    except ValueError as e:
        logger.error(f"Validation error in set_secret for master {arn}: {str(e)}")
        raise
    except ClientError as e:
        logger.error(f"AWS API error in set_secret for master {arn}: {str(e)}", exc_info=True)
        raise
    except Exception as e:
        logger.error(f"Unexpected error in set_secret for master {arn}: {str(e)}", exc_info=True)
        raise

def test_secret(service_client: BaseClient, arn: str, token: str) -> None:
    """
    Purpose:
        Verify that the new master password (AWSPENDING) can successfully connect to the database.

    Flow Summary:
        1. Get AWSPENDING secret value from Secrets Manager.
        2. Extract database connection parameters (host, port, username, password).
        3. Attempt database connection with retry logic (handles propagation delay).
        4. Raise exception if all connection attempts fail.

    Args:
        service_client (BaseClient): Boto3 Secrets Manager client
        arn (str): ARN of the secret being tested
        token (str): Client request token (version ID)

    Environment Variables:
        DB_CONNECTION_TEST_RETRIES: Number of retries before failure (default: 3)
        DB_CONNECTION_TEST_RETRY_DELAY: Seconds between retries (default: 5)

    Returns:
        None: Completes successfully or raises exception

    Raises:
        ValueError: If required fields (host, username, password) are missing
        pymysql.err.OperationalError: If authentication fails after all retries
        pymysql.err.MySQLError: If other database errors occur
        Exception: For unexpected internal errors

    References:
        https://docs.aws.amazon.com/ja_jp/secretsmanager/latest/userguide/rotate-secrets_lambda-functions.html

    Note:
        Retry logic is essential. The new password may not be immediately active after
        the RDS password update. Authentication errors (code 1045) may occur during
        early connection attempts. These errors are expected and will trigger retries.
    """
    
    try:
        # Get AWSPENDING secret value using get_secret function()
        pending_secret = get_secret(service_client, arn, token, VERSION_STAGE_PENDING)
        
        # Extract database connection parameters from AWSPENDING secret value
        host = pending_secret.get('host')
        port = pending_secret.get('port')
        username = pending_secret.get('username')
        password = pending_secret.get('password')
        
        # Validate required parameters
        if not all([host, port, username, password]):
            raise ValueError("Required credentials (host, port, username, password) are missing from secret")
        
        # Convert port to integer
        port = int(port)
        
        logger.info(f"Testing connection with new master password for user {username} for secret {arn}")

        # Retry configuration for database password propagation
        max_retries = int(os.environ.get(ENV_DB_CONNECTION_TEST_RETRIES, DEFAULT_CONNECTION_RETRIES))
        retry_delay = int(os.environ.get(ENV_DB_CONNECTION_TEST_RETRY_DELAY, DEFAULT_RETRY_DELAY))
        
        last_exception = None
        # Python's range(start, stop) generates numbers from start to stop-1 
        for attempt in range(1, max_retries + 1):
            try:
                # Test database connection with new password using test_database_connection function()
                test_database_connection(host, port, username, password)
                logger.info(f"Successfully connected with new master password for user {username} for secret {arn}")
                logger.info(f"Master secret tested successfully for {arn}")
                return  # Success - exit function

            except pymysql.err.OperationalError as e:
                last_exception = e
                error_code = e.args[0] if e.args else None
                
                # Retry if authentication error (1045) occurs and it's not the last attempt
                if error_code == MYSQL_ERROR_ACCESS_DENIED and attempt < max_retries:
                    # Write a warning to the log, then wait and retry
                    logger.warning(f"Authentication failed on attempt {attempt}/{max_retries}. "
                                 f"RDS password may still be propagating. Waiting {retry_delay} seconds before retry...")
                    time.sleep(retry_delay)
                else:
                    # Non-retryable error or last attempt failed - raise exception
                    raise

            except Exception as e:
                # Non-retryable errors (network issues, etc.)
                logger.error(f"Non-retryable error during connection test: {str(e)}")
                raise
        
        logger.error(f"All {max_retries} connection attempts failed for secret {arn}")
        raise last_exception
        
    except Exception as e:
        logger.error(f"Error in test_secret for master {arn}: {str(e)}")
        raise

def finish_secret(service_client: BaseClient, arn: str, token: str) -> None:
    """
    Purpose:
        Complete the rotation by promoting AWSPENDING to AWSCURRENT.

    Flow Summary:
        1. Get current version ID (AWSCURRENT).
        2. Skip if the token is already AWSCURRENT.
        3. Promote AWSPENDING to AWSCURRENT.
        4. AWS automatically moves old AWSCURRENT to AWSPREVIOUS.

    Args:
        service_client (BaseClient): Boto3 Secrets Manager client
        arn (str): ARN of the secret being finalized
        token (str): Client request token (version ID)

    Returns:
        None: Completes successfully or raises exception

    Raises:
        Exception: For unexpected internal errors

    References:
        https://docs.aws.amazon.com/ja_jp/secretsmanager/latest/userguide/rotate-secrets_lambda-functions.html

    Version Stage Lifecycle:
        1st rotation:
            Before: Version-A (AWSCURRENT)
            After:  Version-A (AWSPREVIOUS), Version-B (AWSCURRENT + AWSPENDING)
        
        2nd rotation:
            Before: Version-B (AWSCURRENT + AWSPENDING)
            create_secret: Version-C (AWSPENDING), Version-B (AWSCURRENT only)
            After: Version-B (AWSPREVIOUS), Version-C (AWSCURRENT + AWSPENDING)

    Note:
        AWSPENDING label is automatically removed from old versions when put_secret_value
        is called with a new token. No manual cleanup is required.
    """

    try:
        # Get current version ID using get_current_version function()
        current_version_id = get_current_version(service_client, arn)
        
        # Skip if already current
        if current_version_id == token:
            logger.info(f"Secret {arn} is already current, skipping version update")
            return
        
        # Promote AWSPENDING to AWSCURRENT
        service_client.update_secret_version_stage(
            SecretId=arn,
            VersionStage=VERSION_STAGE_CURRENT,
            MoveToVersionId=token,
            RemoveFromVersionId=current_version_id
        )
        
        logger.info(f"Master secret rotation completed successfully for {arn}")
        
    except Exception as e:
        logger.error(f"Error in finish_secret for master {arn}: {str(e)}")
        raise 

# ============================================================================
# Helper Functions
# ============================================================================
# Core utilities used by rotation steps above
#
# Functions:
#   - get_secret(): Get secret value from Secrets Manager
#   - create_new_secret_value(): Create new secret dict with generated password
#   - get_random_password(): Generate secure password via AWS API
#   - test_database_connection(): Verify DB connectivity with SSL/TLS
#   - get_current_version(): Get current secret version ID

def get_secret(
    service_client: BaseClient, 
    arn: str, 
    token: Optional[str] = None, 
    version_stage: str = VERSION_STAGE_CURRENT
) -> Dict[str, Any]:
    """
    Purpose:
        Get secret value from AWS Secrets Manager for the specified version stage.

    Flow Summary:
        1. Prepare parameters for API request.
        2. Add version ID to parameters if token is specified.
        3. Call AWS Secrets Manager get_secret_value API.
        4. Parse JSON string and return as dictionary.

    Args:
        service_client (BaseClient): Boto3 Secrets Manager client
        arn (str): ARN of the secret to retrieve
        token (str, optional): Version ID to retrieve specific version
        version_stage (str, optional): Version stage (default: AWSCURRENT)

    Returns:
        dict: Secret value as dictionary
            Example: {
                "engine": "mysql",
                "host": "cluster.region.rds.amazonaws.com",
                "port": 3306,
                "username": "master",
                "password": "random_password",
                "dbClusterIdentifier": "my-cluster"
            }

    Raises:
        ClientError: If secret retrieval fails (e.g., ResourceNotFoundException)

    References:
        https://docs.aws.amazon.com/ja_jp/secretsmanager/latest/userguide/reference_secret_json_structure.html
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/secretsmanager/client/get_secret_value.html
    """

    try:
        params = {
            'SecretId': arn,
            'VersionStage': version_stage
        }

        # If token is specified, add version ID to params
        if token is not None:
            params['VersionId'] = token

        # Get secret value from AWS Secrets Manager and parse JSON
        response = service_client.get_secret_value(**params)
        return json.loads(response['SecretString'])

    except ClientError as e:
        logger.error(f"Error retrieving secret: '{arn}' {e}")
        raise

def create_new_secret_value(service_client: BaseClient, current_secret: Dict[str, Any]) -> Dict[str, Any]:
    """
    Purpose:
        Create a new secret dictionary by copying current secret and replacing password.

    Flow Summary:
        1. Validate that 'password' field exists in current secret.
        2. Create a copy of the current secret dictionary.
        3. Generate new password using get_random_password().
        4. Replace 'password' field with newly generated password.
        5. Return new secret dictionary.

    Args:
        service_client (BaseClient): Boto3 Secrets Manager client
        current_secret (dict): Current secret dictionary from Secrets Manager

    Returns:
        dict: New secret with all fields copied except password
            Example: {
                "engine": "mysql",
                "host": "cluster.region.rds.amazonaws.com",
                "port": 3306,
                "username": "master",
                "password": "NEW_RANDOM_PASSWORD",  # ← Updated
                "dbClusterIdentifier": "my-cluster"
            }

    Raises:
        KeyError: If 'password' field is missing in current_secret

    References:
        https://docs.aws.amazon.com/ja_jp/secretsmanager/latest/userguide/reference_secret_json_structure.html

    Note:
        All other fields (engine, host, port, username, dbClusterIdentifier, etc.)
        are preserved as-is. Only the password is changed.
    """
    
    # Validate that password field exists
    if 'password' not in current_secret:
        raise KeyError("The 'password' field is required in current_secret")
    
    # Copy the current secret
    new_secret = current_secret.copy()
    
    # Generate new password using get_random_password function()
    new_secret['password'] = get_random_password(service_client)
    
    return new_secret

def get_random_password(service_client: BaseClient) -> str:
    """
    Purpose:
        Generate a secure random password using get_random_password API.

    Flow Summary:
        1. Read password length and excluded characters from environment variables.
        2. Call get_random_password API with password policy parameters.
        3. Return generated password string.

    Args:
        service_client (BaseClient): Boto3 Secrets Manager client

    Environment Variables:
        PASSWORD_LENGTH: Password length (default: 32)
        EXCLUDE_CHARACTERS: Characters to exclude (default: /@"'\\)

    Returns:
        str: Randomly generated password meeting the password policy

    Password Policy:
        - Length: Configurable via PASSWORD_LENGTH (default: 32)
        - Includes: Uppercase, lowercase, numbers, punctuation
        - Excludes: Configurable via EXCLUDE_CHARACTERS (default: /@"'\\)
        - No spaces allowed
        - At least one character from each included type

    Aurora MySQL Constraints:
        - Must be 8-41 printable ASCII characters
        - Cannot contain: /, ", @, or spaces

    References:
        https://docs.aws.amazon.com/ja_jp/AmazonRDS/latest/AuroraUserGuide/Aurora.Modifying.html
        https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetRandomPassword.html
    """

    passwd = service_client.get_random_password(
        PasswordLength=int(os.environ.get(ENV_PASSWORD_LENGTH, DEFAULT_PASSWORD_LENGTH)),
        ExcludeCharacters=os.environ.get(ENV_EXCLUDE_CHARACTERS, DEFAULT_EXCLUDE_CHARACTERS),
        ExcludeNumbers=False,
        ExcludePunctuation=False,
        ExcludeUppercase=False,
        ExcludeLowercase=False,
        IncludeSpace=False,
        RequireEachIncludedType=True
    )
    return passwd['RandomPassword']

def test_database_connection(host: str, port: int, username: str, password: str) -> bool:
    """
    Purpose:
        Test database connection with provided credentials using SSL/TLS encryption.

    Flow Summary:
        1. Validate required parameters (host, port, username, password).
        2. Check for CA certificate bundle path in environment variables.
        3. Establish SSL/TLS connection to database.
        4. Execute simple query (SELECT 1) to verify connection.
        5. Close connection and return success.

    Args:
        host (str): Database host address (e.g., cluster.region.rds.amazonaws.com)
        port (int): Database port number (typically 3306 for MySQL)
        username (str): Database user name
        password (str): Database password to test

    Environment Variables:
        DB_CA_BUNDLE_PATH: Path to CA certificate bundle (optional)

    Returns:
        bool: True if connection is successful

    Raises:
        ValueError: If required parameters are missing or invalid
        pymysql.err.OperationalError: If connection or authentication fails
            Error codes:
                1045: Access denied (invalid credentials)
                1044: Access denied to database
                2003: Cannot connect (connection refused)
                2005: Unknown host
                2006: Server has gone away
        pymysql.err.MySQLError: For other MySQL-related errors
        Exception: For unexpected errors

    SSL/TLS Configuration:
        - If DB_CA_BUNDLE_PATH is set and file exists:
          Uses explicit CA certificate with VERIFY_IDENTITY mode (full validation)
        - Otherwise:
          Uses system default CA certificates with certificate verification (recommended)

    References:
        https://pymysql.readthedocs.io/en/latest/modules/connections.html
        https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html
        https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem
    """
    
    # Validate required parameters
    if not all([host, username, password]):
        raise ValueError("Host, username, and password are required")
    # Raise error if port is not an integer type or port <= 0
    if not isinstance(port, int) or port <= 0:
        raise ValueError(f"Invalid port number: {port}")
    
    # Check if CA certificate bundle path is specified via environment variable
    ca_bundle_path = os.environ.get(ENV_DB_CA_BUNDLE_PATH)

    # Two SSL/TLS connection modes based on CA certificate availability
    try:
        # Mode 1: Use explicit CA certificate path (custom CA or specific AWS RDS CA bundle version)
        #         Set DB_CA_BUNDLE_PATH environment variable to specify certificate path
        #         Typical use case: Private CA, corporate CA, or certificate version control
        if ca_bundle_path and os.path.exists(ca_bundle_path):
            logger.info(f"Using SSL with explicit CA bundle: {ca_bundle_path}")
            with pymysql.connect(
                host=host,
                port=port,
                user=username,
                password=password,
                connect_timeout=DEFAULT_CONNECTION_TIMEOUT,
                read_timeout=DEFAULT_CONNECTION_TIMEOUT,
                write_timeout=DEFAULT_CONNECTION_TIMEOUT,
                ssl_disabled=False,  # Enable SSL/TLS
                ssl_ca=ca_bundle_path,  # Specify CA certificate path
                ssl_verify_cert=True,  # Verify server certificate
                ssl_verify_identity=True  # Verify hostname matches certificate
            ) as conn:
                # Execute simple query to verify connection works
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                    cur.fetchone()
        
        # Mode 2: Use system default CA certificates (includes AWS RDS CA bundle)
        #         Recommended for standard AWS environments - no configuration needed
        else:
            logger.info("Using SSL with system default CA certificates")
            with pymysql.connect(
                host=host,
                port=port,
                user=username,
                password=password,
                connect_timeout=DEFAULT_CONNECTION_TIMEOUT,
                read_timeout=DEFAULT_CONNECTION_TIMEOUT,
                write_timeout=DEFAULT_CONNECTION_TIMEOUT,
                ssl_disabled=False,  # Enable SSL/TLS
                # ssl_ca not specified - uses system CA (/etc/ssl/certs/ on Lambda)
                ssl_verify_cert=True,  # Verify server certificate
                ssl_verify_identity=True  # Verify hostname matches certificate
            ) as conn:
                # Execute simple query to verify connection works
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                    cur.fetchone()
        
        logger.info(f"Database connection test successful for user: {username}")
        return True
        
    except pymysql.err.OperationalError as e:
        # Handle MySQL operational errors (connection and authentication failures)
        error_code = e.args[0] if e.args else None
        
        # Authentication errors (error codes: 1045, 1044)
        if error_code in (MYSQL_ERROR_ACCESS_DENIED, MYSQL_ERROR_ACCESS_DENIED_DB):
            # 1045: Access denied (wrong password or user doesn't exist)
            # 1044: Access denied to database (insufficient privileges)
            logger.error(f"Authentication failed for user {username}: {str(e)}")
        
        # Connection errors (error codes: 2003, 2005, 2006)
        elif error_code in (MYSQL_ERROR_CONNECTION_REFUSED, MYSQL_ERROR_UNKNOWN_HOST, MYSQL_ERROR_SERVER_GONE):
            # 2003: Cannot connect (connection refused, firewall, wrong port)
            # 2005: Unknown host (DNS resolution failure)
            # 2006: Server has gone away (connection lost)
            logger.error(f"Cannot connect to database at {host}:{port}: {str(e)}")
        
        # Other operational errors
        else:
            logger.error(f"Database operational error: {str(e)}")
        raise
    
    except pymysql.err.MySQLError as e:
        # Handle other MySQL-specific errors (SQL syntax, query execution, etc.)
        logger.error(f"MySQL error during connection test: {str(e)}")
        raise
    
    except Exception as e:
        # Handle unexpected errors (network issues, SSL/TLS problems, etc.)
        logger.error(f"Unexpected error during database connection test: {str(e)}", exc_info=True)
        raise

def get_current_version(service_client: BaseClient, arn: str) -> Optional[str]:
    """
    Purpose:
        Get the current version ID (AWSCURRENT stage) from Secrets Manager.

    Flow Summary:
        1. Call describe_secret API to get secret metadata.
        2. Loop through VersionIdsToStages dictionary.
        3. Find version ID that has AWSCURRENT label.
        4. Return version ID, or None if AWSCURRENT not found.

    Args:
        service_client (BaseClient): Boto3 Secrets Manager client
        arn (str): ARN of the secret

    Returns:
        str: Current version ID or None if AWSCURRENT not found

    Raises:
        Exception: For unexpected internal errors

    References:
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/secretsmanager/client/describe_secret.html

    Example Response:
        VersionIdsToStages: {
            "abc123-version-id-1": ["AWSCURRENT"],
            "def456-version-id-2": ["AWSPREVIOUS"]
        }
    """

    try:
        response = service_client.describe_secret(SecretId=arn)

        # Find version ID that has AWSCURRENT label
        for version_id, stages in response.get('VersionIdsToStages', {}).items():
            # If AWSCURRENT label is found, return version ID
            if VERSION_STAGE_CURRENT in stages:
                return version_id

        # If AWSCURRENT label is not found, return None
        return None

    except Exception as e:
        logger.error(f"Error in get_current_version for {arn}: {str(e)}")
        raise