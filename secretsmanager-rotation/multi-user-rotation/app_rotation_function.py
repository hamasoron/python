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

# Environment variable keys - REQUIRED: Must be set via Lambda environment variables in IaC(Terraform/CloudFormation/CDK)
ENV_MASTER_SECRET_ARN = 'MASTER_SECRET_ARN'
ENV_APP_USER_1 = 'APP_USER_1'
ENV_APP_USER_2 = 'APP_USER_2'

# Environment variable keys - Optional: All have default values if not set
ENV_PASSWORD_LENGTH = 'PASSWORD_LENGTH'
ENV_EXCLUDE_CHARACTERS = 'EXCLUDE_CHARACTERS'
ENV_DB_PASSWORD_PROPAGATION_WAIT = 'DB_PASSWORD_PROPAGATION_WAIT'
ENV_DB_CONNECTION_TEST_RETRIES = 'DB_CONNECTION_TEST_RETRIES'
ENV_DB_CONNECTION_TEST_RETRY_DELAY = 'DB_CONNECTION_TEST_RETRY_DELAY'
ENV_DB_CA_BUNDLE_PATH = 'DB_CA_BUNDLE_PATH'

# Default values
DEFAULT_PASSWORD_LENGTH = 32
DEFAULT_EXCLUDE_CHARACTERS = '/@"\'\\'
DEFAULT_MAX_SET_SECRET_RETRIES = 10
DEFAULT_SET_SECRET_RETRY_DELAY = 3
DEFAULT_DB_WAIT_TIME = 5
DEFAULT_CONNECTION_RETRIES = 3
DEFAULT_RETRY_DELAY = 5
DEFAULT_CONNECTION_TIMEOUT = 30

# Default privileges for initial app user setup (used only on first rotation)
DEFAULT_APP_PRIVILEGES = 'SELECT,INSERT,UPDATE,DELETE,CREATE,DROP'

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
# Rotation Flow (Multi-User Strategy - Zero Downtime Rotation)
# ============================================================================
# Step 1: createSecret
#   - Get AWSCURRENT secret value
#   - Alternate username (APP_USER_1 ↔ APP_USER_2)
#   - Generate new password
#   - Store new secret value as AWSPENDING version
#
# Step 2: setSecret
#   - Get AWSCURRENT and AWSPENDING secret values
#   - Connect to database as master user for SQL operations
#   - Check if new user (APP_USER_2) exists
#   - If exists: ALTER USER password
#   - If not exists: CREATE USER + clone privileges from old user (APP_USER_1)
#   - Wait for RDS password propagation (default: 5 seconds)
#   - Handles concurrent master rotation with retry logic
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
# 1. ClientError: AWS SDK errors (Secrets Manager)
# 2. ValueError: Missing or invalid parameters
# 3. pymysql.err.OperationalError: DB connection/auth errors
# 4. pymysql.err.MySQLError: General MySQL errors
# 5. Exception: Catch-all for unexpected errors

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Purpose:
        Entry point for AWS Secrets Manager app user rotation (Multi-user strategy).
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
            "SecretId": "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:MyAppSecret-abc123",
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
    logger.info(f"App rotation event received: {json.dumps(log_event)}")
    
    # Validate that all required keys exist in the event
    try:
        step = event['Step']
        arn = event['SecretId']
        token = event['ClientRequestToken']
    except KeyError as e:
        logger.error(f"Missing required event parameter: {str(e)}")
        raise ValueError(f"Missing required event parameter: {str(e)}")
    
    # Initialize Secrets Manager client
    # Credentials are retrieved in order: Environment variables → AWS config files → IAM role (Lambda execution role)
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
            
        logger.info(f"Successfully completed app rotation step {step} for secret {arn}")
        return {"statusCode": 200, "body": f"App rotation step {step} completed successfully"}

    except Exception as e:
        logger.error(f"Error during app rotation step {step}: {str(e)}", exc_info=True)
        raise

# ============================================================================
# Secrets Manager Rotation Steps (Main Logic)
# ============================================================================
# Multi-user rotation flow: createSecret → setSecret → testSecret → finishSecret
# Strategy: Zero downtime by alternating between APP_USER_1 ↔ APP_USER_2
#
# Function Dependencies:
#   create_secret()
#   ├── get_secret() ───────────────────────────────── Get AWSCURRENT secret value
#   └── create_new_secret_value() ──────────────────── Alternate username and generate new password
#       └── get_random_password() ──────────────────── AWS Secrets Manager password generation
#
#   set_secret() [Complex - Concurrent master rotation support]
#   ├── get_secret() ───────────────────────────────── Get AWSCURRENT and AWSPENDING secret values
#   ├── get_master_secret_with_fallback() ──────────── Handle concurrent master rotation
#   │   └── get_secret() ───────────────────────────── Try AWSPENDING, fallback to AWSCURRENT secret values
#   ├── create_tls_connection() ────────────────────── Create SSL/TLS connection as master user
#   ├── user_exists() ──────────────────────────────── Check if user exists in mysql.user
#   └── clone_user_privileges() ────────────────────── Copy privileges from old to new user
#       ├── should_skip_grant() ────────────────────── Filter USAGE grants
#       └── parse_grant_statement() ────────────────── Regex parsing of GRANT statements
#
#   test_secret()
#   ├── get_secret() ───────────────────────────────── Get AWSPENDING secret value
#   └── test_database_connection() ─────────────────── Verify new password with retry logic
#       └── create_tls_connection() ────────────────── Create SSL/TLS connection with app credentials
#
#   finish_secret()
#   └── get_current_version() ──────────────────────── Get AWSCURRENT secret version ID

def create_secret(service_client: BaseClient, arn: str, token: str) -> None:
    """
    Purpose:
        Create a new secret version with AWSPENDING stage, alternating username and generating new password.

    Flow Summary:
        1. Check if AWSPENDING version already exists for this token.
        2. Get current secret (AWSCURRENT) from Secrets Manager.
        3. Generate new secret with alternated username and updated password.
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
        Update the new app user password in RDS/Aurora MySQL cluster using SQL with master user credentials.

    Flow Summary:
        1. Get current(AWSCURRENT) and pending(AWSPENDING) secrets from Secrets Manager.
        2. Extract database connection parameters from current or pending secrets.
        3. Get master secret ARN from environment variables.
        4. Extract username from current secret and new username and new password from pending secret.
        5. Establish SSL/TLS connection to database as master user.
        6. Connect to database as master user.
        7. Create new user(APP_USER_2) or update existing user(APP_USER_2)'s password using master user credentials.
        8. Commit and close the database connection.
        9. Wait for password propagation (default: 5 seconds).

    Multi-User Strategy:
        - Old user remains valid during rotation (zero downtime)
        - New user is created/updated in parallel
        - Applications continue using old user until finishSecret completes

    Rotation Timeline (DB Users and Secrets Manager State):
        Assuming APP_USER_1 = "hamasoron1", APP_USER_2 = "hamasoron2"
        
        1st Rotation (hamasoron1 → hamasoron2):
            - CREATE USER 'hamasoron2' with default privileges
            - 'hamasoron1' doesn't exist in DB yet (initial setup)
            - Result: root + hamasoron2
        
        2nd Rotation (hamasoron2 → hamasoron1):
            - CREATE USER 'hamasoron1' and clone privileges from hamasoron2
            - Result: root + hamasoron2 + hamasoron1 (both with same privileges)
        
        3rd+ Rotations:
            - ALTER USER (password update only, user already exists)
            - Result: Both users remain in the database, and their passwords are updated alternately
        
    Concurrent Master Rotation Support (Handles simultaneous rotations):
        - get_master_secret_with_fallback() always uses the latest master password
          (prefers AWSPENDING if exists, fallback to AWSCURRENT)
        - set_secret() automatically retries when authentication fails
          (master password may still be propagating)
        - test_secret() uses app credentials only
          (not affected by master password propagation delay)
        
        Concurrent rotation timeline:
            Time | Master Rotation                                   | App Rotation
            -----|---------------------------------------------------|-------------------------------------------------------------
            0s   | set_secret (RDS API via IAM)                      | set_secret detects AWSPENDING
                 |                                                   | └─ Waits 8 seconds for RDS propagation
            8s   | (propagating NEW master password...)              | set_secret connects with NEW Master credentials
                 |                                                   | └─ Updates App user password (usually succeeds on 1st try)
            ~10s | Password propagation wait completed (10s)         | Waits 5 seconds for password propagation
            ~13s | test_secret (connect AS NEW Master credentials)   | test_secret (connect AS NEW App credentials)
            
    Args:
        service_client (BaseClient): Boto3 Secrets Manager client
        arn (str): ARN of the app secret being rotated
        token (str): Client request token (version ID)

    Environment Variables:
        MASTER_SECRET_ARN: ARN of master user secret (required)
        DB_PASSWORD_PROPAGATION_WAIT: Wait time after password change (default: 5)

    Returns:
        None: Completes successfully or raises exception

    Raises:
        ValueError: If required parameters are missing
        ClientError: If AWS API calls fail
        pymysql.MySQLError: If database operation fails
        Exception: For unexpected internal errors
        
    References:
        https://docs.aws.amazon.com/ja_jp/secretsmanager/latest/userguide/rotate-secrets_lambda-functions.html
        

    Note:
        When concurrent master rotation is detected (AWSPENDING exists), waits 8 seconds
        before first connection attempt to allow RDS password propagation. This minimizes
        authentication failures and reduces unnecessary warning logs. Retry logic (max 10
        attempts) handles any remaining temporary auth failures.
    """

    try:
        logger.info(f"Setting app user password using SQL with master user credentials for secret {arn}")
        
        # Get current and pending app secrets values using get_secret function()
        try:
            current_secret = get_secret(service_client, arn, version_stage=VERSION_STAGE_CURRENT)
            pending_secret = get_secret(service_client, arn, token, VERSION_STAGE_PENDING)
        except ClientError as e:
            logger.error(f"Failed to get secrets from Secrets Manager for {arn}: {e}")
            raise
        
        # Extract host and port from AWSCURRENT or AWSPENDING secret values
        host = current_secret.get('host') or pending_secret.get('host')
        port = current_secret.get('port') or pending_secret.get('port')
        database = current_secret.get('database') or pending_secret.get('database')
        
        # Get master secret ARN from environment variables
        master_secret_arn = os.environ.get(ENV_MASTER_SECRET_ARN)
        if not master_secret_arn:
            raise ValueError("MASTER_SECRET_ARN environment variable is not set")
        
        # Extract username from AWSCURRENT secret value and new username and new password from AWSPENDING secret value
        current_username = current_secret.get('username')
        new_username = pending_secret.get('username')
        new_password = pending_secret.get('password')
        
        # Validate required parameters
        if not all([host, port, current_username, new_username, new_password]):
            missing_fields = []
            if not host: missing_fields.append("host")
            if not port: missing_fields.append("port")
            if not current_username: missing_fields.append("current_username")
            if not new_username: missing_fields.append("new_username")
            if not new_password: missing_fields.append("new_password")
            
            error_msg = f"Required credentials are missing: {', '.join(missing_fields)}"
            logger.error(error_msg)
            raise ValueError(error_msg)
        
        # Convert port to integer
        port = int(port)
        
        logger.info(f"Updating app username and password using master credentials on {host}:{port}")

        # Initialize retry count(default: 10 attempts) and delay time(default: 3 seconds)
        max_retries = DEFAULT_MAX_SET_SECRET_RETRIES
        retry_delay = DEFAULT_SET_SECRET_RETRY_DELAY
        
        # Check if master rotation is in progress
        master_rotation_in_progress = False
        try:
            service_client.get_secret_value(SecretId=master_secret_arn, VersionStage=VERSION_STAGE_PENDING)
            master_rotation_in_progress = True
            logger.info("Master rotation is in progress (AWSPENDING detected). Waiting 8 seconds for RDS password propagation before attempting connection...")
            # Wait for 8 seconds for RDS password propagation
            time.sleep(8) 
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                logger.info("No concurrent master rotation detected. Proceeding immediately.")
            else:
                logger.warning(f"Could not check master rotation status: {e}")
        
        # Create new user(APP_USER_2) or update existing user(APP_USER_2)'s password using master user credentials.
        # If authentication fails, the operation is automatically retried several times.
        # On every retry, master user credentials are retrieved using get_master_secret_with_fallback().
        for attempt in range(max_retries):
            try:
                # Get master secret value
                master_secret = get_master_secret_with_fallback(service_client, master_secret_arn, attempt)
                # Extract master username and password from master secret value
                master_username = master_secret.get('username')
                master_password = master_secret.get('password')
                
                if not all([master_username, master_password]):
                    raise ValueError("Master user credentials are incomplete")
                
                logger.info(f"Connecting as master user '{master_username}' to manage app user [attempt {attempt + 1}/{max_retries}]")
                
                # Establish SSL/TLS connection
                conn = create_tls_connection(host, port, master_username, master_password)
                
                # Create new user(APP_USER_2) or update existing user(APP_USER_2)'s password using master user credentials
                with conn.cursor() as cur:
                    # Check if new user(APP_USER_2) exists
                    if user_exists(cur, new_username):
                        # User(APP_USER_2) exists: Update password only
                        logger.info(f"User '{new_username}' exists, updating password")
                        cur.execute("ALTER USER %s@'%%' IDENTIFIED BY %s", (new_username, new_password))
                    else:
                        # User(APP_USER_2) does not exist: Create new user and clone privileges
                        logger.info(f"User '{new_username}' does not exist, creating new user")
                        cur.execute("CREATE USER %s@'%%' IDENTIFIED BY %s", (new_username, new_password))
                        
                        # Clone privileges from current user(APP_USER_1) to new user(APP_USER_2)
                        # Pass database name from secret for default privilege grant on initial setup
                        clone_user_privileges(cur, current_username, new_username, database)
                    
                    logger.info(f"Successfully set password for user '{new_username}'")
                
                conn.commit()
                conn.close()
                
                # Wait for password change to propagate in database (default: 5 seconds)
                wait_time = int(os.environ.get(ENV_DB_PASSWORD_PROPAGATION_WAIT, DEFAULT_DB_WAIT_TIME))
                logger.info(f"Waiting {wait_time} seconds for database password change to propagate...")
                time.sleep(wait_time)
                logger.info(f"Password propagation wait completed")
                
                # Log retry statistics on success
                if attempt > 0:
                    logger.info(f"Database operation succeeded after {attempt + 1} attempt(s). "
                              f"Previous failures were likely due to concurrent master rotation.")
                
                break  # Success - exit retry loop
                
            except (pymysql.MySQLError, ClientError) as e:
                attempt_num = attempt + 1
                
                # Check if error code 1045 (authentication error)
                # This may occur during concurrent master rotation
                is_auth_error = False
                if isinstance(e, pymysql.err.OperationalError) and e.args:
                    error_code = e.args[0]
                    if error_code == MYSQL_ERROR_ACCESS_DENIED:  # 1045
                        is_auth_error = True
                
                # Last attempt: Log error and raise exception
                if attempt_num == max_retries:
                    if is_auth_error:
                        logger.error(f"Authentication failed after {max_retries} attempts. "
                                   f"Master credentials may be rotating concurrently. Error: {str(e)}")
                    else:
                        logger.error(f"Database error after {max_retries} attempts: {str(e)}")
                    raise
                
                # Not the last attempt: Wait and retry
                else:
                    if is_auth_error:
                        # Use INFO level for early attempts during concurrent rotation (expected), WARNING for later attempts (unexpected)
                        if master_rotation_in_progress and attempt_num <= 3:
                            logger.info(f"Authentication failed on attempt {attempt_num}/{max_retries} during concurrent master rotation (expected). "
                                      f"Retrying in {retry_delay} seconds...")
                        else:
                            logger.warning(f"Authentication failed on attempt {attempt_num}/{max_retries}. "
                                         f"This may be caused by concurrent master rotation. "
                                         f"Will retry with fresh master credentials in {retry_delay} seconds...")
                    else:
                        # Retry for other database errors
                        logger.warning(f"Database error on attempt {attempt_num}/{max_retries}: {str(e)}. "
                                     f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, 30)  # Exponential backoff (max 30s)
        
        logger.info(f"App user password set successfully for '{new_username}'")
        
    except Exception as e:
        logger.error(f"Error in set_secret for app: {str(e)}")
        raise

def test_secret(service_client: BaseClient, arn: str, token: str) -> None:
    """
    Purpose:
        Verify that the new app user password (AWSPENDING) can successfully connect to the database.

    Flow Summary:
        1. Get pending secret from Secrets Manager.
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
        the database password update. Authentication errors (code 1045) may occur during
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
        
        logger.info(f"Testing connection with new app password for user {username} for secret {arn}")
        
        # Retry configuration for database password propagation
        max_retries = int(os.environ.get(ENV_DB_CONNECTION_TEST_RETRIES, DEFAULT_CONNECTION_RETRIES))
        retry_delay = int(os.environ.get(ENV_DB_CONNECTION_TEST_RETRY_DELAY, DEFAULT_RETRY_DELAY))
        
        last_exception = None
        # Python's range(start, stop) generates numbers from start to stop-1
        for attempt in range(1, max_retries + 1):
            try:
                # Test database connection with new password using test_database_connection function()
                test_database_connection(host, port, username, password)
                logger.info(f"Successfully connected with new app password for user {username} for secret {arn}")
                logger.info(f"App secret tested successfully for {arn}")
                return  # Success - exit function
                
            except pymysql.err.OperationalError as e:
                last_exception = e
                error_code = e.args[0] if e.args else None
                
                # Retry if authentication error (1045) occurs and it's not the last attempt
                if error_code == MYSQL_ERROR_ACCESS_DENIED and attempt < max_retries:
                    # Write a warning to the log, then wait and retry
                    logger.warning(f"Authentication failed on attempt {attempt}/{max_retries}. "
                                 f"Database password may still be propagating. Waiting {retry_delay} seconds before retry...")
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
        logger.error(f"Error in test_secret for app {arn}: {str(e)}")
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
        
        logger.info(f"App secret rotation completed successfully for {arn}")
        logger.info("Applications will now use the new user credentials on next connection")
        
    except Exception as e:
        logger.error(f"Error in finish_secret for app {arn}: {str(e)}")
        raise

# ============================================================================
# Helper Functions
# ============================================================================
# Core utilities used by rotation steps above
#
# Functions:
#   - get_secret(): Get secret value from Secrets Manager
#   - create_new_secret_value(): Alternate username and generate password
#   - get_random_password(): Generate secure password via AWS API
#   - get_master_secret_with_fallback(): Handle concurrent master rotation
#   - create_tls_connection(): Create SSL/TLS database connection
#   - user_exists(): Check if database user exists
#   - clone_user_privileges(): Copy all privileges between users
#   - should_skip_grant(): Filter default/empty grants
#   - parse_grant_statement(): Parse GRANT syntax with regex
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
                "username": "hamasoron1",
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
        Create a new secret dictionary by alternating username and generating new password.

    Flow Summary:
        1. Validate that 'password' field exists in current secret.
        2. Create a copy of the current secret dictionary.
        3. Get user names from environment variables.
        4. Determine which user to alternate to (APP_USER_1 ↔ APP_USER_2).
        5. Generate new password using get_random_password().
        6. Return new secret dictionary.

    Args:
        service_client (BaseClient): Boto3 Secrets Manager client
        current_secret (dict): Current secret dictionary from Secrets Manager

    Environment Variables:
        APP_USER_1: First application user name (required)
        APP_USER_2: Second application user name (required)

    Returns:
        dict: New secret with alternated username and new password
            Example: {
                "engine": "mysql",
                "host": "cluster.region.rds.amazonaws.com",
                "port": 3306,
                "username": "myapp_user_2",  # ← Alternated from myapp_user_1
                "password": "NEW_RANDOM_PASSWORD",  # ← Updated
                "dbClusterIdentifier": "my-cluster"
            }

    Raises:
        KeyError: If 'password' field is missing in current_secret

    References:
        https://docs.aws.amazon.com/ja_jp/secretsmanager/latest/userguide/reference_secret_json_structure.html

    Example Rotation Cycle:
        1st rotation:
            Current: {"username": "myapp_user_1", "password": "pass1", ...}
            New:     {"username": "myapp_user_2", "password": "pass2", ...}
        
        2nd rotation:
            Current: {"username": "myapp_user_2", "password": "pass2", ...}
            New:     {"username": "myapp_user_1", "password": "pass3", ...}

    Note:
        All other fields (engine, host, port, dbClusterIdentifier, etc.)
        are preserved as-is. Only username and password are changed.
    """

    # Validate that password field exists
    if 'password' not in current_secret:
        raise KeyError("The 'password' field is required in current_secret")

    # Copy the current secret
    new_secret = current_secret.copy()
    
    # Extract username from AWSCURRENT secret value
    current_username = current_secret.get('username', '')
    
    # Get user names from environment variables (required)
    try:
        user1 = os.environ[ENV_APP_USER_1]
        user2 = os.environ[ENV_APP_USER_2]
    except KeyError as e:
        error_msg = (f"Required environment variable not set: {str(e)}. "
                    f"Please set {ENV_APP_USER_1} and {ENV_APP_USER_2} in Lambda configuration.")
        logger.error(error_msg)
        raise ValueError(error_msg)
    
    logger.info(f"Multi-user rotation strategy configured: {user1} ↔ {user2}")
    
    # Alternate between user1 and user2
    if current_username == user1:
        new_secret['username'] = user2
        logger.info(f"Alternating username from {user1} to {user2}")
    else:
        new_secret['username'] = user1
        logger.info(f"Alternating username from {user2} to {user1}")
    
    # Generate new password using get_random_password function()
    new_secret['password'] = get_random_password(service_client)
    logger.info(f"Generated new password for {new_secret['username']}")
    
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

def get_master_secret_with_fallback(
    service_client: BaseClient, 
    master_secret_arn: str, 
    retry_attempt: int = 0
) -> Dict[str, Any]:
    """
    Purpose:
        Get master user credentials with fallback logic.

    Flow Summary:
        1. Try to get AWSPENDING secret value of master user first.
        2. If AWSPENDING secret value not found, fall back to AWSCURRENT secret value.
        3. Return master credentials dictionary.

    Args:
        service_client (BaseClient): Boto3 Secrets Manager client
        master_secret_arn (str): ARN of master secret
        retry_attempt (int): Current retry attempt number (for logging)

    Concurrent Rotation Strategy:
        This function enables app rotation to continue even during master rotation:
        - If master rotation is in progress: Uses AWSPENDING (new master password)
        - If no master rotation: Uses AWSCURRENT (current master password)
        - Called on each retry attempt to adapt to master state changes

    Returns:
        dict: Master user credentials
            Example: {
                "username": "master",
                "password": "master_password",
                "host": "cluster.region.rds.amazonaws.com",
                "port": 3306
            }

    Raises:
        ClientError: If master user credentials retrieval fails
        Exception: For unexpected errors
    """

    try:
        # Try AWSPENDING secret value first (master rotation in progress)
        try:
            master_secret = get_secret(service_client, master_secret_arn, version_stage=VERSION_STAGE_PENDING)
            logger.info(f"Got AWSPENDING secret value of master user (master rotation in progress) [attempt {retry_attempt + 1}]")
            return master_secret
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                # AWSPENDING secret value not found - no master rotation in progress, fall back to AWSCURRENT secret value
                logger.info(f"AWSPENDING secret value not found, using AWSCURRENT secret value (normal operation) [attempt {retry_attempt + 1}]")
                master_secret = get_secret(service_client, master_secret_arn, version_stage=VERSION_STAGE_CURRENT)
                return master_secret
            else:
                raise
    except Exception as e:
        logger.error(f"Error retrieving master user credentials: {str(e)}")
        raise

def create_tls_connection(host: str, port: int, username: str, password: str) -> pymysql.Connection:
    """
    Purpose:
        Create a database connection with SSL/TLS encryption.
        
    Flow Summary:
        1. Check for RDS CA bundle path in environment variables.
        2. Configure SSL/TLS parameters based on CA bundle availability.
        3. Establish encrypted connection to database.

    Args:
        host (str): Database host address (e.g., cluster.region.rds.amazonaws.com)
        port (int): Database port number (typically 3306 for MySQL)
        username (str): Database user name
        password (str): Database password

    Environment Variables:
        DB_CA_BUNDLE_PATH: Path to CA certificate bundle (optional)

    SSL/TLS Configuration:
        - If DB_CA_BUNDLE_PATH is set and file exists:
          Uses explicit CA certificate with VERIFY_IDENTITY mode (full validation)
        - Otherwise:
          Uses system default CA certificates with certificate verification (recommended)

    Returns:
        pymysql.Connection: Established database connection with SSL/TLS

    Raises:
        pymysql.err.OperationalError: If connection fails
        pymysql.err.MySQLError: For other MySQL-related errors
        Exception: For unexpected errors

    References:
        https://pymysql.readthedocs.io/en/latest/modules/connections.html
        https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html
    """

    # Check if CA certificate bundle path is specified via environment variable
    ca_bundle_path = os.environ.get(ENV_DB_CA_BUNDLE_PATH)
    
    # Base connection parameters
    connection_params = {
        'host': host,
        'port': port,
        'user': username,
        'password': password,
        'connect_timeout': DEFAULT_CONNECTION_TIMEOUT,
        'read_timeout': DEFAULT_CONNECTION_TIMEOUT,
        'write_timeout': DEFAULT_CONNECTION_TIMEOUT,
        'ssl_disabled': False,  # Enable SSL/TLS
        'ssl_verify_cert': True,  # Verify server certificate
        'ssl_verify_identity': True  # Verify hostname matches certificate
    }
    
    # Two SSL/TLS connection modes based on CA certificate availability
    # Mode 1: Use explicit CA certificate path (custom CA or specific AWS RDS CA bundle version)
    #         Set DB_CA_BUNDLE_PATH environment variable to specify certificate path
    #         Typical use case: Private CA, corporate CA, or certificate version control
    if ca_bundle_path and os.path.exists(ca_bundle_path):
        logger.info(f"Using SSL with explicit CA bundle: {ca_bundle_path}")
        connection_params['ssl_ca'] = ca_bundle_path
    # Mode 2: Use system default CA certificates (includes AWS RDS CA bundle)
    #         Recommended for standard AWS environments - no configuration needed
    else:
        logger.info("Using SSL with system default CA certificates")
    
    return pymysql.connect(**connection_params)

def user_exists(cursor: Any, username: str) -> bool:
    """
    Purpose:
        Check if a database user exists in the MySQL user table.

    Flow Summary:
        1. Execute SELECT COUNT query on mysql.user table.
        2. Check if count is greater than 0.
        3. Return True if user exists, False otherwise.

    Args:
        cursor: Database cursor object (pymysql cursor)
        username (str): Username to check

    Returns:
        bool: True if user exists, False otherwise

    Raises:
        Exception: If database query fails

    References:
        https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotation-strategy.html
    """

    try:
        cursor.execute("SELECT COUNT(*) FROM mysql.user WHERE user = %s", (username,))
        result = cursor.fetchone()
        exists = result[0] > 0
        logger.info(f"User '{username}' exists: {exists}")
        return exists
    except Exception as e:
        logger.error(f"Error checking if user '{username}' exists: {str(e)}")
        raise

def clone_user_privileges(cursor: Any, source_username: str, target_username: str, database_name: Optional[str] = None) -> None:
    """
    Purpose:
        Copy all privileges from source user to target user.
        If source user doesn't exist (initial setup), apply default privileges (SELECT,INSERT,UPDATE,DELETE).

    Flow Summary:
        1. Get all GRANT statements for source user using SHOW GRANTS
        2. Parse each GRANT statement
        3. Build new GRANT statement for target user
        4. Execute new GRANT statement for target user
    
    Initial Setup Handling:
        On first rotation, source user doesn't exist in database yet.
        
        Example Timeline:
            Assuming APP_USER_1 = "hamasoron1", APP_USER_2 = "hamasoron2"

            1st rotation (hamasoron1 → hamasoron2):
                - source_username = 'hamasoron1' (doesn't exist in DB)
                - target_username = 'hamasoron2' (being created)
                - Result: Apply default privileges (source user not found)
            
            2nd rotation (hamasoron2 → hamasoron1):
                - source_username = 'hamasoron2' (exists in DB)
                - target_username = 'hamasoron1' (being created)
                - Result: Clone privileges from hamasoron2 to hamasoron1
            
            3rd+ rotations: Both users exist, no privilege cloning needed (only password updates)
    
    Args:
        cursor: Database cursor object (pymysql cursor)
        source_username (str): Source username to copy privileges from
        target_username (str): Target username to grant privileges to
        database_name (str, optional): Database name for default privilege grant.
                                       Used when source user doesn't exist (initial setup).
                                       Should be obtained from app secret's 'database' field.
    
    Returns:
        None
    
    Raises:
        Exception: If privilege cloning fails (except for source user not found during initial setup)
    """
    
    # Clone all privileges from source user to target user
    try:
        logger.info(f"Cloning privileges from '{source_username}' to '{target_username}'")
        
        # Get all GRANT statements for source user (only host '%' is supported)
        cursor.execute("SHOW GRANTS FOR %s@'%%'", (source_username,))
        grants = cursor.fetchall()
        
        if not grants:
            logger.warning(f"No grants found for user '{source_username}'")
            return
        
        # Parse each GRANT statement and apply to the target user
        for grant in grants:
            grant_statement = grant[0]
            logger.debug(f"Processing grant statement: {grant_statement}")
            
            # Skip default GRANT statements that don't need cloning (GRANT USAGE ON *.*) using should_skip_grant()
            if should_skip_grant(grant_statement):
                logger.debug(f"Skipping USAGE grant (default privilege): {grant_statement}")
                continue # Skip processing this grant and move to next grant_statement 
            
            # Parse the GRANT statement with regex (regular expression) using parse_grant_statement()
            parsed = parse_grant_statement(grant_statement)
            
            # Raise error if parse failed
            if not parsed:
                error_msg = f"Failed to parse GRANT statement: {grant_statement}"
                logger.error(error_msg)
                raise ValueError(error_msg)
            
            # Build new GRANT statement for target user
            target_grant = f"{parsed['grant_clause']} TO '{target_username}'@'{parsed['hostname']}'"
            if parsed['additional_clauses']:
                target_grant = f"{target_grant} {parsed['additional_clauses']}"
            
            logger.info(f"Applying grant: {target_grant}")
            # Execute new GRANT statement for target user
            cursor.execute(target_grant)
        
        logger.info(f"Successfully cloned all privileges from '{source_username}' to '{target_username}'")
        
    except Exception as e:
        # Handle initial setup: source user doesn't exist yet
        error_message = str(e)
        
        # MySQL error 1141: "There is no such grant defined for user 'X' on hostname 'Y'"
        # This occurs on first rotation when source user doesn't exist in database
        if "There is no such grant defined" in error_message or "1141" in error_message:
            logger.warning(f"Source user '{source_username}' does not exist in database. This appears to be initial setup.")
            logger.info(f"Applying default privileges to '{target_username}' instead of cloning from non-existent user")
            
            # Validate that database_name is provided from secret
            if not database_name:
                raise ValueError("database_name is required for initial privilege setup. "
                               "Please ensure the 'database' field is set in the secret.")
            
            target_database = database_name
            default_privileges = DEFAULT_APP_PRIVILEGES
            
            # Apply default privileges to target user
            grant_sql = f"GRANT {default_privileges} ON {target_database}.* TO %s@'%%'"
            logger.info(f"Executing default grant: {grant_sql.replace('%s', repr(target_username))}")
            cursor.execute(grant_sql, (target_username,))
            
            # Flush privileges to ensure changes take effect immediately
            cursor.execute("FLUSH PRIVILEGES")
            
            logger.info(f"Successfully applied default privileges ({default_privileges}) to '{target_username}' on database '{target_database}'")
            logger.warning(f"Note: Default privileges were used for initial setup. "
                          f"Subsequent rotations will clone privileges from existing users.")
            
            return
        
        # For other errors, re-raise
        logger.error(f"Error cloning privileges: {error_message}")
        raise

def should_skip_grant(grant_statement: str) -> bool:
    """
    Purpose:
        Check if a GRANT statement is a default privilege (GRANT USAGE ON *.*).

    Args:
        grant_statement (str): The GRANT statement to check

    Returns:
        bool: True if should skip, False otherwise

    Note:
        GRANT USAGE ON *.* is a default privilege with no permissions.
        It's automatically granted when a user is created and doesn't need cloning.
    """

    # Skip GRANT USAGE ON *.* (default privilege with no real permissions)
    return "GRANT USAGE ON *.*" in grant_statement.upper()

def parse_grant_statement(grant_statement: str) -> Optional[Dict[str, str]]:
    """
    Purpose:
        Parse a GRANT statement using regex (regular expression).

    Args:
        grant_statement (str): The GRANT statement to parse

    Returns:
        dict or None: Dictionary with keys 'grant_clause', 'username', 'hostname', 'additional_clauses'
                      Returns None if parsing fails

    Regex Pattern:
        - (GRANT .+?): Capture the GRANT clause
        - \\s+TO\\s+: Match the TO keyword
        - ['"`]?(\\w+)['"`]?: Capture username
        - @: Match the @ separator
        - ['"`]([^'"`]+)['"`]?: Capture hostname
        - (.*?)(?:;)?: Capture the additional clauses

    Example:
        Input: "GRANT SELECT ON mydb.* TO 'hamasoron1'@'localhost' WITH GRANT OPTION"
        Output: {
            'grant_clause': 'GRANT SELECT ON mydb.*',
            'username': 'hamasoron1',
            'hostname': 'localhost',
            'additional_clauses': 'WITH GRANT OPTION'
        }
    """

    import re
    
    pattern = r"(GRANT .+?)\s+TO\s+['\"]?(\w+)['\"]?@['\"]?([^'\"]+)['\"]?(.*?)(?:;)?$"
    match = re.match(pattern, grant_statement, re.IGNORECASE)
    
    if not match:
        return None
    
    return {
        'grant_clause': match.group(1).strip(),
        'username': match.group(2).strip(),
        'hostname': match.group(3).strip(),
        'additional_clauses': match.group(4).strip() # Special case only
    }

def test_database_connection(host: str, port: int, username: str, password: str) -> bool:
    """
    Purpose:
        Test database connection with provided credentials using SSL/TLS encryption.

    Flow Summary:
        1. Validate required parameters (host, port, username, password).
        2. Establish SSL/TLS connection using create_tls_connection().
        3. Execute simple query (SELECT 1) to verify connection.
        4. Close connection and return success.

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
    
    try:
        # Establish connection using helper function
        with create_tls_connection(host, port, username, password) as conn:
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