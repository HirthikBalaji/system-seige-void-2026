import os
import sys
import urllib.request
import zipfile
import subprocess
import time

# Portable PostgreSQL for Windows (64-bit)
PG_VERSION = "16.1-1"
PG_URL = f"https://get.enterprisedb.com/postgresql/postgresql-{PG_VERSION}-windows-x64-binaries.zip"
PG_DIR = os.path.abspath("pgsql")
DATA_DIR = os.path.abspath("pg_data")

def download_and_extract():
    if os.path.exists(PG_DIR):
        print("[+] PostgreSQL directory already exists.")
        return

    zip_file = "postgresql.zip"
    print(f"[*] Downloading PostgreSQL {PG_VERSION}...")
    try:
        urllib.request.urlretrieve(PG_URL, zip_file)
        print("[+] Download complete.")
    except Exception as e:
        print(f"[-] Download failed: {e}")
        sys.exit(1)

    print("[*] Extracting binaries...")
    try:
        with zipfile.ZipFile(zip_file, 'r') as zip_ref:
            zip_ref.extractall(".")
        print("[+] Extraction complete.")
    except Exception as e:
        print(f"[-] Extraction failed: {e}")
        sys.exit(1)
    finally:
        if os.path.exists(zip_file):
            os.remove(zip_file)

def init_db():
    if os.path.exists(DATA_DIR):
        print("[+] Data directory already exists.")
        return

    initdb_bin = os.path.join(PG_DIR, "bin", "initdb.exe")
    print("[*] Initializing Database cluster...")
    try:
        # Run initdb to set up database cluster with UTF8 encoding
        subprocess.run([
            initdb_bin,
            "-D", DATA_DIR,
            "-U", "postgres",
            "--auth-local=trust",
            "--auth-host=trust",
            "-E", "UTF8"
        ], check=True)
        print("[+] Database cluster initialized successfully.")
    except Exception as e:
        print(f"[-] initdb failed: {e}")
        sys.exit(1)

def start_postgres():
    pg_ctl_bin = os.path.join(PG_DIR, "bin", "pg_ctl.exe")
    print("[*] Starting PostgreSQL server on localhost:5433...")
    
    # Write custom pg_hba.conf to allow trust authentication on localhost
    hba_path = os.path.join(DATA_DIR, "pg_hba.conf")
    with open(hba_path, "w") as f:
        f.write("# TYPE  DATABASE        USER            ADDRESS                 METHOD\n")
        f.write("local   all             all                                     trust\n")
        f.write("host    all             all             127.0.0.1/32            trust\n")
        f.write("host    all             all             ::1/128                 trust\n")

    try:
        # Start server as a background process using pg_ctl
        cmd = [pg_ctl_bin, "-D", DATA_DIR, "-o", "-p 5433", "start"]
        subprocess.run(cmd, check=True)
        print("[+] PostgreSQL started successfully.")
        time.sleep(3)
    except Exception as e:
        print(f"[-] pg_ctl failed to start: {e}")
        sys.exit(1)

def create_users_and_db():
    psql_bin = os.path.join(PG_DIR, "bin", "psql.exe")
    print("[*] Creating roles and database for secrets platform...")
    
    commands = [
        "DROP DATABASE IF EXISTS secrets_platform;",
        "DROP ROLE IF EXISTS platform_owner;",
        "DROP ROLE IF EXISTS app_user;",
        "CREATE ROLE platform_owner WITH LOGIN PASSWORD 'postgresownerpass123!';",
        "CREATE ROLE app_user WITH LOGIN PASSWORD 'postgresapppass123!';",
        "ALTER ROLE platform_owner CREATEDB;",
        "CREATE DATABASE secrets_platform OWNER platform_owner;",
        "GRANT CONNECT ON DATABASE secrets_platform TO app_user;"
    ]
    
    for cmd in commands:
        try:
            subprocess.run([
                psql_bin,
                "-U", "postgres",
                "-h", "localhost",
                "-p", "5433",
                "-d", "postgres",
                "-c", cmd
            ], check=True)
        except Exception as e:
            print(f"[-] Failed executing command ({cmd}): {e}")
            sys.exit(1)
            
    print("[+] Users and secrets_platform database successfully provisioned!")

if __name__ == "__main__":
    download_and_extract()
    init_db()
    start_postgres()
    create_users_and_db()
