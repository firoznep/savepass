const { Client } = require("pg");
const fs = require("fs");
const path = require("path");

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) {
    return;
  }

  const envFile = fs.readFileSync(filePath, "utf8");
  for (const line of envFile.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }

    const separatorIndex = trimmed.indexOf("=");
    if (separatorIndex === -1) {
      continue;
    }

    const key = trimmed.slice(0, separatorIndex).trim();
    const rawValue = trimmed.slice(separatorIndex + 1).trim();
    const value = rawValue.replace(/^['"]|['"]$/g, "");

    if (!process.env[key]) {
      process.env[key] = value;
    }
  }
}

function quoteIdentifier(identifier) {
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(identifier)) {
    throw new Error(`Invalid PostgreSQL identifier: ${identifier}`);
  }

  return `"${identifier.replace(/"/g, '""')}"`;
}

function getConfig(database) {
  return {
    host: process.env.DB_HOST || "127.0.0.1",
    port: parseInt(process.env.DB_PORT || "60700", 10),
    user: process.env.DB_USER || "postgres",
    password: process.env.DB_PASSWORD || "",
    database,
  };
}

function printAuthHelp(err) {
  const message = err && err.message ? err.message : "";
  if (
    err.code === "28000" ||
    message.includes("Ident authentication failed") ||
    message.includes("Peer authentication failed")
  ) {
    console.error("");
    console.error("PostgreSQL rejected the configured user via Ident/peer auth.");
    console.error(
      "Your app is using DB_HOST=%s DB_PORT=%s DB_USER=%s DB_NAME=%s.",
      process.env.DB_HOST || "127.0.0.1",
      process.env.DB_PORT || "60700",
      process.env.DB_USER || "postgres",
      process.env.DB_NAME || "safepass",
    );
    console.error("");
    console.error("For local development, enable password auth for local TCP connections,");
    console.error("then set a password on the role and put the same value in .env.local:");
    console.error("  # In pg_hba.conf, use scram-sha-256 or md5 for 127.0.0.1/32");
    console.error("  # Example: host all all 127.0.0.1/32 scram-sha-256");
    console.error("  sudo systemctl reload postgresql");
    console.error("  sudo -u postgres psql -c \"ALTER USER postgres PASSWORD 'postgres';\"");
    console.error("  DB_PASSWORD=postgres");
    console.error("");
    console.error("Then restart `next dev` so the pool picks up the new env value.");
  }
}

async function init() {
  try {
    loadEnvFile(path.join(__dirname, "..", ".env.local"));

    const databaseName = process.env.DB_NAME || "safepass";
    const adminClient = new Client(getConfig("postgres"));

    console.log(
      "Connecting to PostgreSQL on %s:%s as '%s'...",
      process.env.DB_HOST || "127.0.0.1",
      process.env.DB_PORT || "60700",
      process.env.DB_USER || "postgres",
    );
    await adminClient.connect();

    // Check if the application database exists.
    const dbCheck = await adminClient.query(
      "SELECT 1 FROM pg_database WHERE datname = $1",
      [databaseName],
    );
    if (dbCheck.rowCount === 0) {
      console.log(`Database '${databaseName}' does not exist. Creating it...`);
      // CREATE DATABASE cannot run inside a transaction block, so we execute it directly
      await adminClient.query(`CREATE DATABASE ${quoteIdentifier(databaseName)}`);
      console.log(`Database '${databaseName}' created successfully!`);
    } else {
      console.log(`Database '${databaseName}' already exists.`);
    }
    await adminClient.end();

    // Now connect to the application database and run the schema SQL.
    console.log(`Connecting to '${databaseName}' database to apply schema...`);
    const appClient = new Client(getConfig(databaseName));

    await appClient.connect();

    const schemaPath = path.join(__dirname, "..", "db", "schema.sql");
    const schemaSql = fs.readFileSync(schemaPath, "utf8");

    console.log("Executing schema.sql...");
    await appClient.query(schemaSql);
    console.log(
      "Schema applied successfully! All tables and indexes are ready.",
    );

    await appClient.end();
    console.log("PostgreSQL setup completed successfully!");
  } catch (err) {
    printAuthHelp(err);
    console.error("Database initialization failed:", err);
    process.exit(1);
  }
}

init();
