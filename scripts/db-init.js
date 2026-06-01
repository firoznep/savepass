const { Client } = require("pg");
const fs = require("fs");
const path = require("path");

// .env.local example
// DB_HOST=127.0.0.1
// DB_PORT=60700
// DB_USER=postgres
// DB_PASSWORD=
// DB_NAME=safepass
// JWT_SECRET=safepass_jwt_secret_token_key_9988776655
// NODE_ENV=development

// We first connect to the default 'postgres' database to ensure the 'safepass' database exists.
// We will try ports 5432 and 5433 to find which one is active.
const ports = [60700, 5433, 5432];
const hosts = ["localhost", "127.0.0.1", "::1"];
const passwords = ["postgres", "", "password", "admin"];

async function findActiveConnection() {
  for (const port of ports) {
    for (const host of hosts) {
      for (const password of passwords) {
        console.log(
          `Testing connection to PostgreSQL on ${host}:${port} with user 'postgres' and password '${password}'...`,
        );
        const client = new Client({
          host: host,
          port: port,
          user: "postgres",
          password: password,
          database: "postgres",
        });

        try {
          await client.connect();
          console.log(
            `Successfully connected on ${host}:${port} with password '${password}'!`,
          );
          await client.end();
          return { host, port, password };
        } catch (err) {
          console.log(
            `Failed to connect on ${host}:${port} with password '${password}': ${err.message}`,
          );
        }
      }
    }
  }
  throw new Error(
    "Could not connect to PostgreSQL on any host/port/password combination. Please check if PostgreSQL is running.",
  );
}

async function init() {
  try {
    const { host, port, password } = await findActiveConnection();

    // Connect to postgres to create the database if not exists
    const adminClient = new Client({
      host: host,
      port: port,
      user: "postgres",
      password: password,
      database: "postgres",
    });

    await adminClient.connect();

    // Check if safepass database exists
    const dbCheck = await adminClient.query(
      "SELECT 1 FROM pg_database WHERE datname = 'safepass'",
    );
    if (dbCheck.rowCount === 0) {
      console.log("Database 'safepass' does not exist. Creating it...");
      // CREATE DATABASE cannot run inside a transaction block, so we execute it directly
      await adminClient.query("CREATE DATABASE safepass");
      console.log("Database 'safepass' created successfully!");
    } else {
      console.log("Database 'safepass' already exists.");
    }
    await adminClient.end();

    // Now connect to 'safepass' database and run the schema SQL
    console.log("Connecting to 'safepass' database to apply schema...");
    const appClient = new Client({
      host: host,
      port: port,
      user: "postgres",
      password: password,
      database: "safepass",
    });

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
    console.error("Database initialization failed:", err);
    process.exit(1);
  }
}

init();
