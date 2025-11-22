# Database Setup Guide

This guide will help you set up a PostgreSQL database for the AskMe server.

## Option 1: Local PostgreSQL

### Install PostgreSQL

**macOS (using Homebrew):**
```bash
brew install postgresql@15
brew services start postgresql@15
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
```

**Windows:**
Download and install from [PostgreSQL official website](https://www.postgresql.org/download/windows/)

### Create Database

1. Connect to PostgreSQL:
```bash
psql postgres
```

2. Create a new database:
```sql
CREATE DATABASE askme_db;
```

3. Create a user (optional, or use your existing user):
```sql
CREATE USER askme_user WITH PASSWORD 'your_password_here';
GRANT ALL PRIVILEGES ON DATABASE askme_db TO askme_user;
```

4. Exit psql:
```sql
\q
```

### Set Environment Variable

Create a `.env` file in the project root:

```bash
DATABASE_URL="postgresql://askme_user:your_password_here@localhost:5432/askme_db?schema=public"
```

Or if using default postgres user:
```bash
DATABASE_URL="postgresql://postgres:your_password@localhost:5432/askme_db?schema=public"
```

## Option 2: Cloud Database (Recommended for Hackathon)

### Using Neon (Free Tier)

1. Go to [Neon](https://neon.tech) and sign up
2. Create a new project
3. Copy the connection string (it will look like):
   ```
   postgresql://user:password@ep-xxx.us-east-2.aws.neon.tech/neondb?sslmode=require
   ```
4. Add it to your `.env` file:
   ```bash
   DATABASE_URL="your_neon_connection_string_here"
   ```

### Using Supabase (Free Tier)

1. Go to [Supabase](https://supabase.com) and create a project
2. Go to Project Settings > Database
3. Copy the connection string (use the "URI" format)
4. Add it to your `.env` file:
   ```bash
   DATABASE_URL="your_supabase_connection_string_here"
   ```

### Using Railway (Free Tier)

1. Go to [Railway](https://railway.app) and sign up
2. Create a new project
3. Add a PostgreSQL service
4. Copy the DATABASE_URL from the service variables
5. Add it to your `.env` file

## Initialize Database

Once you have your `DATABASE_URL` set in `.env`:

1. Install dependencies:
```bash
npm install
```

2. Generate Prisma Client:
```bash
npm run prisma:generate
```

3. Run your first migration:
```bash
npm run prisma:migrate
```

This will create the database tables based on your Prisma schema.

## Verify Setup

You can open Prisma Studio to view your database:
```bash
npm run prisma:studio
```

This will open a web interface at `http://localhost:5555` where you can view and edit your database.

## Troubleshooting

- **Connection refused**: Make sure PostgreSQL is running
- **Authentication failed**: Check your username and password in the DATABASE_URL
- **Database does not exist**: Make sure you created the database first
- **SSL required**: If using a cloud provider, make sure `?sslmode=require` is in your connection string

