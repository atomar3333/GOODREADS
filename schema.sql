-- schema.sql
-- This file defines the database schema for the Goodreads clone.

DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS books;
-- Add more tables here as the application grows (e.g., reviews, shelves, etc.)

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);

CREATE TABLE books (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL, -- The ID of the user who added the book
    title TEXT NOT NULL,
    author TEXT NOT NULL,
    genre TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
