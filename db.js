
const { Pool } = require('pg');


const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
   
    ssl: {
        rejectUnauthorized: false
    }
});

pool.query('SELECT NOW()', (err, res) => {
    if (err) {
        console.error('Error connecting to the PostgreSQL database:', err);
    } else {
        console.log('Successfully connected to PostgreSQL database!');
    }
});

module.exports = pool;