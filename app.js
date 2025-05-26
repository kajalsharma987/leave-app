// Load environment variables from .env file
require('dotenv').config(); // <-- This modification (if .env is in parent folder of app.js, this is correct;
                             // if app.js and .env are in the same folder, it would be path: '.env')

const express = require('express');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const pool = require('./db'); // Your PostgreSQL database connection pool
const cors = require('cors'); // For CORS (Cross-Origin Resource Sharing)

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

// Configure CORS
// This is necessary if your frontend and backend are on different domains or ports
// For development, you can allow all origins: { origin: '*' }
// In production, you should allow specific frontend URLs
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000', // <-- Keep this as is!
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}));

app.use(express.json()); // Middleware to parse JSON bodies

// // Serve static files from the 'public' folder - This line was removed (as frontend will be deployed separately)
// app.use(express.static(path.join(__dirname, '../public')));

// This function creates tables in the database and inserts a default admin user
// It should be called only once when the application starts
async function createTablesAndAdmin() {
    try {
        // Create Users table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(50) NOT NULL,
                createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // Create Leave Applications table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS leave_applications (
                id SERIAL PRIMARY KEY,
                applicant_id INTEGER NOT NULL,
                applicant_name VARCHAR(255) NOT NULL,
                applicant_role VARCHAR(50) NOT NULL,
                leave_type VARCHAR(50) NOT NULL,
                start_date DATE NOT NULL,
                end_date DATE NOT NULL,
                reason TEXT NOT NULL,
                status VARCHAR(50) DEFAULT 'Pending',
                submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                approver_id INTEGER,
                approver_name VARCHAR(255),
                approved_at TIMESTAMP,
                approver_remarks TEXT,
                FOREIGN KEY (applicant_id) REFERENCES users(id)
            );
        `);
        console.log('Tables created successfully or already exist.');

        // Create default admin user if not exists
        const adminExists = await pool.query("SELECT * FROM users WHERE email = 'admin@example.com'");
        if (adminExists.rows.length === 0) {
            const hashedPassword = await bcrypt.hash('admin123', 10); // Replace 'admin123' with a stronger password
            await pool.query(
                `INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4)`,
                ['Admin User', 'admin@example.com', hashedPassword, 'admin']
            );
            console.log('Default admin user created: admin@example.com / admin123');
        }
    } catch (err) {
        console.error('Error creating tables or default admin:', err);
    }
}

// Call this function to create tables and insert admin user when application starts
createTablesAndAdmin();

// --- Middleware for Authentication and Authorization ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) return res.status(401).json({ message: 'Authentication token required' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid or expired token' });
        req.user = user; // user payload includes { id, name, email, role }
        next();
    });
};

const authorizeRoles = (roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Forbidden: You do not have the required role' });
        }
        next();
    };
};

// --- API Endpoints ---

// User Registration
app.post('/api/register', async (req, res) => {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password || !role) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    if (!['student', 'teacher', 'admin'].includes(role)) {
        return res.status(400).json({ message: 'Invalid role specified.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4) RETURNING id',
            [name, email, hashedPassword, role]
        );
        res.status(201).json({ message: 'User registered successfully!', userId: result.rows[0].id });
    } catch (error) {
        console.error("Database error during registration:", error.message);
        if (error.code === '23505') { // PostgreSQL unique_violation error code
            return res.status(409).json({ message: 'This email is already registered.' });
        }
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

// User Login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }

    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password.' }); // Changed from Hindi
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid email or password.' }); // Changed from Hindi
        }

        // Generate JWT token
        const token = jwt.sign(
            { id: user.id, name: user.name, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '1h' } // Token expires in 1 hour
        );

        res.status(200).json({
            message: 'Login successful',
            token: token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        console.error("Database error during login:", error.message);
        res.status(500).json({ message: 'Internal server error.' }); // Changed from Hindi
    }
});

// Apply for Leave
app.post('/api/leaves', authenticateToken, async (req, res) => {
    const { leaveType, startDate, endDate, reason } = req.body;
    const { id: applicantId, name: applicantName, role: applicantRole } = req.user;

    if (!leaveType || !startDate || !endDate || !reason) {
        return res.status(400).json({ message: 'All leave fields are required.' });
    }
    if (new Date(startDate) > new Date(endDate)) {
        return res.status(400).json({ message: 'Start date cannot be after end date.' });
    }

    try {
        const result = await pool.query(
            `INSERT INTO leave_applications (applicant_id, applicant_name, applicant_role, leave_type, start_date, end_date, reason, status, submitted_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW()) RETURNING id`, // NOW() for current timestamp in PostgreSQL
            [applicantId, applicantName, applicantRole, leaveType, startDate, endDate, reason, 'Pending']
        );
        res.status(201).json({ message: 'Leave application submitted successfully!', leaveId: result.rows[0].id });
    } catch (error) {
        console.error("Database error submitting leave:", error.message);
        res.status(500).json({ message: 'Failed to submit leave application.' });
    }
});

// View user's own leaves
app.get('/api/leaves/my', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    try {
        const result = await pool.query(
            'SELECT * FROM leave_applications WHERE applicant_id = $1 ORDER BY submitted_at DESC',
            [userId]
        );
        res.status(200).json(result.rows);
    } catch (error) {
        console.error("Database error fetching my leaves:", error.message);
        res.status(500).json({ message: 'Failed to fetch your leave applications.' });
    }
});

// Get pending approvals (for teachers and admins)
app.get('/api/leaves/pending', authenticateToken, authorizeRoles(['teacher', 'admin']), async (req, res) => {
    const userRole = req.user.role;
    let queryText = 'SELECT * FROM leave_applications WHERE status = $1';
    let params = ['Pending'];

    if (userRole === 'teacher') {
        queryText += ' AND applicant_role = $2';
        params.push('student');
    }
    queryText += ' ORDER BY submitted_at ASC';

    try {
        const result = await pool.query(queryText, params);
        res.status(200).json(result.rows);
    } catch (error) {
        console.error("Database error fetching pending leaves:", error.message);
        res.status(500).json({ message: 'Failed to fetch pending leave applications.' });
    }
});

// Approve/Reject Leave (for teachers and admins)
app.put('/api/leaves/:id/status', authenticateToken, authorizeRoles(['teacher', 'admin']), async (req, res) => {
    const leaveId = req.params.id;
    const { status, approverRemarks } = req.body;
    const { id: approverId, name: approverName, role: approverRole } = req.user;

    if (!['Approved', 'Rejected'].includes(status)) {
        return res.status(400).json({ message: 'Invalid status provided.' });
    }

    try {
        const leaveResult = await pool.query('SELECT * FROM leave_applications WHERE id = $1', [leaveId]);
        const leave = leaveResult.rows[0];

        if (!leave) {
            return res.status(404).json({ message: 'Leave application not found.' });
        }
        if (leave.status !== 'Pending') {
            return res.status(400).json({ message: 'Leave is not in Pending status.' });
        }

        // Authorization check for teacher role
        if (approverRole === 'teacher' && leave.applicant_role !== 'student') {
            return res.status(403).json({ message: 'Teachers can only approve/reject student leaves.' });
        }

        const updateResult = await pool.query(
            `UPDATE leave_applications SET
                status = $1,
                approver_id = $2,
                approver_name = $3,
                approved_at = NOW(),
                approver_remarks = $4
             WHERE id = $5 RETURNING id`,
            [status, approverId, approverName, approverRemarks, leaveId]
        );

        if (updateResult.rowCount === 0) {
            return res.status(404).json({ message: 'Leave application not found or no changes made.' });
        }
        res.status(200).json({ message: `Leave successfully ${status.toLowerCase()}!` });
    } catch (error) {
        console.error(`Database error while setting leave status to ${status}:`, error.message);
        res.status(500).json({ message: `Failed to set leave status to ${status}: ${error.message}` });
    }
});

// // Catch-all to serve index.html for SPA routing - This line was removed
// app.get('*', (req, res) => {
//     res.sendFile(path.join(__dirname, '../public', 'index.html'));
// });

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
