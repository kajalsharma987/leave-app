// पर्यावरण चर (environment variables) को लोड करें (.env फाइल से)
require('dotenv').config({ path: '../.env' });
const express = require('express');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const pool = require('./db'); // आपका PostgreSQL डेटाबेस कनेक्शन पूल
const cors = require('cors'); // CORS (Cross-Origin Resource Sharing) के लिए

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

// CORS को कॉन्फ़िगर करें
// यदि आपका फ्रंटएंड और बैकएंड अलग-अलग डोमेन या पोर्ट पर हैं तो यह आवश्यक है
// डेवलपमेंट के लिए, आप सभी ओरिजिन की अनुमति दे सकते हैं: { origin: '*' }
// प्रोडक्शन में, आपको विशिष्ट फ्रंटएंड URL को अनुमति देनी चाहिए
app.use(cors({
    origin: 'http://localhost:3000', // अपने फ्रंटएंड के URL से बदलें यदि यह अलग है
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}));

app.use(express.json()); // JSON बॉडी को पार्स करने के लिए मिडलवेयर
app.use(express.static(path.join(__dirname, '../public'))); // 'public' फोल्डर से स्टैटिक फाइलें सर्व करें

// यह फ़ंक्शन डेटाबेस में टेबल्स बनाता है और डिफ़ॉल्ट एडमिन यूजर डालता है
// इसे केवल एक बार एप्लिकेशन स्टार्ट होने पर कॉल किया जाना चाहिए
async function createTablesAndAdmin() {
    try {
        // Users टेबल बनाएं
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

        // Leave Applications टेबल बनाएं
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

        // डिफ़ॉल्ट एडमिन यूजर बनाएं यदि मौजूद न हो
        const adminExists = await pool.query("SELECT * FROM users WHERE email = 'admin@example.com'");
        if (adminExists.rows.length === 0) {
            const hashedPassword = await bcrypt.hash('admin123', 10); // 'admin123' को एक मजबूत पासवर्ड से बदलें
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

// एप्लिकेशन स्टार्ट होने पर टेबल्स बनाने और एडमिन यूजर डालने के लिए इस फ़ंक्शन को कॉल करें
createTablesAndAdmin();

// --- मिडलवेयर (Middleware) प्रमाणीकरण और प्राधिकरण के लिए ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) return res.status(401).json({ message: 'Authentication token required' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid or expired token' });
        req.user = user; // user पेलोड में { id, name, email, role } शामिल है
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

// --- API एंडपॉइंट्स (Endpoints) ---

// यूजर रजिस्ट्रेशन
app.post('/api/register', async (req, res) => {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password || !role) {
        return res.status(400).json({ message: 'सभी फ़ील्ड आवश्यक हैं।' });
    }

    if (!['student', 'teacher', 'admin'].includes(role)) {
        return res.status(400).json({ message: 'अमान्य भूमिका निर्दिष्ट की गई है।' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4) RETURNING id',
            [name, email, hashedPassword, role]
        );
        res.status(201).json({ message: 'उपयोगकर्ता सफलतापूर्वक पंजीकृत हुआ!', userId: result.rows[0].id });
    } catch (error) {
        console.error("पंजीकरण के दौरान डेटाबेस त्रुटि:", error.message);
        if (error.code === '23505') { // PostgreSQL unique_violation error code
            return res.status(409).json({ message: 'यह ईमेल पहले से पंजीकृत है।' });
        }
        res.status(500).json({ message: 'पंजीकरण के दौरान सर्वर त्रुटि।' });
    }
});

// यूजर लॉगिन
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'ईमेल और पासवर्ड आवश्यक हैं।' });
    }

    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user) {
            return res.status(401).json({ message: 'अमान्य क्रेडेंशियल।' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'अमान्य क्रेडेंशियल।' });
        }

        // JWT टोकन जेनरेट करें
        const token = jwt.sign(
            { id: user.id, name: user.name, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '1h' } // टोकन 1 घंटे में समाप्त हो जाता है
        );

        res.status(200).json({
            message: 'लॉगिन सफल रहा',
            token: token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        console.error("लॉगिन के दौरान डेटाबेस त्रुटि:", error.message);
        res.status(500).json({ message: 'आंतरिक सर्वर त्रुटि।' });
    }
});

// लीव के लिए आवेदन करें
app.post('/api/leaves', authenticateToken, async (req, res) => {
    const { leaveType, startDate, endDate, reason } = req.body;
    const { id: applicantId, name: applicantName, role: applicantRole } = req.user;

    if (!leaveType || !startDate || !endDate || !reason) {
        return res.status(400).json({ message: 'सभी लीव फ़ील्ड आवश्यक हैं।' });
    }
    if (new Date(startDate) > new Date(endDate)) {
        return res.status(400).json({ message: 'शुरू होने की तारीख समाप्त होने की तारीख के बाद नहीं हो सकती।' });
    }

    try {
        const result = await pool.query(
            `INSERT INTO leave_applications (applicant_id, applicant_name, applicant_role, leave_type, start_date, end_date, reason, status, submitted_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW()) RETURNING id`, // NOW() PostgreSQL में वर्तमान टाइमस्टैम्प के लिए
            [applicantId, applicantName, applicantRole, leaveType, startDate, endDate, reason, 'Pending']
        );
        res.status(201).json({ message: 'लीव आवेदन सफलतापूर्वक सबमिट हुआ!', leaveId: result.rows[0].id });
    } catch (error) {
        console.error("लीव सबमिट करने में डेटाबेस त्रुटि:", error.message);
        res.status(500).json({ message: 'लीव आवेदन सबमिट करने में विफल रहा।' });
    }
});

// उपयोगकर्ता की अपनी लीव देखें
app.get('/api/leaves/my', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    try {
        const result = await pool.query(
            'SELECT * FROM leave_applications WHERE applicant_id = $1 ORDER BY submitted_at DESC',
            [userId]
        );
        res.status(200).json(result.rows);
    } catch (error) {
        console.error("मेरी लीव लाने में डेटाबेस त्रुटि:", error.message);
        res.status(500).json({ message: 'आपके लीव आवेदन लाने में विफल रहा।' });
    }
});

// लंबित अनुमोदन प्राप्त करें (शिक्षकों और प्रशासकों के लिए)
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
        console.error("लंबित लीव लाने में डेटाबेस त्रुटि:", error.message);
        res.status(500).json({ message: 'लंबित लीव आवेदन लाने में विफल रहा।' });
    }
});

// लीव को स्वीकृत/अस्वीकृत करें (शिक्षकों और प्रशासकों के लिए)
app.put('/api/leaves/:id/status', authenticateToken, authorizeRoles(['teacher', 'admin']), async (req, res) => {
    const leaveId = req.params.id;
    const { status, approverRemarks } = req.body;
    const { id: approverId, name: approverName, role: approverRole } = req.user;

    if (!['Approved', 'Rejected'].includes(status)) {
        return res.status(400).json({ message: 'अमान्य स्थिति प्रदान की गई है।' });
    }

    try {
        const leaveResult = await pool.query('SELECT * FROM leave_applications WHERE id = $1', [leaveId]);
        const leave = leaveResult.rows[0];

        if (!leave) {
            return res.status(404).json({ message: 'लीव आवेदन नहीं मिला।' });
        }
        if (leave.status !== 'Pending') {
            return res.status(400).json({ message: 'लीव लंबित स्थिति में नहीं है।' });
        }

        // शिक्षक भूमिका के लिए प्राधिकरण जांच
        if (approverRole === 'teacher' && leave.applicant_role !== 'student') {
            return res.status(403).json({ message: 'शिक्षक केवल छात्र लीव को स्वीकृत/अस्वीकृत कर सकते हैं।' });
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
            return res.status(404).json({ message: 'लीव आवेदन नहीं मिला या कोई बदलाव नहीं किया गया।' });
        }
        res.status(200).json({ message: `लीव सफलतापूर्वक ${status} हुई!` });
    } catch (error) {
        console.error(`लीव की स्थिति ${status} करने में डेटाबेस त्रुटि:`, error.message);
        res.status(500).json({ message: `लीव की स्थिति ${status} करने में विफल रहा: ${error.message}` });
    }
});

// SPA रूटिंग के लिए index.html सर्व करने के लिए कैच-ऑल
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../public', 'index.html'));
});

// सर्वर शुरू करें
app.listen(PORT, () => {
    console.log(`सर्वर http://localhost:${PORT} पर चल रहा है`);
});