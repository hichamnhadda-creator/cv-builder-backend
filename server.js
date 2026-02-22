const express = require('express');
const cors = require('cors');
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 5000;

// Initialize Supabase client
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
);

// Middleware
const allowedOrigins = [
    'http://localhost:5173',
    'http://localhost:3000',
    'https://hichamnhadda-creator.github.io',
    process.env.FRONTEND_URL
].filter(Boolean);

const corsOptions = {
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
};

app.use(cors(corsOptions));
app.use(express.json());

// Auth Middleware
const verifyToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const { data: { user }, error } = await supabase.auth.getUser(token);

        if (error || !user) {
            return res.status(401).json({ error: 'Invalid token' });
        }

        req.user = user;
        next();
    } catch (err) {
        console.error('Token verification error:', err);
        return res.status(401).json({ error: 'Token verification failed' });
    }
};

// Routes
app.get('/', (req, res) => {
    res.json({
        message: 'CV Builder API is running',
        status: 'online',
        endpoints: {
            test: '/api/test',
            cvs: '/api/cvs'
        }
    });
});

app.get('/api/test', (req, res) => {
    res.send('Backend is working');
});

// CV Endpoints
app.get('/api/cvs', verifyToken, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('cvs')
            .select('*')
            .eq('user_id', req.user.id);

        if (error) throw error;
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/cvs', verifyToken, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('cvs')
            .insert([{ ...req.body, user_id: req.user.id }])
            .select()
            .single();

        if (error) throw error;
        res.status(201).json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/cvs/:id', verifyToken, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('cvs')
            .select('*')
            .eq('id', req.params.id)
            .eq('user_id', req.user.id)
            .single();

        if (error) throw error;
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/cvs/:id', verifyToken, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('cvs')
            .update(req.body)
            .eq('id', req.params.id)
            .eq('user_id', req.user.id)
            .select()
            .single();

        if (error) throw error;
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/cvs/:id', verifyToken, async (req, res) => {
    try {
        const { error } = await supabase
            .from('cvs')
            .delete()
            .eq('id', req.params.id)
            .eq('user_id', req.user.id);

        if (error) throw error;
        res.status(204).send();
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Subscription Endpoints
app.get('/api/subscription', verifyToken, async (req, res) => {
    try {
        const { data: profile, error } = await supabase
            .from('profiles')
            .select('subscription_plan, subscription_status, download_count')
            .eq('id', req.user.id)
            .single();

        if (error) throw error;
        res.json(profile);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/subscription/track-download', verifyToken, async (req, res) => {
    try {
        // Increment download count in profiles table
        const { data, error } = await supabase.rpc('increment_download_count', { user_id: req.user.id });

        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on port ${PORT}`);
});
