const express = require('express');
const cors = require('cors');
const path = require('path');
const dotenv = require('dotenv');

// Load environment variables based on NODE_ENV
const nodeEnv = process.env.NODE_ENV || 'development';
const envPath = nodeEnv === 'production' ? '.env.production' : '.env';
dotenv.config({ path: path.resolve(process.cwd(), envPath) });

// Re-check for .env if .env.production was requested but not found (optional fallback)
if (nodeEnv === 'production' && !process.env.SUPABASE_URL) {
    dotenv.config({ path: path.resolve(process.cwd(), '.env') });
}

const crypto = require('crypto');
const helmet = require('helmet');
const compression = require('compression');
const { createClient } = require('@supabase/supabase-js');
const checkoutNodeJssdk = require('@paypal/checkout-server-sdk');

const environment = new checkoutNodeJssdk.core.SandboxEnvironment(
    process.env.PAYPAL_CLIENT_ID || 'sb', 
    process.env.PAYPAL_CLIENT_SECRET || 'sb'
);
const paypalClient = new checkoutNodeJssdk.core.PayPalHttpClient(environment);

const app = express();
app.use(helmet()); // Set security-related HTTP headers
app.use(compression()); // Compress all responses
const PORT = process.env.PORT || 5000;

// Initialize Supabase client
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
);

// Lemon Squeezy Configuration (Removed)

const isProduction = process.env.NODE_ENV === 'production';

app.use(cors({ origin: '*', credentials: true }));
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

// Profile endpoints
app.get('/api/profile', verifyToken, async (req, res) => {
    try {
        const { data: profile, error } = await supabase
            .from('profiles')
            .select('credits')
            .eq('id', req.user.id)
            .single();

        if (error) throw error;
        
        // Determine if user has purchased anything before
        const { count } = await supabase
            .from('transactions')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', req.user.id);
            
        res.json({ ...profile, has_purchased: count > 0 });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Secure endpoint to increment local testing only (if ever needed)
// app.post('/api/credits/add', verifyToken, async(req, res) => { ... })

// Payment Endpoints
app.post('/api/payment/create-order', verifyToken, async (req, res) => {
    try {
        const { packId } = req.body;
        // Packs: pack_40=30MAD, pack_100=60MAD, pack_200=100MAD
        let value = '0.00';
        if (packId === 'pack_40') value = '3.00'; // ~$3.00 USD
        else if (packId === 'pack_100') value = '6.00';
        else if (packId === 'pack_200') value = '10.00';
        else return res.status(400).json({ error: 'Invalid pack ID' });

        const request = new checkoutNodeJssdk.orders.OrdersCreateRequest();
        request.prefer("return=representation");
        request.requestBody({
            intent: 'CAPTURE',
            purchase_units: [{
                amount: {
                    currency_code: 'USD',
                    value: value
                }
            }]
        });

        const order = await paypalClient.execute(request);
        res.json({ id: order.result.id });
    } catch (err) {
        console.error('PayPal Create Order Error:', err);
        res.status(500).json({ error: 'Failed to create order' });
    }
});

app.post('/api/payment/capture-order', verifyToken, async (req, res) => {
    try {
        const { orderID, packId } = req.body;
        const request = new checkoutNodeJssdk.orders.OrdersCaptureRequest(orderID);
        request.requestBody({});
        const capture = await paypalClient.execute(request);

        if (capture.result.status === 'COMPLETED') {
            let creditsToAdd = 0;
            if (packId === 'pack_40') creditsToAdd = 40;
            else if (packId === 'pack_100') creditsToAdd = 100;
            else if (packId === 'pack_200') creditsToAdd = 200;

            // Fetch current profile
            const { data: profile } = await supabase
                .from('profiles')
                .select('credits')
                .eq('id', req.user.id)
                .single();

            const currentCredits = profile?.credits || 0;

            // Update credits
            await supabase
                .from('profiles')
                .update({ credits: currentCredits + creditsToAdd })
                .eq('id', req.user.id);

            // Log transaction
            await supabase.from('transactions').insert([{
                user_id: req.user.id,
                paypal_order_id: orderID,
                amount_mad: packId === 'pack_100' ? 60 : packId === 'pack_200' ? 100 : 30,
                credits_added: creditsToAdd
            }]);

            res.json({ success: true, newCredits: currentCredits + creditsToAdd });
        } else {
            res.status(400).json({ error: 'Payment capture not completed' });
        }
    } catch (err) {
        console.error('PayPal Capture Error:', err);
        res.status(500).json({ error: 'Failed to capture payment' });
    }
});

// Deduct Credit Endpoint for exporting CV
app.post('/api/cvs/deduct-credit', verifyToken, async (req, res) => {
    try {
        const cost = 5;
        const { data: profile } = await supabase
            .from('profiles')
            .select('credits')
            .eq('id', req.user.id)
            .single();
            
        const currentCredits = profile?.credits || 0;
        
        if (currentCredits < cost) {
            return res.status(403).json({ error: 'Not enough credits' });
        }
        
        const { data, error } = await supabase
            .from('profiles')
            .update({ credits: currentCredits - cost })
            .eq('id', req.user.id)
            .select('credits')
            .single();
            
        if (error) throw error;
        
        res.json({ success: true, remainingCredits: data.credits });
    } catch (err) {
        console.error('Deduct Credit Error:', err);
        res.status(500).json({ error: 'Failed to deduct credits' });
    }
});

// Global Error Handler
app.use((err, req, res, next) => {
    console.error(`[Unhandled Error] ${err.message}`);
    res.status(err.status || 500).json({
        error: isProduction ? 'Internal Server Error' : err.message,
        stack: isProduction ? null : err.stack
    });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running in ${isProduction ? 'production' : 'development'} mode on port ${PORT}`);
});
