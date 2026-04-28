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

// Log loaded environment for debugging
console.log(`[Config] Environment: ${nodeEnv}`);
console.log(`[Config] Supabase URL: ${process.env.SUPABASE_URL ? 'Loaded' : 'MISSING'}`);
console.log(`[Config] Supabase Key: ${process.env.SUPABASE_ANON_KEY ? 'Loaded' : 'MISSING'}`);
console.log(`[Config] Frontend URL: ${process.env.FRONTEND_URL || 'Not Set (allowing all via CORS reflect)'}`);

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

// Initialize Supabase client with SERVICE_ROLE_KEY for administrative access
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY // Fallback to anon key if service role is missing (though not recommended)
);

if (!process.env.SUPABASE_SERVICE_ROLE_KEY) {
    console.warn('[Warning] SUPABASE_SERVICE_ROLE_KEY is missing. Backend may be restricted by RLS.');
}




const isProduction = process.env.NODE_ENV === 'production';

app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl)
        if (!origin) return callback(null, true);
        
        const allowedOrigins = [
            process.env.FRONTEND_URL,
            'http://localhost:3000',
            'http://localhost:5173',
            'https://hichamnhadda-creator.github.io'
        ];

        if (allowedOrigins.includes(origin) || origin.includes('github.io')) {
            callback(null, true);
        } else {
            // Still allow other origins for now to avoid blocking legitimate users, 
            // but log it for security auditing
            console.log(`[CORS] Request from origin: ${origin}`);
            callback(null, true);
        }
    },
    credentials: true
}));
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ limit: '5mb', extended: true }));

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
            console.error(`[Auth] Token verification failed for ${req.ip}:`, error?.message || 'No user found');
            return res.status(401).json({ error: 'Invalid or expired token' });
        }

        console.log(`[Auth] Authenticated user: ${user.email} (${user.id})`);
        req.user = user;
        next();
    } catch (err) {
        console.error(`[Auth] Internal verification error for ${req.ip}:`, err.message);
        return res.status(401).json({ error: 'Authentication failed' });
    }
};


// Request Logger Middleware
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl} ${res.statusCode} - ${duration}ms`);
    });
    next();
});

// Routes
app.get('/', (req, res) => {
    res.json({
        message: 'CV Builder API is running',
        status: 'online',
        endpoints: {
            test: '/api/test',
            cvs: '/api/cvs',
            templates: '/api/templates',
            profile: '/api/profile'
        }
    });
});

app.get('/api/test', (req, res) => {
    console.log('[API] Test endpoint reached');
    res.send('Backend is working');
});

// Template Endpoints (New)
app.get('/api/templates', async (req, res) => {
    try {
        console.log('[API] Fetching templates...');
        // For now, return a basic list to satisfy the requirement
        // In a real scenario, this might come from a DB or config file
        const templates = [
            { id: 'modern-1', name: 'Modern Executive', category: 'modern', isPremium: false },
            { id: 'professional-1', name: 'Corporate Classic', category: 'professional', isPremium: true },
            { id: 'creative-1', name: 'Creative Studio', category: 'creative', isPremium: true },
            { id: 'minimal-1', name: 'Pure Minimal', category: 'minimal', isPremium: true }
        ];
        res.json(templates);
    } catch (error) {
        console.error('[API] Templates error:', error.message);
        res.status(500).json({ error: 'Failed to fetch templates' });
    }
});

// CV Endpoints
app.get('/api/cvs', verifyToken, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('cvs')
            .select('*')
            .eq('user_id', req.user.id);

        if (error) {
            console.error(`[CV] Fetch error for user ${req.user.id}:`, error.message);
            throw error;
        }
        console.log(`[CV] Fetched ${data.length} CVs for user ${req.user.id}`);
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

        if (error) {
            console.error(`[CV] Create error for user ${req.user.id}:`, error.message);
            throw error;
        }
        console.log(`[CV] Created new CV (${data.id}) for user ${req.user.id}`);
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
        let { data: profile, error } = await supabase
            .from('profiles')
            .select('credits')
            .eq('id', req.user.id)
            .single();

        if (error) {
            // PGRST116 means 0 rows returned - user exists in Auth but not in Profiles table
            if (error.code === 'PGRST116') {
                console.warn(`[Profile] No profile record found for user ${req.user.id}. Using defaults.`);
                profile = { credits: 0 };
            } else {
                console.error(`[Profile] Fetch error for user ${req.user.id}:`, error.message);
                throw error;
            }
        }
        
        // Determine if user has purchased anything before
        const { count, error: transError } = await supabase
            .from('transactions')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', req.user.id);
            
        if (transError) {
            console.error(`[Profile] Transaction count error for ${req.user.id}:`, transError.message);
        }
            
        console.log(`[Profile] Fetched profile for ${req.user.email}. Credits: ${profile?.credits || 0}, Purchased: ${count > 0}`);
        res.json({ 
            credits: profile?.credits || 0, 
            has_purchased: (count || 0) > 0 
        });
    } catch (error) {
        console.error('[Profile] Final catch block:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// Secure endpoint to increment local testing only (if ever needed)
// app.post('/api/credits/add', verifyToken, async(req, res) => { ... })

// Payment Endpoints
app.post('/api/payment/create-order', verifyToken, async (req, res) => {
    try {
        const { packId } = req.body;
        
        // Define price mapping (USD) - DO NOT trust frontend price
        const packPricing = {
            'pack_40': { price: '3.00', credits: 40 },
            'pack_100': { price: '6.00', credits: 100 },
            'pack_200': { price: '10.00', credits: 200 }
        };

        const selectedPack = packPricing[packId];
        if (!selectedPack) {
            return res.status(400).json({ error: 'Invalid pack ID' });
        }

        const request = new checkoutNodeJssdk.orders.OrdersCreateRequest();
        request.prefer("return=representation");
        request.requestBody({
            intent: 'CAPTURE',
            purchase_units: [{
                description: `Credit Pack: ${selectedPack.credits} credits`,
                custom_id: packId, // Store packId for capture reference
                amount: {
                    currency_code: 'USD',
                    value: selectedPack.price
                }
            }]
        });

        const order = await paypalClient.execute(request);
        res.json({ id: order.result.id });
    } catch (err) {
        console.error('PayPal Create Order Error:', err);
        res.status(500).json({ error: 'Failed to create PayPal order' });
    }
});

app.post('/api/payment/capture-order', verifyToken, async (req, res) => {
    try {
        const { orderID } = req.body;
        
        if (!orderID) {
            return res.status(400).json({ error: 'Order ID is required' });
        }

        const request = new checkoutNodeJssdk.orders.OrdersCaptureRequest(orderID);
        request.requestBody({});
        const capture = await paypalClient.execute(request);

        if (capture.result.status === 'COMPLETED') {
            // Get the pack details from capture result or body (trusting capture result metadata if possible)
            // For simplicity and safety, we can pass packId in body too, but we validate it.
            const { packId } = req.body;
            
            const packPricing = {
                'pack_40': { credits: 40, mad: 30 },
                'pack_100': { credits: 100, mad: 60 },
                'pack_200': { credits: 200, mad: 100 }
            };

            const pack = packPricing[packId];
            if (!pack) {
                console.error(`Unexpected packId ${packId} for order ${orderID}`);
                return res.status(400).json({ error: 'Invalid pack configuration' });
            }

            // 1. Fetch current credits
            const { data: profile, error: profileError } = await supabase
                .from('profiles')
                .select('credits')
                .eq('id', req.user.id)
                .single();

            if (profileError) throw profileError;

            const newCredits = (profile?.credits || 0) + pack.credits;

            // 2. Update user credits in profiles
            const { error: updateError } = await supabase
                .from('profiles')
                .update({ credits: newCredits })
                .eq('id', req.user.id);

            if (updateError) throw updateError;

            // 3. Log the transaction
            const { error: transError } = await supabase
                .from('transactions')
                .insert([{
                    user_id: req.user.id,
                    paypal_order_id: orderID,
                    amount_mad: pack.mad,
                    credits_added: pack.credits,
                    status: 'completed',
                    payment_method: 'paypal',
                    currency: 'USD',
                    amount_paid: capture.result.purchase_units[0].payments.captures[0].amount.value
                }]);

            if (transError) {
                console.error('Transaction logging failed but payment was captured:', transError);
                // We don't fail here because the user already paid and credits were added.
            }

            res.json({ 
                success: true, 
                newCredits: newCredits,
                transactionId: orderID
            });
        } else {
            console.warn(`Payment capture status: ${capture.result.status}`);
            res.status(400).json({ error: `Payment not completed: ${capture.result.status}` });
        }
    } catch (err) {
        console.error('PayPal Capture Error:', err);
        res.status(500).json({ error: 'Failed to capture PayPal payment' });
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
