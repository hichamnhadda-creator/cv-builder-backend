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
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

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
        
        // Create a scoped Supabase client with the user's token to bypass any RLS anon blocks
        req.supabase = createClient(
            process.env.SUPABASE_URL,
            process.env.SUPABASE_ANON_KEY,
            {
                global: {
                    headers: {
                        Authorization: `Bearer ${token}`
                    }
                }
            }
        );

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

// Template Endpoints (Updated with full list or flag logic)
app.get('/api/templates', async (req, res) => {
    try {
        // Return minimal info for validation; frontend has the full data
        const templates = [
            { id: 'modern-1', isPremium: false },
            { id: 'professional-1', isPremium: false },
            { id: 'creative-1', isPremium: false },
            { id: 'minimal-1', isPremium: false },
            { id: 'dark-1', isPremium: false },
            // All others are considered premium by default in this simple logic
        ];
        res.json(templates);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch templates' });
    }
});

// Helper to map frontend camelCase to database lowercase
const mapToDB = (frontendCV, userId) => {
    return {
        id: frontendCV.id,
        user_id: userId,
        title: frontendCV.title,
        templateid: frontendCV.templateId,
        personalinfo: frontendCV.personalInfo,
        experience: frontendCV.experience,
        education: frontendCV.education,
        diplomas: frontendCV.diplomas,
        skills: frontendCV.skills,
        languages: frontendCV.languages,
        certifications: frontendCV.certifications,
        projects: frontendCV.projects,
        customization: frontendCV.customization,
        createdat: frontendCV.createdAt || new Date().toISOString(),
        updatedat: frontendCV.updatedAt || new Date().toISOString()
    };
};

// Helper to map database lowercase to frontend camelCase
const mapToFrontend = (dbCV) => {
    if (!dbCV) return null;
    return {
        id: dbCV.id,
        title: dbCV.title,
        templateId: dbCV.templateid,
        personalInfo: dbCV.personalinfo,
        experience: dbCV.experience,
        education: dbCV.education,
        diplomas: dbCV.diplomas,
        skills: dbCV.skills,
        languages: dbCV.languages,
        certifications: dbCV.certifications,
        projects: dbCV.projects,
        customization: dbCV.customization,
        createdAt: dbCV.createdat,
        updatedAt: dbCV.updatedat
    };
};

// CV Endpoints
app.get('/api/cvs', verifyToken, async (req, res) => {
    try {
        const { data, error } = await req.supabase
            .from('cvs')
            .select('*')
            .eq('user_id', req.user.id);

        if (error) {
            console.error(`[CV] Fetch error for user ${req.user.id}:`, error.message);
            throw error;
        }
        console.log(`[CV] Fetched ${data.length} CVs for user ${req.user.id}`);
        res.json(data.map(mapToFrontend));
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/cvs', verifyToken, async (req, res) => {
    try {
        const dbPayload = mapToDB(req.body, req.user.id);
        const { data, error } = await req.supabase
            .from('cvs')
            .insert([dbPayload])
            .select()
            .single();

        if (error) {
            console.error(`[CV] Create error for user ${req.user.id}:`, error.message);
            throw error;
        }
        console.log(`[CV] Created new CV (${data.id}) for user ${req.user.id}`);
        res.status(201).json(mapToFrontend(data));
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/cvs/:id', verifyToken, async (req, res) => {
    try {
        const { data, error } = await req.supabase
            .from('cvs')
            .select('*')
            .eq('id', req.params.id)
            .eq('user_id', req.user.id)
            .single();

        if (error) throw error;
        res.json(mapToFrontend(data));
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/cvs/:id', verifyToken, async (req, res) => {
    try {
        console.log(`[CV] Save request for CV ${req.params.id} by user ${req.user.id}`);
        const dbPayload = mapToDB(req.body, req.user.id);
        
        // Use upsert so that if the CV was created offline/locally, it still saves successfully
        const { data, error } = await req.supabase
            .from('cvs')
            .upsert(dbPayload)
            .select()
            .single();

        if (error) {
            console.error(`[CV] Save error for ${req.params.id}:`, error.message);
            throw error;
        }
        console.log(`[CV] Successfully saved CV ${req.params.id}`);
        res.json(mapToFrontend(data));
    } catch (error) {
        console.error(`[CV] PUT endpoint catch:`, error.message);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/cvs/:id', verifyToken, async (req, res) => {
    try {
        const { error } = await req.supabase
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
        console.log(`[Profile] Fetching for user: ${req.user.id} (${req.user.email})`);
        let { data: profile, error } = await req.supabase
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
        const { count, error: transError } = await req.supabase
            .from('transactions')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', req.user.id);
            
        if (transError) {
            console.error(`[Profile] Transaction count error for ${req.user.id}:`, transError.message);
        }
            
        console.log(`[Profile] RESPONSE for ${req.user.email}: Credits=${profile?.credits || 0}, Purchased=${(count || 0) > 0}`);
        res.json({ 
            credits: profile?.credits || 0, 
            has_purchased: (count || 0) > 0 
        });
    } catch (error) {
        console.error('[Profile] Final catch block:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// Secure endpoint to add credits after purchase
app.post('/api/credits/add', verifyToken, async (req, res) => {
    try {
        const { credits, packId, transactionId } = req.body;
        console.log(`[Credits] ADD request for user ${req.user.id}. Amount: ${credits}, Pack: ${packId}`);

        if (!credits || credits <= 0) {
            return res.status(400).json({ error: 'Invalid credit amount' });
        }

        // 1. Get current balance
        const { data: profile, error: fetchError } = await req.supabase
            .from('profiles')
            .select('credits')
            .eq('id', req.user.id)
            .single();
            
        let currentCredits = 0;
        if (!fetchError) {
            currentCredits = Number(profile?.credits || 0);
        } else if (fetchError.code !== 'PGRST116') {
            console.error(`[Credits] Fetch before add failed:`, fetchError.message);
            throw fetchError;
        }

        const newBalance = currentCredits + credits;
        console.log(`[Credits] UPDATING balance for ${req.user.id}: ${currentCredits} -> ${newBalance}`);

        // 2. Update profile (upsert ensures it works even if no profile existed)
        const { data: updatedProfile, error: updateError } = await req.supabase
            .from('profiles')
            .upsert({ 
                id: req.user.id, 
                credits: newBalance,
                updated_at: new Date().toISOString()
            })
            .select('credits')
            .single();

        if (updateError) {
            console.error(`[Credits] Update failed:`, updateError.message);
            throw updateError;
        }

        // 3. Record transaction
        const { error: transError } = await req.supabase
            .from('transactions')
            .insert([{
                user_id: req.user.id,
                credits_added: credits,
                amount_mad: 0, // In mock we don't have price here, but could pass it
                status: 'completed',
                payment_method: 'mock_card',
                paypal_order_id: transactionId || 'internal_' + Date.now()
            }]);

        if (transError) {
            console.warn(`[Credits] Transaction record failed (non-critical):`, transError.message);
        }

        console.log(`[Credits] SUCCESS. New balance for ${req.user.id}: ${updatedProfile.credits}`);
        res.json({ success: true, credits: updatedProfile.credits });
    } catch (err) {
        console.error('[Credits] ADD ERROR:', err);
        res.status(500).json({ error: 'Failed to add credits' });
    }
});


// Deduct Credit Endpoint for exporting CV
app.post('/api/cvs/deduct-credit', verifyToken, async (req, res) => {
    try {
        const { templateId } = req.body;
        
        console.log('\n=== EXPORT PDF REQUEST ===');
        console.log(`[Export] Incoming Auth Header:`, req.headers.authorization ? `${req.headers.authorization.substring(0, 20)}...` : 'Missing');
        console.log(`[Export] Decoded User ID:`, req.user?.id);
        console.log(`[Export] Decoded User Email:`, req.user?.email);
        console.log(`[Credits] DEDUCT request for template: ${templateId}`);

        // Define free templates (should match frontend templateData.js)
        const freeTemplates = ['modern-1', 'professional-1', 'creative-1', 'minimal-1', 'dark-1'];
        
        if (freeTemplates.includes(templateId)) {
            console.log(`[Credits] Template ${templateId} is FREE. Bypassing deduction.`);
            return res.json({ success: true, message: 'Free template - no credits required' });
        }

        let { data: profile, error: profileError } = await req.supabase
            .from('profiles')
            .select('credits')
            .eq('id', req.user.id)
            .single();
            
        if (profileError) {
            if (profileError.code === 'PGRST116') {
                console.warn(`[Credits] No profile found for user ${req.user.id}. Defaulting to 0.`);
                profile = { credits: 0 };
            } else {
                console.error(`[Credits] Database error for user ${req.user.id}:`, profileError.message);
                return res.status(500).json({ error: 'Failed to retrieve user profile' });
            }
        }
            
        const cost = 5;
        // Parse credits as a number to prevent string comparison bugs
        const currentCredits = Number(profile?.credits || 0);
        
        console.log(`[Credits] VALIDATION - User: ${req.user.id}, DB Credits: ${profile?.credits}, Parsed Current: ${currentCredits}, Required: ${cost}`);
        
        if (currentCredits < cost) {
            console.error(`[Export 403 Reason] Insufficient credits. DB shows ${currentCredits}, but ${cost} is required.`);
            console.warn(`[Credits] INSUFFICIENT for user ${req.user.id}: ${currentCredits} < ${cost}`);
            return res.status(403).json({ error: `Not enough credits (Available: ${currentCredits}, Required: ${cost})` });
        }
        
        const newBalance = currentCredits - cost;
        const { data: updatedProfile, error: updateError } = await req.supabase
            .from('profiles')
            .update({ credits: newBalance })
            .eq('id', req.user.id)
            .select('credits')
            .single();
            
        if (updateError) {
            console.error(`[Credits] DEDUCT failed for user ${req.user.id}:`, updateError.message);
            throw updateError;
        }
        
        console.log(`[Credits] DEDUCT SUCCESS - User: ${req.user.id}, New Balance: ${updatedProfile.credits}`);
        res.json({ success: true, remainingCredits: updatedProfile.credits });
    } catch (err) {
        console.error('[Credits] DEDUCT ERROR:', err);
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
