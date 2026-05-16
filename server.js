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
const multer = require('multer');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');
const { GoogleGenAI } = require('@google/genai');
const { Paddle, Environment } = require('@paddle/paddle-node-sdk');

// Initialize Paddle
const paddle = new Paddle({
    apiKey: process.env.PADDLE_API_KEY,
    environment: process.env.PADDLE_ENV === 'production' ? Environment.Production : Environment.Sandbox,
});

// Configure multer for memory storage
const upload = multer({ 
    storage: multer.memoryStorage()
    // fileSize limit removed as requested
});

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
// Paddle Webhook (Needs raw body for signature verification)
app.post('/api/webhooks/paddle', express.text({ type: 'application/json' }), async (req, res) => {
    const signature = req.headers['paddle-signature'] || '';
    const secret = process.env.PADDLE_WEBHOOK_SECRET || '';

    try {
        if (!signature || !secret) {
            console.error('[Paddle Webhook] Missing signature or secret');
            return res.status(400).send('Missing signature or secret');
        }

        const eventData = paddle.webhooks.unmarshal(req.body, secret, signature);
        console.log(`[Paddle Webhook] Received event: ${eventData.eventType}`);

        if (eventData.eventType === 'transaction.completed') {
            const transaction = eventData.data;
            // Get user_id and credits from custom_data
            const userId = transaction.customData?.user_id;
            const creditsStr = transaction.customData?.credits;
            const credits = parseInt(creditsStr || '0');

            if (userId && credits > 0) {
                console.log(`[Paddle Webhook] Processing ${credits} credits for user ${userId}`);
                
                // 1. Get current balance using ADMIN client
                const { data: profile } = await supabase
                    .from('profiles')
                    .select('credits')
                    .eq('id', userId)
                    .single();
                
                const currentCredits = Number(profile?.credits || 0);
                const newBalance = currentCredits + credits;

                // 2. Update profile
                const { error: updateError } = await supabase
                    .from('profiles')
                    .upsert({ 
                        id: userId, 
                        credits: newBalance,
                        updated_at: new Date().toISOString()
                    });

                if (updateError) {
                    console.error(`[Paddle Webhook] Profile update error:`, updateError.message);
                    throw updateError;
                }

                // 3. Record transaction
                const { error: transError } = await supabase
                    .from('transactions')
                    .insert([{
                        user_id: userId,
                        paddle_transaction_id: transaction.id,
                        amount_paid: parseFloat(transaction.details?.totals?.total || '0') / 100, // Paddle returns cents
                        currency: transaction.currencyCode,
                        credits_added: credits,
                        status: 'completed',
                        payment_method: 'paddle'
                    }]);

                if (transError) {
                    console.warn(`[Paddle Webhook] Transaction record error:`, transError.message);
                }

                console.log(`[Paddle Webhook] SUCCESS. User ${userId} new balance: ${newBalance}`);
            }
        }
        
        res.status(200).send('Webhook processed');
    } catch (err) {
        console.error(`[Paddle Webhook] Verification failed:`, err.message);
        res.status(400).send(`Webhook Error: ${err.message}`);
    }
});

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

const FREE_TEMPLATES = [
    'modern-1'
];

/**
 * Server-side validation for template access
 */
const checkTemplateAccess = async (supabase, userId, templateId) => {
    const cleanId = templateId?.trim()?.toLowerCase();
    if (FREE_TEMPLATES.includes(cleanId)) return true;

    // Check if user is premium (has credits or transactions)
    const { data: profile } = await supabase
        .from('profiles')
        .select('credits')
        .eq('id', userId)
        .single();
    
    const { count } = await supabase
        .from('transactions')
        .select('*', { count: 'exact', head: true })
        .eq('user_id', userId);

    const credits = profile?.credits || 0;
    const transactions = count || 0;

    const isPremium = credits > 0 || transactions > 0;
    
    console.log(`[Backend Access Check] User: ${userId}, Template: ${cleanId}, Credits: ${credits}, Transactions: ${transactions}, Result: ${isPremium ? 'ALLOWED' : 'DENIED'}`);

    return isPremium;
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
        const { templateId } = req.body;
        
        // 1. Verify template access
        const canAccess = await checkTemplateAccess(req.supabase, req.user.id, templateId);
        if (!canAccess) {
            console.warn(`[CV] Access Denied: Free user ${req.user.id} tried to create CV with premium template ${templateId}`);
            return res.status(403).json({ 
                error: 'Premium template access denied. Please upgrade your plan.',
                premiumRequired: true 
            });
        }

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
        
        const frontendCV = mapToFrontend(data);
        
        // Verify template access for existing CV
        const canAccess = await checkTemplateAccess(req.supabase, req.user.id, frontendCV.templateId);
        if (!canAccess) {
            console.warn(`[CV] Access Denied: Free user ${req.user.id} tried to open CV ${req.params.id} with premium template ${frontendCV.templateId}`);
            return res.status(403).json({ 
                error: 'Premium template access denied. Please upgrade your plan.',
                premiumRequired: true 
            });
        }

        res.json(frontendCV);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/cvs/:id', verifyToken, async (req, res) => {
    try {
        console.log(`[CV] Save request for CV ${req.params.id} by user ${req.user.id}`);
        
        const { templateId } = req.body;
        
        // 1. Verify template access before saving/updating
        const canAccess = await checkTemplateAccess(req.supabase, req.user.id, templateId);
        if (!canAccess) {
            console.warn(`[CV] Access Denied: Free user ${req.user.id} tried to save CV with premium template ${templateId}`);
            return res.status(403).json({ 
                error: 'Premium template access denied. Please upgrade your plan.',
                premiumRequired: true 
            });
        }

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

// Import CV Endpoint
app.post('/api/cvs/import', verifyToken, upload.single('file'), async (req, res) => {
    try {
        console.log(`[Import CV] Request from user: ${req.user.id}`);
        
        // 1. Verify premium status
        const { data: profile } = await req.supabase
            .from('profiles')
            .select('credits')
            .eq('id', req.user.id)
            .single();
            
        const { count, error: transError } = await req.supabase
            .from('transactions')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', req.user.id);
            
        const currentCredits = profile?.credits || 0;
        
        if (transError || ((count || 0) === 0 && currentCredits <= 0)) {
            console.warn(`[Import CV] Access denied: User ${req.user.id} has no transactions and no credits.`);
            return res.status(403).json({ error: 'Premium feature. Please purchase a credit pack to use CV Import.' });
        }

        // 2. Validate file
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const ext = path.extname(req.file.originalname).toLowerCase();
        let rawText = '';
        let inlineData = null;

        // 3. Extract Text or Prepare Inline Data
        if (ext === '.pdf') {
            try {
                const pdfData = await pdfParse(req.file.buffer);
                rawText = pdfData.text;
            } catch (err) {
                console.warn('[Import CV] pdf-parse failed:', err.message);
            }
            
            // If text is too short (scanned PDF or image-based), send PDF directly to Gemini
            if (!rawText || rawText.trim().length < 50) {
                console.log('[Import CV] Insufficient text extracted. Sending PDF directly to Gemini for OCR.');
                inlineData = {
                    data: req.file.buffer.toString('base64'),
                    mimeType: 'application/pdf'
                };
            }
        } else if (ext === '.docx') {
            const docxData = await mammoth.extractRawText({ buffer: req.file.buffer });
            rawText = docxData.value;
            
            if (!rawText || rawText.trim().length < 50) {
                return res.status(400).json({ error: 'Could not extract sufficient text from the DOCX file.' });
            }
        } else {
            return res.status(400).json({ error: 'Unsupported file format. Please upload PDF or DOCX.' });
        }

        console.log(`[Import CV] Processing file. Sending to Gemini...`);

        // 4. Parse with Gemini AI
        if (!process.env.GEMINI_API_KEY) {
            console.error('[Import CV] GEMINI_API_KEY is not configured in backend.');
            return res.status(500).json({ error: 'AI Parsing is not configured on the server.' });
        }

        const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
        
        const systemPrompt = `You are an expert CV/Resume parser.
Extract the details from the following resume text and format them EXACTLY into this JSON structure.
Return ONLY valid JSON, without any markdown formatting or code blocks.

{
    "personalInfo": {
        "fullName": "Extracted full name or empty string",
        "email": "Extracted email or empty string",
        "phone": "Extracted phone or empty string",
        "address": "Extracted location/address or empty string",
        "linkedin": "Extracted linkedin URL or empty string",
        "website": "Extracted website URL or empty string",
        "summary": "Extracted professional summary or about me section"
    },
    "experience": [
        {
            "id": "generate_a_random_string_id",
            "company": "Company Name",
            "position": "Job Title",
            "startDate": "YYYY-MM",
            "endDate": "YYYY-MM or Present",
            "description": "Job responsibilities and achievements"
        }
    ],
    "education": [
        {
            "id": "generate_a_random_string_id",
            "school": "School/University Name",
            "degree": "Degree Name",
            "field": "Field of Study",
            "startDate": "YYYY",
            "endDate": "YYYY or Expected YYYY"
        }
    ],
    "skills": ["Skill 1", "Skill 2"],
    "languages": ["Language 1", "Language 2"]
}

Guidelines:
- Guess the start and end dates based on context if not explicit.
- Use empty strings or empty arrays if a section is not found.
- Do NOT wrap the JSON in \`\`\`json blocks.
`;

        const contentsParts = [
            systemPrompt,
            inlineData ? { inlineData } : "\n\n--- RESUME TEXT ---\n" + rawText
        ];

        const response = await ai.models.generateContent({
            model: 'gemini-2.5-flash',
            contents: contentsParts
        });

        let jsonString = response.text;
        
        // Clean markdown blocks if Gemini returns them anyway
        if (jsonString.startsWith('\`\`\`json')) {
            jsonString = jsonString.replace(/^\`\`\`json/, '').replace(/\`\`\`$/, '').trim();
        } else if (jsonString.startsWith('\`\`\`')) {
            jsonString = jsonString.replace(/^\`\`\`/, '').replace(/\`\`\`$/, '').trim();
        }

        let parsedData;
        try {
            parsedData = JSON.parse(jsonString);
        } catch (parseError) {
            console.error('[Import CV] Failed to parse AI JSON response:', jsonString.substring(0, 200));
            throw new Error('AI returned invalid JSON format');
        }

        console.log(`[Import CV] Successfully parsed CV data for user ${req.user.id}`);
        res.json({ success: true, data: parsedData });

    } catch (error) {
        console.error(`[Import CV] Error:`, error.message);
        res.status(500).json({ error: error.message || 'Failed to import CV' });
    }
});

// Profile endpoints
app.get('/api/profile', verifyToken, async (req, res) => {
    try {
        console.log(`[Profile] Fetching for user: ${req.user.id} (${req.user.email})`);
        let { data: profile, error } = await supabase
            .from('profiles')
            .select('credits, free_export_count')
            .eq('id', req.user.id)
            .single();

        if (error) {
            if (error.code === 'PGRST116') {
                console.warn(`[Profile] No profile record found for user ${req.user.id}. Using defaults.`);
                profile = { credits: 0, free_export_count: 0 };
            } else {
                console.error(`[Profile] Fetch error for user ${req.user.id}:`, error.message);
                throw error;
            }
        }
        
        const { count, error: transError } = await supabase
            .from('transactions')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', req.user.id);
            
        const currentCredits = Number(profile?.credits || 0);
        const freeExportsUsed = Number(profile?.free_export_count || 0);
        const hasPurchased = (count || 0) > 0 || currentCredits > 0;
            
        res.json({ 
            credits: currentCredits, 
            free_export_count: freeExportsUsed,
            has_purchased: hasPurchased 
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Removed old insecure credit endpoint. Credits are now handled via Paddle Webhooks.


// Deduct Credit Endpoint for exporting CV
app.post('/api/cvs/deduct-credit', verifyToken, async (req, res) => {
    try {
        const { templateId } = req.body;
        
        // Case-insensitive template check
        const cleanTemplateId = (templateId || '').trim().toLowerCase();
        const isFreeTemplate = cleanTemplateId === 'modern-1';
        
        // 1. Get user profile and transaction status using ADMIN client
        const { data: profile, error: profileError } = await supabase
            .from('profiles')
            .select('credits, free_export_count')
            .eq('id', req.user.id)
            .single();
            
        const { count: transCount } = await supabase
            .from('transactions')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', req.user.id);

        const currentFreeExports = Number(profile?.free_export_count || 0);
        const currentCredits = Number(profile?.credits || 0);
        const isPremium = (transCount || 0) > 0 || currentCredits > 0;

        console.log(`[Export Auth] User: ${req.user.id}, Template: ${cleanTemplateId}, FreeUsed: ${currentFreeExports}, isPremium: ${isPremium}`);

        // 2. Handle Free Template Logic
        if (isFreeTemplate) {
            if (currentFreeExports >= 1 && !isPremium) {
                console.warn(`[Export BLOCKED] Limit reached (1/1) for ${req.user.id}`);
                return res.status(403).json({ 
                    error: 'Free download limit reached. Please upgrade to Premium.',
                    limitReached: true 
                });
            }

            if (isPremium) {
                return res.json({ success: true, message: 'Premium access' });
            }

            const nextCount = currentFreeExports + 1;
            console.log(`[Export] Incrementing count to ${nextCount} for ${req.user.id}`);
            
            // Explicitly update using ADMIN client
            const { data: updateData, error: updateError } = await supabase
                .from('profiles')
                .update({ 
                    free_export_count: nextCount,
                    updated_at: new Date().toISOString()
                })
                .eq('id', req.user.id)
                .select();

            if (updateError) {
                console.error(`[Export] DB Update Error:`, updateError.message);
                throw updateError;
            }

            // If no rows updated, the profile might be missing - try insert
            if (!updateData || updateData.length === 0) {
                console.log(`[Export] Profile missing, creating new record for ${req.user.id}`);
                const { error: insertError } = await supabase
                    .from('profiles')
                    .insert({
                        id: req.user.id,
                        free_export_count: 1,
                        credits: 0
                    });
                if (insertError) throw insertError;
            }

            console.log(`[Export] SUCCESS. New count: ${nextCount}`);

            return res.json({ 
                success: true, 
                freeExportCount: nextCount 
            });
        }

        // 3. Handle Premium Template Logic
        const cost = 5;
        console.log(`[Credits] VALIDATION - User: ${req.user.id}, DB Credits: ${currentCredits}, Required: ${cost}`);
        
        if (currentCredits < cost) {
            console.error(`[Export 403 Reason] Insufficient credits for premium template.`);
            return res.status(403).json({ 
                error: `Premium template requires 5 credits (Available: ${currentCredits}).`,
                insufficientCredits: true
            });
        }
        
        const newBalance = currentCredits - cost;
        const { data: updatedProfile, error: updateError } = await supabase
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
        res.status(500).json({ error: 'Failed to process export credit' });
    }
});


// --- COVER LETTER ENDPOINTS ---

// Generate Cover Letter using AI
app.post('/api/cover-letters/generate', verifyToken, async (req, res) => {
    try {
        const { cvData, company, jobTitle, language = 'en' } = req.body;

        if (!cvData || !company || !jobTitle) {
            return res.status(400).json({ error: 'Missing required data (CV data, company, or job title)' });
        }

        // 1. Premium Validation
        const { data: profile } = await supabase
            .from('profiles')
            .select('credits')
            .eq('id', req.user.id)
            .single();
            
        const { count: transCount } = await supabase
            .from('transactions')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', req.user.id);

        const currentCredits = Number(profile?.credits || 0);
        const isPremium = (transCount || 0) > 0 || currentCredits >= 5;

        if (!isPremium) {
            return res.status(403).json({ 
                error: 'Premium feature. Please purchase credits to generate cover letters.',
                isPremium: false 
            });
        }

        // 2. Generate Content with Gemini
        const genAI = new GoogleGenAI(process.env.GEMINI_API_KEY);
        const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

        const prompt = `
            You are a professional career coach and expert cover letter writer.
            Using the provided CV data, write a high-quality, persuasive, and professional cover letter.
            
            TARGET JOB: ${jobTitle}
            TARGET COMPANY: ${company}
            LANGUAGE: ${language} (Write the entire letter in this language)
            
            CV DATA:
            Name: ${cvData.personalInfo?.fullName}
            Experience: ${JSON.stringify(cvData.experience)}
            Skills: ${JSON.stringify(cvData.skills)}
            Education: ${JSON.stringify(cvData.education)}
            
            Instructions:
            - Write in a professional, engaging tone.
            - Focus on how the candidate's skills and experience solve the company's needs.
            - Include placeholders like [Date], [Hiring Manager Name] if not obvious.
            - Format with proper paragraphs and professional structure.
            - If language is Arabic, ensure formal Modern Standard Arabic.
            - RETURN ONLY THE CONTENT OF THE LETTER. NO MARKDOWN, NO INTRO/OUTRO.
        `;

        const result = await model.generateContent(prompt);
        const text = result.response.text().trim();

        // 3. Deduct Credits (only if they aren't "unlimited" by large purchase, let's just deduct 5)
        if (currentCredits >= 5) {
            await supabase
                .from('profiles')
                .update({ credits: currentCredits - 5 })
                .eq('id', req.user.id);
        }

        res.json({ 
            success: true, 
            content: text,
            remainingCredits: currentCredits >= 5 ? currentCredits - 5 : currentCredits
        });

    } catch (error) {
        console.error('[Cover Letter] Generation failed:', error);
        res.status(500).json({ error: 'Failed to generate cover letter: ' + error.message });
    }
});

// Save Cover Letter
app.post('/api/cover-letters', verifyToken, async (req, res) => {
    try {
        const { title, company, jobTitle, content, language, cvId } = req.body;
        
        const { data, error } = await supabase
            .from('cover_letters')
            .insert([{
                user_id: req.user.id,
                title,
                company,
                job_title: jobTitle,
                content,
                language,
                cv_id: cvId
            }])
            .select()
            .single();

        if (error) throw error;
        res.json({ success: true, data });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get User's Cover Letters
app.get('/api/cover-letters', verifyToken, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('cover_letters')
            .select('*')
            .eq('user_id', req.user.id)
            .order('created_at', { ascending: false });

        if (error) throw error;
        res.json({ success: true, data });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});
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
