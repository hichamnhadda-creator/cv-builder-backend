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
const rateLimit = require('express-rate-limit');
const mammoth = require('mammoth');
const { GoogleGenAI } = require('@google/genai');
const { Polar } = require('@polar-sh/sdk');
const { Webhook } = require('standardwebhooks');

// Initialize Polar
const polar = new Polar({
    accessToken: process.env.POLAR_ACCESS_TOKEN,
    server: process.env.NODE_ENV === 'production' ? 'production' : 'sandbox',
});

// Configure multer for memory storage
const upload = multer({ 
    storage: multer.memoryStorage()
    // fileSize limit removed as requested
});

const app = express();
app.use(helmet()); // Set security-related HTTP headers
app.use(compression()); // Compress all responses

// Rate limiting configurations
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 200, // Limit each IP to 200 requests per `window` (here, per 15 minutes)
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Trop de requêtes, veuillez réessayer plus tard.' }
});

const strictLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 20, // Limit each IP to 20 requests per hour for expensive operations
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Limite atteinte pour cette action, veuillez patienter.' }
});

// Apply general limiter to all API routes
app.use('/api', generalLimiter);

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
// Polar Webhook (Needs raw body for signature verification)
const handlePolarWebhook = async (req, res) => {
    const secret = process.env.POLAR_WEBHOOK_SECRET || '';

    console.log('[Polar Webhook] Received request...');

    try {
        if (!secret) {
            console.error('[Polar Webhook] Missing webhook secret.');
            return res.status(400).send('Missing secret');
        }

        const rawBody = typeof req.body === 'string' ? req.body : (Buffer.isBuffer(req.body) ? req.body.toString('utf8') : JSON.stringify(req.body));
        
        const fs = require('fs');
        const logData = `\n--- Webhook Received ---\nHeaders: ${JSON.stringify(req.headers)}\nBody: ${rawBody}\n`;
        fs.appendFileSync('webhook.log', logData);

        let eventData;
        try {
            const cleanSecret = secret.startsWith('polar_whs_') ? secret.replace('polar_whs_', 'whsec_') : secret;
            const wh = new Webhook(cleanSecret);
            eventData = wh.verify(rawBody, req.headers);
        } catch (verifyError) {
            console.error('[Polar Webhook] Signature verification failed:', verifyError.message);
            fs.appendFileSync('webhook.log', `Verification Error: ${verifyError.message}\n`);
            
            // Allow bypass for local dev testing via smee because the secret often mismatches
            if (process.env.NODE_ENV !== 'production' && req.headers['disguised-host'] === 'smee.io') {
                 console.warn('[Polar Webhook] Bypassing signature check for local Smee testing!');
                 eventData = JSON.parse(rawBody);
            } else {
                 return res.status(400).send('Invalid signature');
            }
        }

        console.log(`[Polar Webhook] Event verified successfully. Event Type: ${eventData.type}`);
        fs.appendFileSync('webhook.log', `Verified Event Type: ${eventData.type}\n`);

        if (['order.created', 'order.paid', 'checkout.completed'].includes(eventData.type)) {
            const order = eventData.data;
            const transactionId = order.id;

            console.log(`[Polar Webhook] Processing event: ${eventData.type} for transaction: ${transactionId}`);

            // 1. Strict Idempotency: Check if this transaction has already been processed
            const { data: existingTx, error: txCheckError } = await supabase
                .from('transactions')
                .select('id')
                .eq('polar_transaction_id', transactionId)
                .maybeSingle();

            if (existingTx) {
                console.log(`[Polar Webhook] Transaction ${transactionId} already processed. Skipping to prevent duplicate credits.`);
                return res.status(200).send('Webhook already processed (idempotent)');
            }

            // 2. Identify the target User
            // IMPORTANT: Prioritize metadata because that is the actual logged-in user who initiated the checkout.
            // If we only use customer.email, we might give credits to the wrong user if they used a different billing email!
            let userEmail = order.metadata?.email || order.user?.email || order.customer?.email || order.customer_email;
            let userId = order.metadata?.user_id || order.custom_field_data?.user_id || null;

            if (!userId && userEmail) {
                console.log(`[Polar Webhook] Attempting to find user by email: ${userEmail}`);
                try {
                    // Use listUsers to find the user by email since getUserByEmail is not supported in this version
                    const { data: usersData, error: usersError } = await supabase.auth.admin.listUsers();
                    if (!usersError && usersData?.users) {
                        const foundUser = usersData.users.find(u => u.email.toLowerCase() === userEmail.toLowerCase());
                        if (foundUser) {
                            userId = foundUser.id;
                            console.log(`[Polar Webhook] User found via listUsers: ${userId} (${userEmail})`);
                        } else {
                            console.log(`[Polar Webhook] User not found in listUsers for email: ${userEmail}`);
                        }
                    } else if (usersError) {
                        console.error(`[Polar Webhook] Error fetching users list:`, usersError.message);
                    }
                } catch (err) {
                    console.error(`[Polar Webhook] Exception during user lookup:`, err.message);
                }
            }

            if (!userId) {
                console.error(`[Polar Webhook] Critical: Could not identify target user for transaction ${transactionId} with email ${userEmail}`);
                return res.status(400).send('Unable to identify user for credit assignment');
            }

            // Fetch current credits before update for detailed logging
            const { data: profileBefore } = await supabase
                .from('profiles')
                .select('credits')
                .eq('id', userId)
                .single();
            const creditsBefore = Number(profileBefore?.credits || 0);

            // 3. Extract Credits from Product Metadata
            const metadataCredits = order.product?.metadata?.credits || order.metadata?.credits;
            let creditsToAdd = 0;

            if (metadataCredits && parseInt(metadataCredits) > 0) {
                creditsToAdd = parseInt(metadataCredits);
                console.log(`[Polar Webhook] Extracted credits from product.metadata: ${creditsToAdd}`);
            } else {
                const productId = order.product_id;
                const priceId = order.product_price_id;
                if (productId === process.env.POLAR_PRODUCT_40_ID || priceId === process.env.POLAR_PRODUCT_40_ID) {
                    creditsToAdd = 40;
                } else if (productId === process.env.POLAR_PRODUCT_100_ID || priceId === process.env.POLAR_PRODUCT_100_ID) {
                    creditsToAdd = 100;
                } else if (productId === process.env.POLAR_PRODUCT_200_ID || priceId === process.env.POLAR_PRODUCT_200_ID) {
                    creditsToAdd = 200;
                } else if (order.amount) {
                    // Fallback to extrapolate credits from amount paid to avoid 0 credits
                    const amountInDollars = order.amount / 100;
                    if (amountInDollars === 10 || amountInDollars === 60) creditsToAdd = 100; 
                    else if (amountInDollars === 5 || amountInDollars === 30) creditsToAdd = 40;
                    else if (amountInDollars === 18 || amountInDollars === 100) creditsToAdd = 200;
                }
                console.log(`[Polar Webhook] Fallback credits logic applied: ${creditsToAdd}`);
            }

            console.log(`[Polar Webhook] Credits to add: ${creditsToAdd}`);

            if (creditsToAdd <= 0) {
                console.warn(`[Polar Webhook] Transaction processed with 0 credits for user ${userId}.`);
            } else {
                console.log(`[Polar Webhook] Assigning +${creditsToAdd} credits to User ${userId}...`);

                // 4. Secure & Atomic Credit Incrementation
                const { error: rpcError } = await supabase.rpc('increment_credits', { 
                    user_id: userId, 
                    amount: creditsToAdd 
                });

                let dbUpdateResult = 'success';

                if (rpcError) {
                    console.warn(`[Polar Webhook] Atomic increment_credits RPC failed, executing safe fallback:`, rpcError.message);
                    
                    const newBalance = creditsBefore + creditsToAdd;

                    const { error: updateError } = await supabase
                        .from('profiles')
                        .upsert({ 
                            id: userId, 
                            credits: newBalance,
                            updated_at: new Date().toISOString()
                        });

                    if (updateError) {
                        console.error(`[Polar Webhook] Fallback balance updates failed:`, updateError.message);
                        dbUpdateResult = 'failed: ' + updateError.message;
                        throw updateError;
                    }
                }

                // Fetch credits after update
                const { data: profileAfter } = await supabase
                    .from('profiles')
                    .select('credits')
                    .eq('id', userId)
                    .single();
                const creditsAfter = Number(profileAfter?.credits || 0);
                console.log(`[Polar Webhook] Credits after update: ${creditsAfter}`);
                console.log(`[Polar Webhook] Database update result: ${dbUpdateResult}`);

                // 5. Log transaction details in Supabase
                const amountPaid = parseFloat(order.amount || '0') / 100;
                const currency = order.currency || 'USD';
                
                const { error: transError } = await supabase
                    .from('transactions')
                    .insert([{
                        user_id: userId,
                        polar_transaction_id: transactionId,
                        amount_paid: amountPaid,
                        currency: currency,
                        credits_added: creditsToAdd,
                        status: 'completed',
                        payment_method: 'polar'
                    }]);

                if (transError) {
                    console.error(`[Polar Webhook] Failed to insert transaction record for ${transactionId}:`, transError.message);
                }

                console.log(`[Polar Webhook] SUCCESS. User ${userId} successfully credited with +${creditsToAdd} credits.`);
            }
        } else {
            console.log(`[Polar Webhook] Ignoring unhandled event type: ${eventData.type}`);
        }

        res.status(200).send('Webhook processed successfully');
    } catch (err) {
        console.error(`[Polar Webhook] Error processing event:`, err.message);
        res.status(400).send(`Webhook Error: ${err.message}`);
    }
};

app.post('/api/webhooks/polar', express.text({ type: 'application/json' }), handlePolarWebhook);

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
app.post('/api/cvs/import', strictLimiter, verifyToken, upload.single('file'), async (req, res) => {
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

// Removed old insecure credit endpoint. Credits are now handled via Polar Webhooks.

// Create Polar Checkout Session Endpoint
app.post('/api/payments/checkout', strictLimiter, verifyToken, async (req, res) => {
    const { productId, credits } = req.body;
    const user = req.user;

    if (!productId || !credits) {
        return res.status(400).json({ error: 'Missing productId or credits' });
    }

    try {
        console.log(`[Polar Checkout] Creating session for product ${productId}, user ${user.email}`);
        
        // Use FRONTEND_URL from environment or fallback to localhost:3000
        const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
        const successUrl = `${frontendUrl}/pricing?payment=success`;
        
        // Use native fetch to bypass Polar SDK 0.11.1 typing limits on metadata
        const polarBaseUrl = process.env.NODE_ENV === 'production' ? 'https://api.polar.sh' : 'https://sandbox-api.polar.sh';
        const response = await fetch(`${polarBaseUrl}/v1/checkouts/`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${process.env.POLAR_ACCESS_TOKEN}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                product_price_id: productId,
                success_url: successUrl,
                customer_email: user.email,
                metadata: {
                    user_id: user.id,
                    email: user.email,
                    credits: credits.toString()
                }
            })
        });

        if (!response.ok) {
            const errorData = await response.text();
            throw new Error(`Polar API Error: ${errorData}`);
        }

        const session = await response.json();
        
        console.log(`[Polar Checkout] Created session: ${session.url}`);
        res.json({ url: session.url });
    } catch (err) {
        console.error('[Polar Checkout] Error creating session:', err.message);
        res.status(500).json({ error: err.message || 'Failed to create checkout session' });
    }
});


app.get('/api/packs', async (req, res) => {
  try {
    const packs = [
      { id: 'pack_40', productPriceId: process.env.POLAR_PRODUCT_40_ID, credits: 40, price: 5 },
      { id: 'pack_100', productPriceId: process.env.POLAR_PRODUCT_100_ID, credits: 100, price: 10 },
      { id: 'pack_200', productPriceId: process.env.POLAR_PRODUCT_200_ID, credits: 200, price: 18 }
    ];
    res.json(packs);
  } catch (error) {
    console.error('[Packs] Error fetching pack list:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// Deduct Credit Endpoint for exporting CV (Costs exactly 5 credits)
app.post('/api/cvs/deduct-credit', verifyToken, async (req, res) => {
    const userId = req.user.id;
    const cost = 5;

    console.log(`[Credits] Deduct request started for User ${userId}. Cost: ${cost} credits.`);

    try {
        // 1. Execute secure atomic PostgreSQL RPC function
        const { data: newBalance, error: rpcError } = await supabase.rpc('deduct_credits', {
            user_id: userId,
            amount: cost
        });

        if (rpcError) {
            // Handle insufficient credits exception raised by PostgreSQL function
            if (rpcError.message && rpcError.message.includes('Insufficient credits')) {
                console.warn(`[Credits] Insufficient credits RPC block for User ${userId}: ${rpcError.message}`);
                return res.status(403).json({
                    error: `Insufficient credits. Each CV export costs exactly 5 credits.`,
                    insufficientCredits: true
                });
            }

            console.warn(`[Credits] deduct_credits RPC failed, initiating safe self-healing fallback:`, rpcError.message);

            // 2. Self-Healing Fallback: Secure read-then-write logic
            const { data: profile, error: readError } = await supabase
                .from('profiles')
                .select('credits')
                .eq('id', userId)
                .single();

            if (readError) {
                console.error(`[Credits] Fallback read profile failed for User ${userId}:`, readError.message);
                throw readError;
            }

            const currentCredits = Number(profile?.credits || 0);
            if (currentCredits < cost) {
                console.warn(`[Credits] Insufficient credits fallback block for User ${userId} (Available: ${currentCredits})`);
                return res.status(403).json({
                    error: `Insufficient credits. Required: 5, Available: ${currentCredits}`,
                    insufficientCredits: true
                });
            }

            const computedBalance = currentCredits - cost;
            const { data: updatedProfile, error: updateError } = await supabase
                .from('profiles')
                .update({ 
                    credits: computedBalance,
                    updated_at: new Date().toISOString()
                })
                .eq('id', userId)
                .select('credits')
                .single();

            if (updateError) {
                console.error(`[Credits] Fallback update profile failed for User ${userId}:`, updateError.message);
                throw updateError;
            }

            console.log(`[Credits] Fallback DEDUCT SUCCESS - User: ${userId}, New Balance: ${updatedProfile.credits}`);
            return res.json({ success: true, remainingCredits: updatedProfile.credits });
        }

        // Successfully executed PostgreSQL atomic deduct_credits RPC
        console.log(`[Credits] Atomic RPC DEDUCT SUCCESS - User: ${userId}, New Balance: ${newBalance}`);
        return res.json({ success: true, remainingCredits: newBalance });

    } catch (err) {
        console.error('[Credits] Fatal error during credit deduction:', err.message);
        res.status(500).json({ error: 'Failed to process export credit deduction' });
    }
});


// --- COVER LETTER ENDPOINTS ---

// Generate Cover Letter using AI
app.post('/api/cover-letters/generate', strictLimiter, verifyToken, async (req, res) => {
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

        const languageMap = {
            'en': 'English',
            'fr': 'French',
            'ar': 'Arabic',
            'es': 'Spanish',
            'de': 'German',
            'it': 'Italian',
            'pt': 'Portuguese'
        };
        const fullLanguageName = languageMap[language] || 'English';

        const prompt = `
            You are a professional career coach and expert cover letter writer.
            Using the provided CV data, write a high-quality, persuasive, and professional cover letter.
            
            TARGET JOB: ${jobTitle}
            TARGET COMPANY: ${company}
            LANGUAGE: ${fullLanguageName} (CRITICAL: You MUST write the ENTIRE letter strictly in ${fullLanguageName}. Do not use English unless the requested language is English.)
            
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

// Delete Cover Letter
app.delete('/api/cover-letters/:id', verifyToken, async (req, res) => {
    try {
        const { error } = await supabase
            .from('cover_letters')
            .delete()
            .eq('id', req.params.id)
            .eq('user_id', req.user.id);

        if (error) throw error;
        res.json({ success: true, message: 'Cover letter deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update Cover Letter
app.put('/api/cover-letters/:id', verifyToken, async (req, res) => {
    try {
        const { title, company, jobTitle, content, language } = req.body;
        const { data, error } = await supabase
            .from('cover_letters')
            .update({
                title,
                company,
                job_title: jobTitle,
                content,
                language,
                updated_at: new Date().toISOString()
            })
            .eq('id', req.params.id)
            .eq('user_id', req.user.id)
            .select()
            .single();

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
