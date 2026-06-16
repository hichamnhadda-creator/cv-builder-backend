-- =========================================================================
-- SAFE IDEMPOTENT DATABASE MIGRATION SCRIPT
-- =========================================================================
-- Run this in your Supabase SQL Editor. It will safely check for existing
-- tables, add columns only if they don't exist, and update security policies
-- without losing any production or test data.

-- =========================================================================
-- 1. PROFILES TABLE & MIGRATION
-- =========================================================================
CREATE TABLE IF NOT EXISTS public.profiles (
  id UUID REFERENCES auth.users(id) ON DELETE CASCADE PRIMARY KEY,
  full_name TEXT,
  credits INTEGER DEFAULT 0,
  free_export_count INTEGER DEFAULT 0,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now())
);

-- Safely verify/add columns in case the table already existed
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS full_name TEXT;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS credits INTEGER DEFAULT 0;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS free_export_count INTEGER DEFAULT 0;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now());

-- Enable RLS
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

-- Idempotent RLS Policies
DROP POLICY IF EXISTS "Users can view own profile" ON public.profiles;
DROP POLICY IF EXISTS "Users can update own profile" ON public.profiles;
DROP POLICY IF EXISTS "Users can insert own profile" ON public.profiles;

CREATE POLICY "Users can view own profile" ON public.profiles FOR SELECT USING (auth.uid() = id);
CREATE POLICY "Users can update own profile" ON public.profiles FOR UPDATE USING (auth.uid() = id);
CREATE POLICY "Users can insert own profile" ON public.profiles FOR INSERT WITH CHECK (auth.uid() = id);


-- =========================================================================
-- 2. TRANSACTIONS TABLE & MIGRATION
-- =========================================================================
CREATE TABLE IF NOT EXISTS public.transactions (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  paddle_transaction_id TEXT,
  polar_transaction_id TEXT,
  amount_mad NUMERIC,
  credits_added INTEGER,
  status TEXT,
  payment_method TEXT,
  currency TEXT,
  amount_paid NUMERIC,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now())
);

-- Safely verify/add columns in case the table already existed
ALTER TABLE public.transactions ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE;
ALTER TABLE public.transactions ADD COLUMN IF NOT EXISTS paddle_transaction_id TEXT;
ALTER TABLE public.transactions ADD COLUMN IF NOT EXISTS polar_transaction_id TEXT;
ALTER TABLE public.transactions ADD COLUMN IF NOT EXISTS amount_mad NUMERIC;
ALTER TABLE public.transactions ADD COLUMN IF NOT EXISTS credits_added INTEGER;
ALTER TABLE public.transactions ADD COLUMN IF NOT EXISTS status TEXT;
ALTER TABLE public.transactions ADD COLUMN IF NOT EXISTS payment_method TEXT;
ALTER TABLE public.transactions ADD COLUMN IF NOT EXISTS currency TEXT;
ALTER TABLE public.transactions ADD COLUMN IF NOT EXISTS amount_paid NUMERIC;
ALTER TABLE public.transactions ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now());

-- Enable RLS
ALTER TABLE public.transactions ENABLE ROW LEVEL SECURITY;

-- Idempotent RLS Policies
DROP POLICY IF EXISTS "Users can view own transactions" ON public.transactions;
DROP POLICY IF EXISTS "Users can insert own transactions" ON public.transactions;

CREATE POLICY "Users can view own transactions" ON public.transactions FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can insert own transactions" ON public.transactions FOR INSERT WITH CHECK (auth.uid() = user_id);


-- =========================================================================
-- 3. CVS TABLE & MIGRATION
-- =========================================================================
CREATE TABLE IF NOT EXISTS public.cvs (
  id TEXT PRIMARY KEY,
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  title TEXT,
  templateId TEXT,
  personalInfo JSONB,
  experience JSONB,
  education JSONB,
  diplomas JSONB,
  skills JSONB,
  languages JSONB,
  certifications JSONB,
  projects JSONB,
  customization JSONB,
  createdAt TEXT,
  updatedAt TEXT
);

-- Safely verify/add columns in case the table already existed
ALTER TABLE public.cvs ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE;
ALTER TABLE public.cvs ADD COLUMN IF NOT EXISTS title TEXT;
ALTER TABLE public.cvs ADD COLUMN IF NOT EXISTS templateId TEXT;
ALTER TABLE public.cvs ADD COLUMN IF NOT EXISTS personalInfo JSONB;
ALTER TABLE public.cvs ADD COLUMN IF NOT EXISTS experience JSONB;
ALTER TABLE public.cvs ADD COLUMN IF NOT EXISTS education JSONB;
ALTER TABLE public.cvs ADD COLUMN IF NOT EXISTS diplomas JSONB;
ALTER TABLE public.cvs ADD COLUMN IF NOT EXISTS skills JSONB;
ALTER TABLE public.cvs ADD COLUMN IF NOT EXISTS languages JSONB;
ALTER TABLE public.cvs ADD COLUMN IF NOT EXISTS certifications JSONB;
ALTER TABLE public.cvs ADD COLUMN IF NOT EXISTS projects JSONB;
ALTER TABLE public.cvs ADD COLUMN IF NOT EXISTS customization JSONB;
ALTER TABLE public.cvs ADD COLUMN IF NOT EXISTS createdAt TEXT;
ALTER TABLE public.cvs ADD COLUMN IF NOT EXISTS updatedAt TEXT;

-- Enable RLS
ALTER TABLE public.cvs ENABLE ROW LEVEL SECURITY;

-- Idempotent RLS Policies
DROP POLICY IF EXISTS "Users can view own CVs" ON public.cvs;
DROP POLICY IF EXISTS "Users can insert own CVs" ON public.cvs;
DROP POLICY IF EXISTS "Users can update own CVs" ON public.cvs;
DROP POLICY IF EXISTS "Users can delete own CVs" ON public.cvs;

CREATE POLICY "Users can view own CVs" ON public.cvs FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can insert own CVs" ON public.cvs FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users can update own CVs" ON public.cvs FOR UPDATE USING (auth.uid() = user_id);
CREATE POLICY "Users can delete own CVs" ON public.cvs FOR DELETE USING (auth.uid() = user_id);


-- =========================================================================
-- 4. COVER LETTERS TABLE & MIGRATION
-- =========================================================================
CREATE TABLE IF NOT EXISTS public.cover_letters (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  cv_id TEXT REFERENCES public.cvs(id) ON DELETE SET NULL,
  title TEXT,
  company TEXT,
  job_title TEXT,
  content TEXT,
  language TEXT DEFAULT 'en',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now())
);

-- Safely verify/add columns in case the table already existed
ALTER TABLE public.cover_letters ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE;
ALTER TABLE public.cover_letters ADD COLUMN IF NOT EXISTS cv_id TEXT REFERENCES public.cvs(id) ON DELETE SET NULL;
ALTER TABLE public.cover_letters ADD COLUMN IF NOT EXISTS title TEXT;
ALTER TABLE public.cover_letters ADD COLUMN IF NOT EXISTS company TEXT;
ALTER TABLE public.cover_letters ADD COLUMN IF NOT EXISTS job_title TEXT;
ALTER TABLE public.cover_letters ADD COLUMN IF NOT EXISTS content TEXT;
ALTER TABLE public.cover_letters ADD COLUMN IF NOT EXISTS language TEXT DEFAULT 'en';
ALTER TABLE public.cover_letters ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now());
ALTER TABLE public.cover_letters ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now());

-- Enable RLS
ALTER TABLE public.cover_letters ENABLE ROW LEVEL SECURITY;

-- Idempotent RLS Policies
DROP POLICY IF EXISTS "Users can view own cover letters" ON public.cover_letters;
DROP POLICY IF EXISTS "Users can insert own cover letters" ON public.cover_letters;
DROP POLICY IF EXISTS "Users can update own cover letters" ON public.cover_letters;
DROP POLICY IF EXISTS "Users can delete own cover letters" ON public.cover_letters;

CREATE POLICY "Users can view own cover letters" ON public.cover_letters FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can insert own cover letters" ON public.cover_letters FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users can update own cover letters" ON public.cover_letters FOR UPDATE USING (auth.uid() = user_id);
CREATE POLICY "Users can delete own cover letters" ON public.cover_letters FOR DELETE USING (auth.uid() = user_id);


-- =========================================================================
-- ATOMIC CREDIT PROCEDURES
-- =========================================================================

-- 1. Atomic increment credits (used by Paddle webhook)
CREATE OR REPLACE FUNCTION increment_credits(user_id UUID, amount INTEGER)
RETURNS VOID AS $$
BEGIN
  INSERT INTO public.profiles (id, credits, updated_at)
  VALUES (user_id, amount, timezone('utc'::text, now()))
  ON CONFLICT (id)
  DO UPDATE SET 
    credits = public.profiles.credits + amount,
    updated_at = timezone('utc'::text, now());
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2. Atomic deduct credits (used by CV exports)
-- Fully atomic, blocks concurrent race conditions using SELECT FOR UPDATE,
-- and automatically raises an exception to roll back if credits are insufficient (< 5).
CREATE OR REPLACE FUNCTION deduct_credits(user_id UUID, amount INTEGER)
RETURNS INTEGER AS $$
DECLARE
  current_balance INTEGER;
  new_balance INTEGER;
BEGIN
  -- Select for update to lock the row and prevent race conditions
  SELECT credits INTO current_balance
  FROM public.profiles
  WHERE id = user_id
  FOR UPDATE;

  -- Handle case where profile does not exist
  IF current_balance IS NULL THEN
    RAISE EXCEPTION 'Profile not found for user %', user_id;
  END IF;

  -- Check if user has sufficient credits
  IF current_balance < amount THEN
    RAISE EXCEPTION 'Insufficient credits. Required: %, Available: %', amount, current_balance;
  END IF;

  -- Deduct credits
  new_balance := current_balance - amount;

  -- Update profile balance
  UPDATE public.profiles
  SET 
    credits = new_balance,
    updated_at = timezone('utc'::text, now())
  WHERE id = user_id;

  RETURN new_balance;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
