-- Run this SQL in your Supabase SQL Editor to fix the missing table and column

-- 1. Create the domain_verifications table if it doesn't exist
CREATE TABLE IF NOT EXISTS domain_verifications (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    host_label VARCHAR(512) NOT NULL,
    token VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    verification_attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    last_checked_at TIMESTAMPTZ,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, domain)
);

-- Create index for faster lookups by user_id
CREATE INDEX IF NOT EXISTS ix_domain_verifications_user_id ON domain_verifications(user_id);

-- 2. Add executive_summary column to owasp_scans if it doesn't exist
DO $$ 
BEGIN 
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'owasp_scans' AND column_name = 'executive_summary'
    ) THEN
        ALTER TABLE owasp_scans ADD COLUMN executive_summary TEXT;
    END IF;
END $$;

-- 3. Enable Row Level Security (RLS) on domain_verifications
ALTER TABLE domain_verifications ENABLE ROW LEVEL SECURITY;

-- 4. Create RLS policies for domain_verifications
-- Users can only see their own domains
DROP POLICY IF EXISTS "Users can view own domains" ON domain_verifications;
CREATE POLICY "Users can view own domains" ON domain_verifications
    FOR SELECT USING (auth.uid()::TEXT = user_id);

-- Users can insert their own domains
DROP POLICY IF EXISTS "Users can insert own domains" ON domain_verifications;
CREATE POLICY "Users can insert own domains" ON domain_verifications
    FOR INSERT WITH CHECK (auth.uid()::TEXT = user_id);

-- Users can update their own domains
DROP POLICY IF EXISTS "Users can update own domains" ON domain_verifications;
CREATE POLICY "Users can update own domains" ON domain_verifications
    FOR UPDATE USING (auth.uid()::TEXT = user_id);

-- Users can delete their own domains
DROP POLICY IF EXISTS "Users can delete own domains" ON domain_verifications;
CREATE POLICY "Users can delete own domains" ON domain_verifications
    FOR DELETE USING (auth.uid()::TEXT = user_id);

-- 5. Grant necessary permissions to authenticated users
GRANT SELECT, INSERT, UPDATE, DELETE ON domain_verifications TO authenticated;

-- 6. Create updated_at trigger for domain_verifications
CREATE OR REPLACE FUNCTION update_domain_verifications_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_domain_verifications_updated_at ON domain_verifications;
CREATE TRIGGER trigger_update_domain_verifications_updated_at
    BEFORE UPDATE ON domain_verifications
    FOR EACH ROW
    EXECUTE FUNCTION update_domain_verifications_updated_at();

-- Verify the changes
SELECT 'domain_verifications table created' AS status
WHERE EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'domain_verifications');

SELECT 'executive_summary column exists' AS status
WHERE EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'owasp_scans' AND column_name = 'executive_summary');
