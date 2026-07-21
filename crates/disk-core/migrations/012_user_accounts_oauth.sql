-- 012_user_accounts_oauth.sql — OAuth identity columns (DISK-0016 slice 2).

ALTER TABLE user_accounts ADD COLUMN oauth_provider TEXT;
ALTER TABLE user_accounts ADD COLUMN oauth_subject TEXT;

CREATE UNIQUE INDEX idx_user_accounts_oauth
    ON user_accounts(oauth_provider, oauth_subject)
    WHERE oauth_provider IS NOT NULL AND oauth_subject IS NOT NULL;
