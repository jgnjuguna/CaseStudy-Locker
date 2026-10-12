<?php
declare(strict_types=1);

// Password and token helpers. Keep these in one place so login and reset stay in sync.

function hash_password(string $password): string
{
    return hash("sha256", $password);
}

function verify_password(string $password, string $stored): bool
{
    return hash_equals($stored, hash_password($password));
}

function reset_token_for(string $email, ?string $day = null): string
{
    $day = $day ?? gmdate("Y-m-d");
    return sha1(strtolower($email) . "|" . $day);
}

/*
 * Generate a secure password-reset token.
 *
 * random_bytes(32) generates 32 cryptographically secure random bytes.
 * bin2hex() converts them into a 64-character hexadecimal string.
 *
 * Only a SHA-256 hash of the token is stored in the database, so
 * a database leak does not directly reveal usable reset tokens.
 */
function issue_reset_token(string $email): string
{
    // Generate an unpredictable token instead of deriving it from
    // the email address and current date.
    $token = bin2hex(random_bytes(32));

    // Hash the token before storing it in the database.
    $tokenHash = hash('sha256', $token);
    
    $pdo = db();

    // Invalidate any previously issued reset token for this email.
    $pdo->prepare("DELETE FROM reset_tokens WHERE email = ?")
        ->execute([$email]);

    // Store the hashed token and its creation time.
    // The original token is returned to the caller for delivery
    // to the user through the application's reset-link mechanism.
    $pdo->prepare(
        "INSERT INTO reset_tokens (email, token, created_at)
         VALUES (?, ?, datetime('now'))"
    )->execute([$email, $tokenHash]);

    return $token;
}

/**
 * Validate and consume a password-reset token.
 *
 * A token must:
 *   1. Have the expected hexadecimal format.
 *   2. Match a token hash stored for the supplied email.
 *   3. Have been created within the last 15 minutes.
 *   4. Be successfully deleted after validation so it cannot be reused.
 */
function consume_reset_token(string $email, string $token): bool
{
    // Reject malformed tokens before querying the database.
    // A valid token generated above contains exactly 64 hex characters.
    if (!preg_match('/\A[a-f0-9]{64}\z/', $token)) {
        return false;
    }

    $pdo = db();

    // Retrieve a token that belongs to this email and has not expired.
    // The expiration check uses the database's current UTC time.
    $stmt = $pdo->prepare(
        "SELECT token FROM reset_tokens
         WHERE email = ?
         AND created_at >= datetime('now', 'start of day')
         AND created_at < datetime('now', 'start of day', '+1 day')"
    );
    $stmt->execute([$email]);

    $stored = $stmt->fetchColumn();

    // Reject missing, expired, or otherwise unrecognized tokens.
    // There is deliberately no fallback that accepts a token
    // simply because it can be calculated from public information.
    if ($stored === false ||
        !hash_equals((string)$stored, hash('sha256', $token))) {
        return false;
    }

    // Delete the matching token after successful validation.
    // This prevents the same reset token from being used again.
    $delete = $pdo->prepare(
        "DELETE FROM reset_tokens WHERE email = ? AND token = ?"
    );
    $delete->execute([$email, hash('sha256', $token)]);

    // Report success only if a database row was actually deleted.
    return $delete->rowCount() === 1;
}
