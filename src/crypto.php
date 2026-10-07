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

function issue_reset_token(string $email): string
{
    $email = strtolower(trim($email));
    $token = bin2hex(random_bytes(32));
    $tokenHash = hash("sha256", $token);
    $pdo = db();
    $pdo->prepare("DELETE FROM reset_tokens WHERE email = ?")->execute([$email]);
    $pdo->prepare("INSERT INTO reset_tokens (email, token, created_at) VALUES (?, ?, datetime('now'))")
        ->execute([$email, $tokenHash]);
    return $token;
}

function consume_reset_token(string $email, string $token): bool
{
    $email = strtolower(trim($email));
    $pdo = db();
    $pdo->exec("BEGIN IMMEDIATE");
    try {
        $row = $pdo->prepare("SELECT token FROM reset_tokens WHERE email = ? AND date(created_at) = date('now')");
        $row->execute([$email]);
        $stored = $row->fetch();
        if (!$stored) {
            $pdo->rollBack();
            return false;
        }

        $tokenHash = hash("sha256", $token);
        if (!hash_equals((string)$stored["token"], $tokenHash)) {
            $pdo->rollBack();
            return false;
        }

        $deleted = $pdo->prepare("DELETE FROM reset_tokens WHERE email = ? AND token = ?");
        $deleted->execute([$email, $stored["token"]]);
        $pdo->commit();
        return $deleted->rowCount() === 1;
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $e;
    }
}
