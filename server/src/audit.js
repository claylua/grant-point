import { query } from './db.js';

export async function recordAuditEvent({
  userId = null,
  username = null,
  action,
  details = null,
  ipAddress = null,
  method = null,
  path = null,
}) {
  if (!action) {
    return;
  }

  const serializedDetails =
    details === null || details === undefined ? null : JSON.stringify(details);

  try {
    await query(
      `INSERT INTO audit_logs (
        user_id,
        username,
        action,
        details,
        ip_address,
        method,
        path
      ) VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7)`,
      [userId, username, action, serializedDetails, ipAddress, method, path]
    );
  } catch (error) {
    console.error('Failed to record audit event', error);
  }
}

export async function getRecentAuditLogs({ limit = 100 } = {}) {
  const safeLimit = Number.isInteger(limit) && limit > 0 ? Math.min(limit, 500) : 100;
  const { rows } = await query(
    `SELECT id, user_id, username, action, details, ip_address, method, path, created_at
     FROM audit_logs
     ORDER BY created_at DESC
     LIMIT $1`,
    [safeLimit]
  );
  return rows;
}
