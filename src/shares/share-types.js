/**
 * The four secrets a share can be of, as payload.shareType names them (spec
 * section 0), each with who gets the share back: a moderator for the two
 * bucket keys, the keyholder (through the home computer, for a recovery pod)
 * for the break-glass key and the backup code. Section 6 says how each is
 * stored (wraps.js).
 */
export const SECURITY_BUCKET_1 = 'securitybucket1';
export const SECURITY_BUCKET_2 = 'securitybucket2';
export const BREAK_GLASS_KEY = 'breakglasskey';
export const BACKUP_CODE = 'backupcode';

/** The four names, for the shape check of /receive-share. */
export const SHARE_TYPES = Object.freeze([SECURITY_BUCKET_1, SECURITY_BUCKET_2, BREAK_GLASS_KEY, BACKUP_CODE]);

/** True when `name` is one of the four share types. */
export function isShareType(name) {
  return SHARE_TYPES.includes(name);
}
