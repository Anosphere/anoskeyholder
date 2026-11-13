import { env } from '../config/env.js';
import { toHex } from '../util/ids.js';
import { putFile } from './bucket.js';
import { countWaitingCopies, deleteWaitingCopy, findShareWithOwner, listWaitingCopies } from './copies.queries.js';

/**
 * The share copies (spec section 16): every share this keyholder saves is
 * also written to a bucket in the operator's own project, as one small JSON
 * file, so a worker that is lost and restored from its vault lacks none of
 * the shares that arrived after the vault's last copy.
 *
 * /receive-share adds a waiting_copies row in the transaction that saves a
 * share. A copy run takes the waiting rows, oldest first, writes each
 * share's file and deletes its row. A run starts at boot, after every
 * deposit and every 60 seconds, one run at a time. When the bucket does not
 * take a file the run stops there and the rest keeps waiting; no deposit
 * ever fails or waits because of a copy.
 */

/** How many waiting rows a run reads at a time. */
const BATCH = 100;

/** A run starts this often, whatever else starts one. */
const RUN_EVERY_MS = 60_000;

/** How long each of the two calls to Google may take: in a copy run, and in the test at a start. */
const RUN_TIMEOUT_MS = 10_000;
const TEST_TIMEOUT_MS = 5_000;

/** The file of one share: shares/<day>/<share id>.json, the day being the date of the share's created_at in UTC. */
function shareFileName(share) {
  return `shares/${share.createdAt.slice(0, 10)}/${toHex(share.shareId)}.json`;
}

/**
 * What a share's file holds: the share's row and its owner's row and nothing
 * more, every byte column in hex, the two times as PostgreSQL holds them
 * (copies.queries.js), so each row can be put back exactly. The share is as
 * wrapped as it is in the database; no key is in the file.
 */
function shareFileContent({ share, owner }) {
  return `${JSON.stringify(
    {
      version: 1,
      keyholderId: env.keyholderId,
      share: {
        shareId: toHex(share.shareId),
        lookupId: toHex(share.lookupId),
        shareType: share.shareType,
        keyId: toHex(share.keyId),
        share: toHex(share.share),
        wrap: share.wrap,
        createdAt: share.createdAt,
      },
      owner: {
        lookupId: toHex(owner.lookupId),
        publicLedgerId: toHex(owner.publicLedgerId),
        anopodId: toHex(owner.anopodId),
        createdAt: owner.createdAt,
      },
    },
    null,
    2,
  )}\n`;
}

/**
 * How the last runs ended, so that each change is logged once and never
 * once per file: whether the bucket refused a file in the last run that
 * reached it, and whether the last run stopped on an error of its own (the
 * database, as a rule).
 */
let bucketRefuses = false;
let runFails = false;

/**
 * One copy run: the waiting rows, oldest first, BATCH at a time, until none
 * is left or the bucket does not take a file. Never throws.
 */
async function copyRun() {
  try {
    let written = 0;
    for (;;) {
      const shareIds = await listWaitingCopies(BATCH);
      if (shareIds.length === 0) break;

      for (const shareId of shareIds) {
        const copy = await findShareWithOwner(shareId);
        if (copy === null) {
          throw new Error(`the waiting share ${toHex(shareId)} has no row in shares with its owner`);
        }
        const reason = await putFile(shareFileName(copy.share), shareFileContent(copy), RUN_TIMEOUT_MS);
        if (reason !== null) {
          // The run stops here; this share and the ones after it keep waiting.
          const waiting = await countWaitingCopies();
          if (!bucketRefuses) {
            console.error(`Share copies: the bucket did not take a file, ${waiting} waiting: ${reason}`);
          }
          bucketRefuses = true;
          runFails = false;
          return;
        }
        await deleteWaitingCopy(shareId);
        written += 1;
      }
    }

    // Nothing waits any more.
    if (bucketRefuses && written > 0) {
      console.log(`Share copies: the bucket takes files again, ${written} written`);
    }
    bucketRefuses = false;
    runFails = false;
  } catch (err) {
    if (!runFails) console.error('Share copies: the copy run stopped:', err?.message ?? err);
    runFails = true;
  }
}

/** One run at a time: whether one is going, and whether another was asked for meanwhile. */
let running = false;
let askedAgain = false;

/**
 * Asks for a copy run: after every deposit, every RUN_EVERY_MS and once at
 * boot. Asked while a run is going, the next one starts when that one ends.
 * Returns at once and never throws, so nothing a copy does can fail or
 * delay a deposit.
 */
export function startCopyRun() {
  if (running) {
    askedAgain = true;
    return;
  }
  running = true;
  (async () => {
    try {
      do {
        askedAgain = false;
        await copyRun();
      } while (askedAgain);
    } finally {
      running = false;
    }
  })();
}

/** The start, once the keyholder listens: the first copy run, then one every RUN_EVERY_MS. */
export function startShareCopies() {
  startCopyRun();
  setInterval(startCopyRun, RUN_EVERY_MS).unref();
}

/**
 * The test at a start, before the keyholder listens: one small file,
 * tests/<day>/<time>.json, the time to the millisecond, and one line that
 * says whether the bucket took it. Never throws and never stops the start;
 * each of its two calls has TEST_TIMEOUT_MS. The file stays in the bucket
 * for its 365 days, like every file there: one per start.
 */
export async function testShareCopies() {
  const at = new Date().toISOString();
  const content = JSON.stringify({ version: 1, keyholderId: env.keyholderId, test: true, at });
  const reason = await putFile(`tests/${at.slice(0, 10)}/${at}.json`, content, TEST_TIMEOUT_MS);
  if (reason === null) {
    console.log('Share copies: test file ok');
  } else {
    console.error(`Share copies: the bucket did not take the test file: ${reason}`);
  }
}
