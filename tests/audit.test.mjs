import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { AuditLog } from '../src/app/audit-log.mjs';

function temporaryAudit() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-audit-'));
  return { directory, file: path.join(directory, 'audit.json') };
}

test('audit chain detects tampering and retains a durable head anchor', () => {
  const { directory, file } = temporaryAudit();
  try {
    const audit = new AuditLog(file, { retention: 2 });
    audit.append({ type: 'first' });
    audit.append({ type: 'second' });
    audit.append({ type: 'third' });

    const verified = new AuditLog(file, { retention: 2 });
    assert.equal(verified.verifyChain().ok, true);
    assert.equal(verified.list(10).length, 2);

    const stored = JSON.parse(fs.readFileSync(file, 'utf8'));
    stored.entries[0].type = 'forged';
    fs.writeFileSync(file, JSON.stringify(stored));
    assert.equal(new AuditLog(file, { retention: 2 }).verifyChain().ok, false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('legacy audit arrays migrate into a verifiable chain on the next append', () => {
  const { directory, file } = temporaryAudit();
  try {
    fs.writeFileSync(file, JSON.stringify([{ at: '2026-10-31T00:00:00.000Z', type: 'legacy' }]));
    const audit = new AuditLog(file);
    assert.equal(audit.verifyChain().ok, true);
    assert.equal(audit.verifyChain().legacyMigrated, true);
    audit.append({ type: 'current' });

    const stored = JSON.parse(fs.readFileSync(file, 'utf8'));
    assert.equal(stored.version, 2);
    assert.equal(new AuditLog(file).verifyChain().ok, true);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
