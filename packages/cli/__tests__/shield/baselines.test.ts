import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';

// ---------------------------------------------------------------------------
// Mock node:os so that homedir() returns our temp directory.
// ---------------------------------------------------------------------------

let _mockHomeDir = '';

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return {
    ...actual,
    homedir: () => _mockHomeDir,
  };
});

// Import after mocks so the modules pick up the mocked homedir.
const {
  recordAction,
  getBaseline,
  listBaselines,
  computeStability,
  checkPhaseTransition,
  approvePolicy,
  saveBaseline,
  loadBaseline,
} = await import('../../src/shield/baselines.js');

const {
  LEARN_PHASE_MIN_ACTIONS,
  LEARN_PHASE_MIN_SESSIONS,
  STABILITY_THRESHOLD,
  SESSION_TIMEOUT_MS,
} = await import('../../src/shield/types.js');

// ---------------------------------------------------------------------------
// Temp directory setup
// ---------------------------------------------------------------------------

let tempDir: string;

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-baselines-test-'));
  _mockHomeDir = tempDir;
});

afterEach(() => {
  fs.rmSync(tempDir, { recursive: true, force: true });
});

// ===========================================================================
// 1. recordAction creates a baseline
// ===========================================================================

describe('recordAction', () => {
  it('creates a baseline on first action', () => {
    recordAction('test-agent-1', 'processes', '/usr/bin/node');

    const bl = getBaseline('test-agent-1');
    expect(bl.agent).toBe('test-agent-1');
    expect(bl.totalActions).toBe(1);
    expect(bl.totalSessions).toBe(1);
    expect(bl.phase).toBe('learn');
    expect(bl.observed.processes['/usr/bin/node']).toBe(1);
  });

  it('increments action count on subsequent actions', () => {
    recordAction('test-agent-2', 'processes', '/usr/bin/node');
    recordAction('test-agent-2', 'processes', '/usr/bin/node');
    recordAction('test-agent-2', 'credentials', 'github-token');

    const bl = getBaseline('test-agent-2');
    expect(bl.totalActions).toBe(3);
    expect(bl.observed.processes['/usr/bin/node']).toBe(2);
    expect(bl.observed.credentials['github-token']).toBe(1);
  });

  it('maps category aliases correctly', () => {
    recordAction('test-agent-3', 'process', '/usr/bin/cat');
    recordAction('test-agent-3', 'credential', 'aws-key');
    recordAction('test-agent-3', 'filesystem', '/etc/hosts');
    recordAction('test-agent-3', 'network', 'api.github.com');
    recordAction('test-agent-3', 'mcp', 'filesystem-server');

    const bl = getBaseline('test-agent-3');
    expect(bl.observed.processes['/usr/bin/cat']).toBe(1);
    expect(bl.observed.credentials['aws-key']).toBe(1);
    expect(bl.observed.filesystemPaths['/etc/hosts']).toBe(1);
    expect(bl.observed.networkHosts['api.github.com']).toBe(1);
    expect(bl.observed.mcpServers['filesystem-server']).toBe(1);
  });

  it('marks lastNewBehaviorAt on unseen targets', () => {
    recordAction('test-agent-4', 'processes', '/usr/bin/node');
    const bl = getBaseline('test-agent-4');
    expect(bl.lastNewBehaviorAt).not.toBeNull();

    const firstNewAt = bl.lastNewBehaviorAt;

    // Same target -- should not update lastNewBehaviorAt
    recordAction('test-agent-4', 'processes', '/usr/bin/node');
    const bl2 = getBaseline('test-agent-4');
    expect(bl2.lastNewBehaviorAt).toBe(firstNewAt);

    // New target -- should update (may be same millisecond, so just
    // verify lastNewBehaviorAt is still set and the target was recorded)
    recordAction('test-agent-4', 'processes', '/usr/bin/git');
    const bl3 = getBaseline('test-agent-4');
    expect(bl3.lastNewBehaviorAt).not.toBeNull();
    // The new target must have been added to the observed map
    expect(bl3.observed.processes['/usr/bin/git']).toBe(1);
    // lastNewBehaviorAt should be >= the first timestamp
    expect(new Date(bl3.lastNewBehaviorAt!).getTime()).toBeGreaterThanOrEqual(
      new Date(firstNewAt!).getTime(),
    );
  });

  it('persists baseline to disk', () => {
    recordAction('test-agent-5', 'processes', '/usr/bin/node');

    const filePath = path.join(
      tempDir,
      '.opena2a',
      'shield',
      'baselines',
      'test-agent-5.json',
    );
    expect(fs.existsSync(filePath)).toBe(true);

    const raw = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    expect(raw.agent).toBe('test-agent-5');
    expect(raw.totalActions).toBe(1);
  });
});

// ===========================================================================
// 2. Stability starts at 0
// ===========================================================================

describe('computeStability', () => {
  it('returns 0 when below minimum thresholds', () => {
    recordAction('stability-agent-1', 'processes', '/usr/bin/node');

    const bl = getBaseline('stability-agent-1');
    expect(computeStability(bl)).toBe(0);
    expect(bl.stabilityScore).toBe(0);
  });

  it('returns 0 when below minimum sessions', () => {
    // Record many actions but only 1 session (no timeout gap)
    for (let i = 0; i < LEARN_PHASE_MIN_ACTIONS + 10; i++) {
      recordAction('stability-agent-2', 'processes', '/usr/bin/node');
    }

    const bl = getBaseline('stability-agent-2');
    // Only 1 session since no timeout gap
    expect(bl.totalSessions).toBe(1);
    expect(computeStability(bl)).toBe(0);
  });
});

// ===========================================================================
// 3. Phase transitions
// ===========================================================================

describe('checkPhaseTransition', () => {
  it('reports insufficient actions', () => {
    recordAction('phase-agent-1', 'processes', '/usr/bin/node');

    const bl = getBaseline('phase-agent-1');
    const result = checkPhaseTransition(bl);
    expect(result.shouldTransition).toBe(false);
    expect(result.nextPhase).toBe('learn');
    expect(result.reason).toContain('actions');
  });

  it('reports insufficient sessions', () => {
    // Create baseline with enough actions but only 1 session
    const bl = getBaseline('phase-agent-2');
    bl.totalActions = LEARN_PHASE_MIN_ACTIONS + 1;
    bl.totalSessions = 1;

    const result = checkPhaseTransition(bl);
    expect(result.shouldTransition).toBe(false);
    expect(result.nextPhase).toBe('learn');
    expect(result.reason).toContain('sessions');
  });

  it('reports awaiting approval in suggest phase', () => {
    const bl = getBaseline('phase-agent-3');
    bl.phase = 'suggest';

    const result = checkPhaseTransition(bl);
    expect(result.shouldTransition).toBe(false);
    expect(result.nextPhase).toBe('suggest');
    expect(result.reason).toContain('approval');
  });

  it('reports already in protect phase', () => {
    const bl = getBaseline('phase-agent-4');
    bl.phase = 'protect';

    const result = checkPhaseTransition(bl);
    expect(result.shouldTransition).toBe(false);
    expect(result.nextPhase).toBe('protect');
    expect(result.reason).toContain('protect');
  });
});

// ===========================================================================
// 4. Save/load round-trip
// ===========================================================================

describe('save and load', () => {
  it('round-trips a baseline through disk', () => {
    recordAction('roundtrip-agent', 'processes', '/usr/bin/node');
    recordAction('roundtrip-agent', 'credentials', 'github-token');
    recordAction('roundtrip-agent', 'network', 'api.github.com');

    const original = getBaseline('roundtrip-agent');
    saveBaseline(original);

    const loaded = loadBaseline('roundtrip-agent');
    expect(loaded).not.toBeNull();
    expect(loaded!.agent).toBe(original.agent);
    expect(loaded!.totalActions).toBe(original.totalActions);
    expect(loaded!.totalSessions).toBe(original.totalSessions);
    expect(loaded!.phase).toBe(original.phase);
    expect(loaded!.observed.processes).toEqual(original.observed.processes);
    expect(loaded!.observed.credentials).toEqual(original.observed.credentials);
    expect(loaded!.observed.networkHosts).toEqual(original.observed.networkHosts);
  });

  it('returns null for non-existent agent', () => {
    const loaded = loadBaseline('does-not-exist');
    expect(loaded).toBeNull();
  });

  it('returns null for corrupted file', () => {
    // Write invalid JSON to the baseline file
    const dir = path.join(tempDir, '.opena2a', 'shield', 'baselines');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'corrupt-agent.json'), 'not valid json');

    const loaded = loadBaseline('corrupt-agent');
    expect(loaded).toBeNull();
  });

  it('sets file permissions to 0o600', () => {
    recordAction('perms-agent', 'processes', '/usr/bin/node');

    const filePath = path.join(
      tempDir,
      '.opena2a',
      'shield',
      'baselines',
      'perms-agent.json',
    );
    const stat = fs.statSync(filePath);
    // 0o600 = 384 decimal; mask off file type bits
    expect(stat.mode & 0o777).toBe(0o600);
  });
});

// ===========================================================================
// 5. listBaselines
// ===========================================================================

describe('listBaselines', () => {
  it('returns empty array when no baselines exist', () => {
    const result = listBaselines();
    expect(result).toEqual([]);
  });

  it('lists all persisted baselines', () => {
    recordAction('list-agent-a', 'processes', '/usr/bin/node');
    recordAction('list-agent-b', 'credentials', 'token');

    const result = listBaselines();
    expect(result.length).toBe(2);
    const names = result.map((bl) => bl.agent).sort();
    expect(names).toEqual(['list-agent-a', 'list-agent-b']);
  });
});

// ===========================================================================
// 6. getBaseline
// ===========================================================================

describe('getBaseline', () => {
  it('creates a fresh baseline for unknown agent', () => {
    const bl = getBaseline('new-agent');
    expect(bl.agent).toBe('new-agent');
    expect(bl.totalActions).toBe(0);
    expect(bl.totalSessions).toBe(0);
    expect(bl.phase).toBe('learn');
    expect(bl.stabilityScore).toBe(0);
  });

  it('returns cached baseline on second call', () => {
    recordAction('cached-agent', 'processes', '/usr/bin/node');

    const first = getBaseline('cached-agent');
    const second = getBaseline('cached-agent');
    // Should be the same object reference (from cache)
    expect(first).toBe(second);
  });
});

// ===========================================================================
// 7. approvePolicy
// ===========================================================================

describe('approvePolicy', () => {
  it('transitions from suggest to protect', () => {
    recordAction('approve-agent', 'processes', '/usr/bin/node');
    const bl = getBaseline('approve-agent');
    bl.phase = 'suggest';
    saveBaseline(bl);

    const approved = approvePolicy('approve-agent');
    expect(approved.phase).toBe('protect');
    expect(approved.recommended).not.toBeNull();
    expect(approved.recommended!.processes!.allow).toContain('/usr/bin/node');
  });

  it('throws when not in suggest phase', () => {
    recordAction('no-approve-agent', 'processes', '/usr/bin/node');

    expect(() => approvePolicy('no-approve-agent')).toThrow(
      /suggest phase/,
    );
  });

  it('persists the approved baseline to disk', () => {
    recordAction('persist-approve-agent', 'processes', '/usr/bin/node');
    const bl = getBaseline('persist-approve-agent');
    bl.phase = 'suggest';
    saveBaseline(bl);

    approvePolicy('persist-approve-agent');

    const loaded = loadBaseline('persist-approve-agent');
    expect(loaded).not.toBeNull();
    expect(loaded!.phase).toBe('protect');
  });
});

// ===========================================================================
// 8. Session tracking
// ===========================================================================

describe('session tracking', () => {
  it('starts with session count 1 on first action', () => {
    recordAction('session-agent-1', 'processes', '/usr/bin/node');

    const bl = getBaseline('session-agent-1');
    expect(bl.totalSessions).toBe(1);
  });

  it('does not increment session within timeout window', () => {
    recordAction('session-agent-2', 'processes', '/usr/bin/node');
    recordAction('session-agent-2', 'processes', '/usr/bin/git');
    recordAction('session-agent-2', 'processes', '/usr/bin/cat');

    const bl = getBaseline('session-agent-2');
    // All actions within the same test execution = same session
    expect(bl.totalSessions).toBe(1);
  });
});

// ===========================================================================
// 9. Unknown categories are handled gracefully
// ===========================================================================

describe('unknown category handling', () => {
  it('records action count but does not populate observed buckets', () => {
    recordAction('unknown-cat-agent', 'banana', 'yellow');

    const bl = getBaseline('unknown-cat-agent');
    expect(bl.totalActions).toBe(1);
    // No observed bucket should contain "yellow"
    expect(Object.keys(bl.observed.processes)).toEqual([]);
    expect(Object.keys(bl.observed.credentials)).toEqual([]);
    expect(Object.keys(bl.observed.filesystemPaths)).toEqual([]);
    expect(Object.keys(bl.observed.networkHosts)).toEqual([]);
    expect(Object.keys(bl.observed.mcpServers)).toEqual([]);
  });
});
