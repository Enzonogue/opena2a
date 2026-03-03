/**
 * Shield adaptive baselines: learn / suggest / protect enforcement flow.
 *
 * Baselines track observed agent behavior over time.  The stability
 * algorithm determines when behavior has settled enough to recommend
 * a policy.  The developer must explicitly approve before Shield
 * starts enforcing.
 *
 * Storage: ~/.opena2a/shield/baselines/{agent}.json  (mode 0o600)
 */

import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import type { AgentBaseline, PolicyRules } from './types.js';
import {
  LEARN_PHASE_MIN_ACTIONS,
  LEARN_PHASE_MIN_SESSIONS,
  SESSION_TIMEOUT_MS,
  SHIELD_BASELINES_DIR,
  STABILITY_THRESHOLD,
  STABILITY_WINDOW_SESSIONS,
} from './types.js';

// ---------------------------------------------------------------------------
// Directory helpers
// ---------------------------------------------------------------------------

/** Return the absolute path to the baselines directory. */
function getBaselinesDir(): string {
  const dir = join(homedir(), '.opena2a', 'shield', SHIELD_BASELINES_DIR);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  return dir;
}

/** Return the path to a specific agent's baseline file. */
function baselinePath(agent: string): string {
  return join(getBaselinesDir(), `${agent}.json`);
}

// ---------------------------------------------------------------------------
// In-memory cache (keyed by agent name)
// ---------------------------------------------------------------------------

const cache = new Map<string, { baseline: AgentBaseline; lastActionAt: number }>();

// ---------------------------------------------------------------------------
// Session tracking
// ---------------------------------------------------------------------------

/**
 * Per-session tracking state.  A "session" increments when
 * recordAction is called after SESSION_TIMEOUT_MS of inactivity.
 */
interface SessionState {
  lastActionAt: number;
  currentSessionHadNewBehavior: boolean;
  /** Circular buffer of booleans (true = session had new behavior). */
  recentSessionNewBehavior: boolean[];
}

const sessionStates = new Map<string, SessionState>();

// ---------------------------------------------------------------------------
// Baseline CRUD
// ---------------------------------------------------------------------------

/** Create a fresh baseline for an agent. */
function createBaseline(agent: string): AgentBaseline {
  const now = new Date().toISOString();
  return {
    agent,
    observationStart: now,
    observationEnd: now,
    totalActions: 0,
    totalSessions: 0,
    phase: 'learn',
    stabilityScore: 0,
    lastNewBehaviorAt: null,
    observed: {
      processes: {},
      credentials: {},
      filesystemPaths: {},
      networkHosts: {},
      mcpServers: {},
    },
    recommended: null,
    thresholds: {
      maxProcessesPerHour: 0,
      maxCredentialAccessPerSession: 0,
      maxNewBinariesPerDay: 0,
    },
  };
}

/**
 * Get or create a baseline for an agent.
 *
 * Checks the in-memory cache first, then disk, and finally creates
 * a new baseline if none exists.
 */
export function getBaseline(agent: string): AgentBaseline {
  const cached = cache.get(agent);
  if (cached) return cached.baseline;

  const loaded = loadBaseline(agent);
  if (loaded) {
    cache.set(agent, { baseline: loaded, lastActionAt: 0 });
    return loaded;
  }

  const fresh = createBaseline(agent);
  cache.set(agent, { baseline: fresh, lastActionAt: 0 });
  return fresh;
}

/** List all persisted baselines (loads from disk). */
export function listBaselines(): AgentBaseline[] {
  const dir = getBaselinesDir();
  const baselines: AgentBaseline[] = [];

  let files: string[];
  try {
    files = readdirSync(dir);
  } catch {
    return baselines;
  }

  for (const file of files) {
    if (!file.endsWith('.json')) continue;
    const agent = file.replace(/\.json$/, '');
    const bl = loadBaseline(agent);
    if (bl) baselines.push(bl);
  }

  return baselines;
}

// ---------------------------------------------------------------------------
// Recording actions
// ---------------------------------------------------------------------------

/** Map a category string to the corresponding observed bucket key. */
function categoryToBucket(
  category: string,
): keyof AgentBaseline['observed'] | null {
  switch (category) {
    case 'process':
    case 'processes':
      return 'processes';
    case 'credential':
    case 'credentials':
      return 'credentials';
    case 'filesystem':
      return 'filesystemPaths';
    case 'network':
      return 'networkHosts';
    case 'mcp':
    case 'mcpServers':
      return 'mcpServers';
    default:
      return null;
  }
}

/**
 * Record an observed action from an agent into their baseline.
 *
 * This is the primary entry point for the adaptive enforcement loop.
 * It handles session tracking, new-behavior detection, and stability
 * recomputation.
 */
export function recordAction(
  agent: string,
  category: string,
  target: string,
): void {
  const baseline = getBaseline(agent);
  const now = Date.now();
  const nowIso = new Date(now).toISOString();

  // --- Session tracking ---
  let ss = sessionStates.get(agent);
  if (!ss) {
    ss = {
      lastActionAt: 0,
      currentSessionHadNewBehavior: false,
      recentSessionNewBehavior: [],
    };
    sessionStates.set(agent, ss);
  }

  const elapsed = ss.lastActionAt === 0 ? Infinity : now - ss.lastActionAt;
  if (elapsed >= SESSION_TIMEOUT_MS) {
    // Close previous session if there was one
    if (ss.lastActionAt !== 0) {
      ss.recentSessionNewBehavior.push(ss.currentSessionHadNewBehavior);
      // Keep only the last STABILITY_WINDOW_SESSIONS entries
      if (ss.recentSessionNewBehavior.length > STABILITY_WINDOW_SESSIONS) {
        ss.recentSessionNewBehavior = ss.recentSessionNewBehavior.slice(
          -STABILITY_WINDOW_SESSIONS,
        );
      }
    }
    // Start a new session
    baseline.totalSessions += 1;
    ss.currentSessionHadNewBehavior = false;
  }
  ss.lastActionAt = now;

  // --- Record the action ---
  baseline.totalActions += 1;
  baseline.observationEnd = nowIso;

  const bucket = categoryToBucket(category);
  if (bucket) {
    const observed = baseline.observed[bucket];
    const isNew = !(target in observed);

    observed[target] = (observed[target] ?? 0) + 1;

    if (isNew) {
      baseline.lastNewBehaviorAt = nowIso;
      ss.currentSessionHadNewBehavior = true;
    }
  }

  // --- Recompute stability ---
  baseline.stabilityScore = computeStability(baseline);

  // --- Auto-transition learn -> suggest ---
  if (baseline.phase === 'learn') {
    const transition = checkPhaseTransition(baseline);
    if (transition.shouldTransition) {
      baseline.phase = transition.nextPhase as 'suggest';
      baseline.recommended = buildRecommendedPolicy(baseline);
    }
  }

  // --- Persist ---
  cache.set(agent, { baseline, lastActionAt: now });
  saveBaseline(baseline);
}

// ---------------------------------------------------------------------------
// Stability computation
// ---------------------------------------------------------------------------

/**
 * Compute a stability score between 0.0 and 1.0.
 *
 * Stability measures the fraction of recent sessions that had no new
 * behavior (no previously unseen processes, credentials, etc.).
 *
 * Returns 0 until minimum action and session thresholds are met.
 */
export function computeStability(baseline: AgentBaseline): number {
  if (
    baseline.totalActions < LEARN_PHASE_MIN_ACTIONS ||
    baseline.totalSessions < LEARN_PHASE_MIN_SESSIONS
  ) {
    return 0;
  }

  const ss = sessionStates.get(baseline.agent);
  if (!ss) return 0;

  // Include the current in-progress session in the window
  const sessions = [
    ...ss.recentSessionNewBehavior,
    ss.currentSessionHadNewBehavior,
  ];

  // Take only the last STABILITY_WINDOW_SESSIONS
  const window = sessions.slice(-STABILITY_WINDOW_SESSIONS);
  if (window.length === 0) return 0;

  const stableSessions = window.filter((hadNew) => !hadNew).length;
  return stableSessions / window.length;
}

// ---------------------------------------------------------------------------
// Phase transitions
// ---------------------------------------------------------------------------

/**
 * Check whether a baseline should transition phases.
 *
 * - learn -> suggest: stability >= STABILITY_THRESHOLD
 * - suggest -> protect: manual approval only (approvePolicy)
 */
export function checkPhaseTransition(baseline: AgentBaseline): {
  shouldTransition: boolean;
  nextPhase: string;
  reason: string;
} {
  if (baseline.phase === 'learn') {
    if (baseline.totalActions < LEARN_PHASE_MIN_ACTIONS) {
      return {
        shouldTransition: false,
        nextPhase: 'learn',
        reason: `Need ${LEARN_PHASE_MIN_ACTIONS - baseline.totalActions} more actions before stability check`,
      };
    }
    if (baseline.totalSessions < LEARN_PHASE_MIN_SESSIONS) {
      return {
        shouldTransition: false,
        nextPhase: 'learn',
        reason: `Need ${LEARN_PHASE_MIN_SESSIONS - baseline.totalSessions} more sessions before stability check`,
      };
    }

    const stability = computeStability(baseline);
    if (stability >= STABILITY_THRESHOLD) {
      return {
        shouldTransition: true,
        nextPhase: 'suggest',
        reason: `Stability score ${stability.toFixed(2)} >= ${STABILITY_THRESHOLD} threshold`,
      };
    }
    return {
      shouldTransition: false,
      nextPhase: 'learn',
      reason: `Stability score ${stability.toFixed(2)} < ${STABILITY_THRESHOLD} threshold`,
    };
  }

  if (baseline.phase === 'suggest') {
    return {
      shouldTransition: false,
      nextPhase: 'suggest',
      reason: 'Awaiting developer approval to transition to protect',
    };
  }

  // Already in protect phase
  return {
    shouldTransition: false,
    nextPhase: 'protect',
    reason: 'Already in protect phase',
  };
}

// ---------------------------------------------------------------------------
// Policy approval (suggest -> protect)
// ---------------------------------------------------------------------------

/**
 * Approve the recommended policy for an agent, transitioning
 * from suggest to protect phase.
 */
export function approvePolicy(agent: string): AgentBaseline {
  const baseline = getBaseline(agent);

  if (baseline.phase !== 'suggest') {
    throw new Error(
      `Cannot approve policy for agent "${agent}" in phase "${baseline.phase}". ` +
        'Agent must be in suggest phase.',
    );
  }

  if (!baseline.recommended) {
    baseline.recommended = buildRecommendedPolicy(baseline);
  }

  baseline.phase = 'protect';
  cache.set(agent, {
    baseline,
    lastActionAt: cache.get(agent)?.lastActionAt ?? 0,
  });
  saveBaseline(baseline);

  return baseline;
}

// ---------------------------------------------------------------------------
// Recommended policy builder
// ---------------------------------------------------------------------------

/** Build a recommended policy from observed behavior. */
function buildRecommendedPolicy(baseline: AgentBaseline): Partial<PolicyRules> {
  const toAllowList = (observed: Record<string, number>): string[] =>
    Object.keys(observed);

  return {
    processes: {
      allow: toAllowList(baseline.observed.processes),
      deny: [],
    },
    credentials: {
      allow: toAllowList(baseline.observed.credentials),
      deny: [],
    },
    filesystem: {
      allow: toAllowList(baseline.observed.filesystemPaths),
      deny: [],
    },
    network: {
      allow: toAllowList(baseline.observed.networkHosts),
      deny: [],
    },
    mcpServers: {
      allow: toAllowList(baseline.observed.mcpServers),
      deny: [],
    },
  };
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/** Save a baseline to disk at ~/.opena2a/shield/baselines/{agent}.json. */
export function saveBaseline(baseline: AgentBaseline): void {
  const filePath = baselinePath(baseline.agent);
  const data = JSON.stringify(baseline, null, 2) + '\n';

  writeFileSync(filePath, data, { encoding: 'utf-8', mode: 0o600 });

  try {
    chmodSync(filePath, 0o600);
  } catch {
    // Best-effort
  }
}

/** Load a baseline from disk. Returns null if not found or corrupted. */
export function loadBaseline(agent: string): AgentBaseline | null {
  const filePath = baselinePath(agent);

  if (!existsSync(filePath)) return null;

  try {
    const raw = readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(raw) as AgentBaseline;

    // Basic validation
    if (!parsed.agent || typeof parsed.totalActions !== 'number') {
      return null;
    }

    return parsed;
  } catch {
    return null;
  }
}
