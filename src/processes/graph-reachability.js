'use strict';

/**
 * basic-graph-reachability · pure-JS BFS over an undirected graph.
 * Per COGOS_PROCESS_DETERMINISM_DOCTRINE_v0.1 §8.8 + §3 (PD-I1..I5).
 *
 * Determinism discipline (§8.8 a–d):
 *   (a) Each node's adjacency list is sorted ascending before BFS.
 *   (b) Tie-break · pred[v] is set ONCE, when v is first reached, by
 *       the smallest-numbered u that reaches it at the shortest
 *       distance · "set once, never overwrite" gives the lex-smallest
 *       predecessor by construction (because adjacency is sorted and
 *       BFS visits sorted-order).
 *   (c) Path output is reconstructed by walking pred[target] → start,
 *       then reversing · anchored to the deterministic predecessor
 *       map, not the queue's encounter order.
 *   (d) Input bounds enforced: nodes ∈ [1, 1000], edges ≤ 10000.
 *
 * Determinism inputs:
 *   - body.now    (ISO-8601 string; PD-I2)
 *   - body.nodes  (integer node count; nodes are 0-indexed)
 *   - body.edges  ([[u,v], ...] undirected; no self-loops; duplicates OK)
 *   - body.start  (integer node index in [0, nodes))
 *   - body.target (integer node index in [0, nodes))
 *
 * Output shape:
 *   { reachable: bool,
 *     distance: integer | null,
 *     path: [integer, ...] | null,
 *     nodes, start, target, now,
 *     process_version }
 *
 * Composes: with int-factor as a multi-step demo (refs `now` from
 * factor step → reachability step). See PD-W4 (pre-flight ref-cascade
 * projection) for v0.2 ergonomic.
 */

const PROCESS_VERSION = 1;
const MAX_NODES = 1000;
const MAX_EDGES = 10000;

function bad(code, message) {
  const err = new Error(message);
  err.code = code;
  throw err;
}

function basicGraphReachability(body) {
  if (!body || typeof body !== 'object') {
    bad('invalid_input', 'basic-graph-reachability: body must be a JSON object');
  }
  // PD-I2 · time anchor from input.
  if (typeof body.now !== 'string' || !body.now) {
    bad('missing_now',
        'basic-graph-reachability requires body.now (ISO-8601 string) per PROCESS_DETERMINISM PD-I2');
  }
  if (!Number.isInteger(body.nodes) || body.nodes < 1 || body.nodes > MAX_NODES) {
    bad('invalid_input',
        `basic-graph-reachability requires body.nodes to be an integer in [1, ${MAX_NODES}]`);
  }
  if (!Array.isArray(body.edges) || body.edges.length > MAX_EDGES) {
    bad('invalid_input',
        `basic-graph-reachability requires body.edges to be an array of length ≤ ${MAX_EDGES}`);
  }
  if (!Number.isInteger(body.start) || body.start < 0 || body.start >= body.nodes) {
    bad('invalid_input',
        'basic-graph-reachability requires body.start to be an integer node index in [0, nodes)');
  }
  if (!Number.isInteger(body.target) || body.target < 0 || body.target >= body.nodes) {
    bad('invalid_input',
        'basic-graph-reachability requires body.target to be an integer node index in [0, nodes)');
  }

  const { nodes, edges, start, target, now } = body;

  // Build adjacency. Reject malformed edges + self-loops.
  const adj = Array.from({ length: nodes }, () => []);
  for (let i = 0; i < edges.length; i++) {
    const e = edges[i];
    if (!Array.isArray(e) || e.length !== 2
        || !Number.isInteger(e[0]) || !Number.isInteger(e[1])
        || e[0] < 0 || e[0] >= nodes
        || e[1] < 0 || e[1] >= nodes
        || e[0] === e[1]) {
      bad('invalid_input', `basic-graph-reachability edge[${i}] is invalid (got ${JSON.stringify(e)})`);
    }
    adj[e[0]].push(e[1]);
    adj[e[1]].push(e[0]);
  }
  // §8.8(a) · sort each adjacency list ascending. Determinism requires
  // a stable canonical traversal order independent of input edge order.
  for (const list of adj) list.sort((a, b) => a - b);

  // BFS · sorted-order traversal · pred set-once (§8.8 b/c).
  const dist = new Array(nodes).fill(-1);
  const pred = new Array(nodes).fill(-1);
  dist[start] = 0;
  const queue = [start];
  let head = 0;
  while (head < queue.length) {
    const u = queue[head++];
    for (const v of adj[u]) {
      if (dist[v] === -1) {
        dist[v] = dist[u] + 1;
        pred[v] = u;
        queue.push(v);
      }
    }
  }

  const reachable = dist[target] !== -1;
  let path = null;
  if (reachable) {
    path = [];
    let cur = target;
    // Walk back via pred · always finite because dist[cur] decreases
    // strictly each hop until cur === start.
    while (cur !== start) {
      path.push(cur);
      cur = pred[cur];
    }
    path.push(start);
    path.reverse();
  }

  return {
    reachable,
    distance: reachable ? dist[target] : null,
    path,
    nodes,
    start,
    target,
    now,
    process_version: PROCESS_VERSION,
  };
}

module.exports = {
  basicGraphReachability,
  PROCESS_VERSION,
  MAX_NODES,
  MAX_EDGES,
};
