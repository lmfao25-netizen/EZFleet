/**
 * EZFleet backend server.
 *
 * A small self-hosted API: per-user accounts (JWT auth), one shared fleet
 * dataset (vehicles, locations, categories), and multi-user issue reports
 * and calendar events stored as real server-side rows so every account
 * sees the same live data.
 *
 * Run with:  npm install && npm start
 * Config via .env (see .env.example).
 */
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_ME_DEV_ONLY_SECRET';
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'data', 'ezfleet.db');
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || '*'; // set to your hosted frontend origin in production
const ALLOW_REGISTRATION = (process.env.ALLOW_REGISTRATION || 'true') === 'true';

if (JWT_SECRET === 'CHANGE_ME_DEV_ONLY_SECRET') {
  console.warn('[ezfleet] WARNING: using the default JWT_SECRET. Set JWT_SECRET in your .env before deploying for real.');
}

fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
const db = new Database(DB_FILE);
db.pragma('journal_mode = WAL');

/* =========================================================
   SCHEMA
   ========================================================= */
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  role_id TEXT,
  avatar TEXT,
  job_position TEXT,
  phone TEXT,
  email TEXT,
  location_id TEXT
);

CREATE TABLE IF NOT EXISTS roles (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,               -- manage roles, company logo, import/export — Administrator only
  can_view_all_locations INTEGER NOT NULL DEFAULT 0, -- bypass the single-location restriction
  can_move_vehicle_location INTEGER NOT NULL DEFAULT 0,
  can_manage_vehicles INTEGER NOT NULL DEFAULT 0,     -- add / delete units
  can_manage_photos INTEGER NOT NULL DEFAULT 0,       -- add / remove photos (everyone can always view them)
  can_view_parts INTEGER NOT NULL DEFAULT 0,
  can_manage_parts INTEGER NOT NULL DEFAULT 0,
  can_edit_vehicle_info INTEGER NOT NULL DEFAULT 0,   -- status, VIN, model, year, engine, category, subcategory, unit #
  can_manage_maintenance INTEGER NOT NULL DEFAULT 0,  -- maintenance logs+schedule, repairs, appointments
  can_create_work_orders INTEGER NOT NULL DEFAULT 0,
  can_manage_reports INTEGER NOT NULL DEFAULT 0,      -- edit severity / delete a report (everyone can always file one)
  can_approve_permits INTEGER NOT NULL DEFAULT 0,     -- approve/close a work permit (everyone can always request one)
  can_manage_subcategories INTEGER NOT NULL DEFAULT 0, -- add/remove truck & trailer subcategories
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS vehicles (
  id TEXT PRIMARY KEY,
  data TEXT NOT NULL,        -- JSON blob: category, location, subcategory, unitNumber, vin, year,
                              -- model, engineDisplacement, status, photos[], parts[], repairs[],
                              -- tires{}, maintenanceSchedule[], maintenanceHistory[]
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  vehicle_id TEXT NOT NULL,
  reporter_user_id TEXT,
  reporter_name TEXT NOT NULL,
  description TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'minor',
  photo TEXT,
  created_at INTEGER NOT NULL,
  resolved_work_order_id TEXT,
  FOREIGN KEY (vehicle_id) REFERENCES vehicles(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS work_orders (
  id TEXT PRIMARY KEY,
  seq INTEGER NOT NULL UNIQUE,        -- guaranteed-unique work order number
  vehicle_id TEXT NOT NULL,
  unit_number TEXT,
  report_id TEXT,
  reporter_name TEXT,
  reported_at INTEGER,
  description TEXT NOT NULL,
  completed_by_user_id TEXT,
  completed_by_name TEXT NOT NULL,
  completed_at INTEGER NOT NULL,
  FOREIGN KEY (vehicle_id) REFERENCES vehicles(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS counters (
  name TEXT PRIMARY KEY,
  value INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS maintenance_logs (
  id TEXT PRIMARY KEY,
  vehicle_id TEXT NOT NULL,
  unit_number TEXT,
  type TEXT NOT NULL,
  completed_by_user_id TEXT,
  completed_by_name TEXT NOT NULL,
  completed_at INTEGER NOT NULL,
  notes TEXT,
  FOREIGN KEY (vehicle_id) REFERENCES vehicles(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS work_permits (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,                        -- 'hotwork' | 'enclosedspace' | 'heightwork'
  status TEXT NOT NULL DEFAULT 'requested',  -- 'requested' -> 'approved' -> 'closed'
  data TEXT NOT NULL,                        -- JSON blob; shape depends on permit type and stage
  requested_by_user_id TEXT, requested_by_name TEXT, requested_at INTEGER,
  approved_by_user_id TEXT, approved_by_name TEXT, approved_at INTEGER,
  closed_by_user_id TEXT, closed_by_name TEXT, closed_at INTEGER
);

CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  vehicle_id TEXT,
  title TEXT NOT NULL,
  date TEXT NOT NULL,
  time TEXT,
  reminder_days INTEGER NOT NULL DEFAULT 0,
  notes TEXT,
  created_by_user_id TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS locations (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS subcategories (
  id TEXT NOT NULL,
  category TEXT NOT NULL,     -- 'truck' | 'trailer'
  label TEXT NOT NULL,
  PRIMARY KEY (id, category)
);

CREATE TABLE IF NOT EXISTS part_categories (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);
`);

// Lightweight migration for servers that were already running before work
// orders existed: add the linking column if it isn't there yet.
try { db.exec('ALTER TABLE reports ADD COLUMN resolved_work_order_id TEXT'); } catch (e) { /* column already exists */ }

// Lightweight migrations for servers that predate roles & profiles.
['role_id', 'avatar', 'job_position', 'phone', 'email', 'location_id'].forEach((col) => {
  try { db.exec(`ALTER TABLE users ADD COLUMN ${col} TEXT`); } catch (e) { /* column already exists */ }
});
// Lightweight migration for servers that predate the full permission matrix.
[
  'can_view_all_locations', 'can_move_vehicle_location', 'can_manage_vehicles', 'can_manage_photos',
  'can_view_parts', 'can_manage_parts', 'can_edit_vehicle_info', 'can_manage_maintenance',
  'can_create_work_orders', 'can_manage_reports', 'can_approve_permits', 'can_manage_subcategories',
].forEach((col) => {
  try { db.exec(`ALTER TABLE roles ADD COLUMN ${col} INTEGER NOT NULL DEFAULT 0`); } catch (e) { /* column already exists */ }
});

// Migration for servers that predate work permits being decoupled from units:
// rebuild the table without vehicle_id/unit_number (SQLite can't drop a
// NOT NULL column in place). Existing permits are preserved.
try {
  const cols = db.prepare("PRAGMA table_info(work_permits)").all();
  if (cols.some((c) => c.name === 'vehicle_id')) {
    db.exec(`
      CREATE TABLE work_permits_new (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'requested',
        data TEXT NOT NULL,
        requested_by_user_id TEXT, requested_by_name TEXT, requested_at INTEGER,
        approved_by_user_id TEXT, approved_by_name TEXT, approved_at INTEGER,
        closed_by_user_id TEXT, closed_by_name TEXT, closed_at INTEGER
      );
      INSERT INTO work_permits_new (id, type, status, data, requested_by_user_id, requested_by_name, requested_at, approved_by_user_id, approved_by_name, approved_at, closed_by_user_id, closed_by_name, closed_at)
        SELECT id, type, status, data, requested_by_user_id, requested_by_name, requested_at, approved_by_user_id, approved_by_name, approved_at, closed_by_user_id, closed_by_name, closed_at FROM work_permits;
      DROP TABLE work_permits;
      ALTER TABLE work_permits_new RENAME TO work_permits;
    `);
  }
} catch (e) { console.warn('work_permits migration skipped:', e.message); }

function uid() {
  return crypto.randomBytes(12).toString('hex');
}

function nextWorkOrderNumber() {
  const txn = db.transaction(() => {
    const row = db.prepare('SELECT value FROM counters WHERE name = ?').get('work_order');
    const next = row ? row.value + 1 : 1001; // start at 1001 so the first WO looks like a real ticket number
    if (row) db.prepare('UPDATE counters SET value = ? WHERE name = ?').run(next, 'work_order');
    else db.prepare('INSERT INTO counters (name, value) VALUES (?, ?)').run('work_order', next);
    return next;
  });
  return txn();
}

const VALID_MAINTENANCE_TYPES = [
  'ctrl3months', 'ctrl6months', 'ctrl9months', 'ctrl12months',
  'engineoilchange', 'auxengineoilchange', 'transoilchange', 'ptooilchange',
  'hubdiffoilchange', 'hydraulicoilchange', 'blowervanpumpoilchange', 'hppoilchange',
];

/* =========================================================
   SEED DEFAULTS (only if tables are empty — first run)
   ========================================================= */
const DEFAULT_LOCATIONS = [
  ['alma', 'Alma'], ['contrecoeur', 'Contrecoeur'], ['fermont', 'Fermont'],
  ['hamilton', 'Hamilton'], ['jonquiere', 'Jonquiere'], ['latuque', 'La Tuque'],
  ['levis', 'Levis'], ['london', 'London'], ['matane', 'Matane'],
  ['pointeauxtrembles', 'Pointe-aux-Trembles'], ['portcartier', 'Port-Cartier'],
  ['rouynnoranda', 'Rouyn-Noranda'], ['saintremi', 'Saint-Remi'],
  ['saintromuald', 'Saint-Romuald'], ['sarnia', 'Sarnia'],
  ['temiscamingue', 'Temiscamingue'], ['troisriviere', 'Trois-Riviere'], ['windsor', 'Windsor'],
];
const DEFAULT_SUBCATEGORIES = {
  truck: ['vacuum', 'hydroblaster', 'sucker', 'scrubber', 'tractor', 'combine', 'hydroexcavator', 'lowpressure'],
  trailer: ['hydroblaster', 'vacuum', 'boattrailer', 'emergencyunit', 'centrifugal', 'boiler', 'airtankunit',
            'conveyor', 'closed', 'marineoperationunit', 'compressor', 'rolloff', 'coviddisinfectionunit', 'pump', 'robot'],
};
const DEFAULT_PART_CATEGORIES = [
  ['engine', 'Engine'], ['brakes', 'Brakes'], ['electrical', 'Electrical'], ['suspension', 'Suspension'],
  ['tiresWheels', 'Tires & Wheels'], ['body', 'Body & Exterior'], ['hydraulics', 'Hydraulics'], ['other', 'Other'],
];

const seedTxn = db.transaction(() => {
  const locCount = db.prepare('SELECT COUNT(*) AS c FROM locations').get().c;
  if (locCount === 0) {
    const ins = db.prepare('INSERT INTO locations (id, label) VALUES (?, ?)');
    DEFAULT_LOCATIONS.forEach(([id, label]) => ins.run(id, label));
  }
  const subCount = db.prepare('SELECT COUNT(*) AS c FROM subcategories').get().c;
  if (subCount === 0) {
    const ins = db.prepare('INSERT INTO subcategories (id, category, label) VALUES (?, ?, ?)');
    Object.keys(DEFAULT_SUBCATEGORIES).forEach((cat) => {
      DEFAULT_SUBCATEGORIES[cat].forEach((id) => ins.run(id, cat, id));
    });
  }
  const partCatCount = db.prepare('SELECT COUNT(*) AS c FROM part_categories').get().c;
  if (partCatCount === 0) {
    const ins = db.prepare('INSERT INTO part_categories (id, label) VALUES (?, ?)');
    DEFAULT_PART_CATEGORIES.forEach(([id, label]) => ins.run(id, label));
  }
  // Always (re-)apply the correct capability matrix for the five built-in
  // roles — this runs on every start, not just first install, so a server
  // upgrading from an earlier version of this app gets corrected rather
  // than being left with every new permission defaulted to "off". Any
  // custom role an admin created beyond these five is left untouched.
  const roleUpsert = db.prepare(`
    INSERT INTO roles (
      id, label, is_admin, can_view_all_locations, can_move_vehicle_location, can_manage_vehicles,
      can_manage_photos, can_view_parts, can_manage_parts, can_edit_vehicle_info,
      can_manage_maintenance, can_create_work_orders, can_manage_reports, can_approve_permits, can_manage_subcategories, created_at
    ) VALUES (
      @id, @label, @is_admin, @can_view_all_locations, @can_move_vehicle_location, @can_manage_vehicles,
      @can_manage_photos, @can_view_parts, @can_manage_parts, @can_edit_vehicle_info,
      @can_manage_maintenance, @can_create_work_orders, @can_manage_reports, @can_approve_permits, @can_manage_subcategories, @created_at
    )
    ON CONFLICT(id) DO UPDATE SET
      label = excluded.label, is_admin = excluded.is_admin,
      can_view_all_locations = excluded.can_view_all_locations,
      can_move_vehicle_location = excluded.can_move_vehicle_location,
      can_manage_vehicles = excluded.can_manage_vehicles,
      can_manage_photos = excluded.can_manage_photos,
      can_view_parts = excluded.can_view_parts,
      can_manage_parts = excluded.can_manage_parts,
      can_edit_vehicle_info = excluded.can_edit_vehicle_info,
      can_manage_maintenance = excluded.can_manage_maintenance,
      can_create_work_orders = excluded.can_create_work_orders,
      can_manage_reports = excluded.can_manage_reports,
      can_approve_permits = excluded.can_approve_permits,
      can_manage_subcategories = excluded.can_manage_subcategories
  `);
  const now = Date.now();
  const full = 1;
  [
    // Administrator: everything, including roles/logo/import-export (is_admin=1).
    {id:'admin', label:'Administrator', is_admin:full, can_view_all_locations:full, can_move_vehicle_location:full,
     can_manage_vehicles:full, can_manage_photos:full, can_view_parts:full, can_manage_parts:full,
     can_edit_vehicle_info:full, can_manage_maintenance:full, can_create_work_orders:full, can_manage_reports:full, can_approve_permits:full, can_manage_subcategories:full},
    // Fleet Manager: identical to Administrator except role management/logo/import-export.
    {id:'fleetmanager', label:'Fleet Manager', is_admin:0, can_view_all_locations:full, can_move_vehicle_location:full,
     can_manage_vehicles:full, can_manage_photos:full, can_view_parts:full, can_manage_parts:full,
     can_edit_vehicle_info:full, can_manage_maintenance:full, can_create_work_orders:full, can_manage_reports:full, can_approve_permits:full, can_manage_subcategories:full},
    // Supervisor: broad read access and management, but can't add/remove units,
    // can't touch photos, and doesn't create work orders (that's the Technician's job).
    {id:'supervisor', label:'Supervisor', is_admin:0, can_view_all_locations:full, can_move_vehicle_location:full,
     can_manage_vehicles:0, can_manage_photos:0, can_view_parts:full, can_manage_parts:full,
     can_edit_vehicle_info:full, can_manage_maintenance:full, can_create_work_orders:0, can_manage_reports:full, can_approve_permits:full, can_manage_subcategories:0},
    // Technician: scoped to their own location, focused on completing work
    // orders and maintenance; can't move a unit to another location.
    {id:'technician', label:'Technician', is_admin:0, can_view_all_locations:0, can_move_vehicle_location:0,
     can_manage_vehicles:0, can_manage_photos:0, can_view_parts:full, can_manage_parts:full,
     can_edit_vehicle_info:full, can_manage_maintenance:full, can_create_work_orders:full, can_manage_reports:full, can_approve_permits:0, can_manage_subcategories:0},
    // Operator: very limited — scoped to their own location, can file a
    // report with a photo, and otherwise only views (no Parts tab, no
    // editing anything, no photo uploads).
    {id:'operator', label:'Operator', is_admin:0, can_view_all_locations:0, can_move_vehicle_location:0,
     can_manage_vehicles:0, can_manage_photos:0, can_view_parts:0, can_manage_parts:0,
     can_edit_vehicle_info:0, can_manage_maintenance:0, can_create_work_orders:0, can_manage_reports:0, can_approve_permits:0, can_manage_subcategories:0},
  ].forEach(r => roleUpsert.run(Object.assign({created_at: now}, r)));
});
seedTxn();

// Bootstrap safety net for servers that already had users before roles
// existed: promote the earliest-created account to Administrator so someone
// can start assigning roles, and default everyone else to Operator.
const adminCount = db.prepare("SELECT COUNT(*) AS c FROM users WHERE role_id = 'admin'").get().c;
if (adminCount === 0) {
  const earliest = db.prepare('SELECT id FROM users ORDER BY created_at ASC LIMIT 1').get();
  if (earliest) db.prepare("UPDATE users SET role_id = 'admin' WHERE id = ?").run(earliest.id);
}
db.prepare("UPDATE users SET role_id = 'operator' WHERE role_id IS NULL").run();

/* =========================================================
   APP / MIDDLEWARE
   ========================================================= */
const app = express();
app.use(cors({ origin: ALLOW_ORIGIN }));
app.use(express.json({ limit: '15mb' })); // photos arrive as base64 data URIs

function signToken(user) {
  return jwt.sign({ sub: user.id, name: user.name, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Looks up the requester's CURRENT role fresh from the database on every
// call (rather than trusting the JWT), so a permission change or demotion
// takes effect immediately rather than waiting for their token to expire.
function requireAdmin(req, res, next) {
  const row = db.prepare(`
    SELECT r.is_admin AS is_admin FROM users u
    LEFT JOIN roles r ON r.id = u.role_id
    WHERE u.id = ?
  `).get(req.user.sub);
  if (!row || !row.is_admin) return res.status(403).json({ error: 'Administrator access required.' });
  next();
}

// Looks up every capability flag for a user's current role in one query,
// fresh from the database (never trusts the JWT for this).
function getCapabilities(userId) {
  const row = db.prepare(`
    SELECT r.* FROM users u LEFT JOIN roles r ON r.id = u.role_id WHERE u.id = ?
  `).get(userId);
  const empty = {
    is_admin:0, can_view_all_locations:0, can_move_vehicle_location:0, can_manage_vehicles:0,
    can_manage_photos:0, can_view_parts:0, can_manage_parts:0, can_edit_vehicle_info:0,
    can_manage_maintenance:0, can_create_work_orders:0, can_manage_reports:0, can_approve_permits:0, can_manage_subcategories:0,
  };
  if (!row) return empty;
  return Object.assign({}, empty, row);
}
function hasCapability(userId, capability) {
  return !!getCapabilities(userId)[capability];
}
// Express middleware factory: app.post('/x', requireAuth, requireCapability('can_manage_photos'), handler)
function requireCapability(capability) {
  return (req, res, next) => {
    if (!hasCapability(req.user.sub, capability)) {
      return res.status(403).json({ error: 'You do not have permission to do that.' });
    }
    next();
  };
}

function roleLabelOf(roleId) {
  if (!roleId) return null;
  const row = db.prepare('SELECT label FROM roles WHERE id = ?').get(roleId);
  return row ? row.label : null;
}

// An Operator who has been assigned a location is scoped to that location
// only — this is the core of the "no cross-location access" rule. Every
// other role (Administrator, Technician, Supervisor) is unrestricted.
// An Operator with no location assigned yet is also unrestricted, since the
// scoping only kicks in once both the role AND the location are set.
function getAccessScope(userId) {
  const row = db.prepare(`
    SELECT u.location_id AS location_id, r.can_view_all_locations AS can_view_all
    FROM users u LEFT JOIN roles r ON r.id = u.role_id
    WHERE u.id = ?
  `).get(userId);
  if (!row) return { restricted: false, locationId: null };
  const restricted = !row.can_view_all && !!row.location_id;
  return { restricted, locationId: restricted ? row.location_id : null };
}
function vehicleLocationOf(vehicleId) {
  const row = db.prepare('SELECT data FROM vehicles WHERE id = ?').get(vehicleId);
  if (!row) return null;
  try { return JSON.parse(row.data).location || null; } catch (e) { return null; }
}
// Blocks the request with 403 if the caller is a scoped Operator and the
// given vehicle isn't at their assigned location. Returns the scope either way.
function enforceVehicleAccess(req, res, vehicleId) {
  const scope = getAccessScope(req.user.sub);
  if (scope.restricted && vehicleLocationOf(vehicleId) !== scope.locationId) {
    res.status(403).json({ error: 'You do not have access to units outside your assigned location.' });
    return null;
  }
  return scope;
}

function publicUser(row) {
  const caps = getCapabilities(row.id);
  return {
    id: row.id,
    name: row.name,
    username: row.username,
    roleId: row.role_id || null,
    roleLabel: roleLabelOf(row.role_id),
    isAdmin: !!caps.is_admin,
    capabilities: {
      canViewAllLocations: !!caps.can_view_all_locations,
      canMoveVehicleLocation: !!caps.can_move_vehicle_location,
      canManageVehicles: !!caps.can_manage_vehicles,
      canManagePhotos: !!caps.can_manage_photos,
      canViewParts: !!caps.can_view_parts,
      canManageParts: !!caps.can_manage_parts,
      canEditVehicleInfo: !!caps.can_edit_vehicle_info,
      canManageMaintenance: !!caps.can_manage_maintenance,
      canCreateWorkOrders: !!caps.can_create_work_orders,
      canManageReports: !!caps.can_manage_reports,
      canApprovePermits: !!caps.can_approve_permits,
      canManageSubcategories: !!caps.can_manage_subcategories,
    },
    avatar: row.avatar || null,
    jobPosition: row.job_position || '',
    phone: row.phone || '',
    email: row.email || '',
    locationId: row.location_id || null,
  };
}

/* =========================================================
   AUTH ROUTES
   ========================================================= */
app.post('/api/auth/register', (req, res) => {
  if (!ALLOW_REGISTRATION) return res.status(403).json({ error: 'Self-registration is disabled on this server.' });
  const { name, username, password } = req.body || {};
  if (!name || !username || !password) return res.status(400).json({ error: 'name, username and password are required.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });

  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username.trim().toLowerCase());
  if (existing) return res.status(409).json({ error: 'That username is already taken.' });

  // The very first account on a fresh server becomes Administrator automatically
  // (otherwise no one could ever assign roles); everyone after that starts as Operator.
  const isFirstUser = db.prepare('SELECT COUNT(*) AS c FROM users').get().c === 0;

  const user = {
    id: uid(),
    name: name.trim(),
    username: username.trim().toLowerCase(),
    password_hash: bcrypt.hashSync(password, 10),
    created_at: Date.now(),
    role_id: isFirstUser ? 'admin' : 'operator',
  };
  db.prepare('INSERT INTO users (id, name, username, password_hash, created_at, role_id) VALUES (?, ?, ?, ?, ?, ?)')
    .run(user.id, user.name, user.username, user.password_hash, user.created_at, user.role_id);

  const token = signToken(user);
  res.json({ token, user: publicUser(user) });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password are required.' });
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.trim().toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Incorrect username or password.' });
  }
  const token = signToken(user);
  res.json({ token, user: publicUser(user) });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user: publicUser(user) });
});

// Full directory (name, role, and profile info) — visible to every logged-in
// teammate, consistent with the rest of this app's shared-fleet, shared-team model.
app.get('/api/users', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM users ORDER BY name').all();
  res.json({ users: rows.map(publicUser) });
});

// Self-service profile edit: picture, job position, contact info, and work
// location — the only fields a non-admin user is allowed to change about themselves.
app.patch('/api/users/me/profile', requireAuth, (req, res) => {
  const { avatar, jobPosition, phone, email, locationId } = req.body || {};
  const isAdmin = hasCapability(req.user.sub, 'is_admin');
  // Only Administrators can set their own working location — everyone else's
  // location is assigned to them by an admin.
  const current = db.prepare('SELECT location_id FROM users WHERE id = ?').get(req.user.sub);
  const finalLocationId = isAdmin ? (locationId || null) : (current ? current.location_id : null);
  db.prepare(`
    UPDATE users SET avatar = ?, job_position = ?, phone = ?, email = ?, location_id = ?
    WHERE id = ?
  `).run(avatar || null, (jobPosition||'').trim(), (phone||'').trim(), (email||'').trim(), finalLocationId, req.user.sub);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.sub);
  res.json({ user: publicUser(user) });
});

// Admin-only: edit any user's full profile, including their location.
app.patch('/api/users/:id/profile', requireAuth, requireAdmin, (req, res) => {
  const { name, avatar, jobPosition, phone, email, locationId } = req.body || {};
  const existing = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'User not found.' });
  db.prepare(`
    UPDATE users SET name = ?, avatar = ?, job_position = ?, phone = ?, email = ?, location_id = ?
    WHERE id = ?
  `).run(
    (name || existing.name).trim(), avatar !== undefined ? avatar : existing.avatar,
    (jobPosition !== undefined ? jobPosition : existing.job_position || '').trim(),
    (phone !== undefined ? phone : existing.phone || '').trim(),
    (email !== undefined ? email : existing.email || '').trim(),
    locationId !== undefined ? (locationId || null) : existing.location_id,
    req.params.id
  );
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  res.json({ user: publicUser(user) });
});

/* =========================================================
   ROLES (admin-managed)
   ========================================================= */
function roleToClient(r) {
  return {
    id: r.id,
    label: r.label,
    isAdmin: !!r.is_admin,
    capabilities: {
      canViewAllLocations: !!r.can_view_all_locations,
      canMoveVehicleLocation: !!r.can_move_vehicle_location,
      canManageVehicles: !!r.can_manage_vehicles,
      canManagePhotos: !!r.can_manage_photos,
      canViewParts: !!r.can_view_parts,
      canManageParts: !!r.can_manage_parts,
      canEditVehicleInfo: !!r.can_edit_vehicle_info,
      canManageMaintenance: !!r.can_manage_maintenance,
      canCreateWorkOrders: !!r.can_create_work_orders,
      canManageReports: !!r.can_manage_reports,
      canApprovePermits: !!r.can_approve_permits,
      canManageSubcategories: !!r.can_manage_subcategories,
    },
  };
}

app.get('/api/roles', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM roles ORDER BY created_at ASC').all();
  res.json({ roles: rows.map(roleToClient) });
});

// Admins can define additional job-function roles beyond the built-in ones.
// Custom roles created this way start with every capability off (the safest
// default) — an admin can promote a real permission set later if this app
// grows a full role-capability editor.
app.post('/api/roles', requireAuth, requireAdmin, (req, res) => {
  const { label } = req.body || {};
  if (!label || !label.trim()) return res.status(400).json({ error: 'A role name is required.' });
  const id = label.trim().toLowerCase().replace(/[^a-z0-9]+/g, '') || uid();
  const existing = db.prepare('SELECT id FROM roles WHERE id = ?').get(id);
  if (existing) return res.status(409).json({ error: 'A role with that name already exists.' });
  db.prepare('INSERT INTO roles (id, label, is_admin, created_at) VALUES (?, ?, 0, ?)').run(id, label.trim(), Date.now());
  const created = db.prepare('SELECT * FROM roles WHERE id = ?').get(id);
  res.json({ role: roleToClient(created) });
});

// Assigning a role to a user is admin-only.
app.patch('/api/users/:id/role', requireAuth, requireAdmin, (req, res) => {
  const { roleId } = req.body || {};
  const role = db.prepare('SELECT * FROM roles WHERE id = ?').get(roleId);
  if (!role) return res.status(400).json({ error: 'Unknown role.' });
  const result = db.prepare('UPDATE users SET role_id = ? WHERE id = ?').run(roleId, req.params.id);
  if (result.changes === 0) return res.status(404).json({ error: 'User not found.' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  res.json({ user: publicUser(user) });
});

/* =========================================================
   FULL STATE (hydrate the app on login)
   ========================================================= */
app.get('/api/state', requireAuth, (req, res) => {
  const locations = db.prepare('SELECT id, label FROM locations ORDER BY label').all();

  const subcategories = { truck: [], trailer: [] };
  db.prepare('SELECT id, category, label FROM subcategories').all().forEach((r) => {
    if (!subcategories[r.category]) subcategories[r.category] = [];
    subcategories[r.category].push({ id: r.id, label: r.label });
  });

  const partCategories = db.prepare('SELECT id, label FROM part_categories').all();

  const vehicleRows = db.prepare('SELECT id, data, updated_at FROM vehicles').all();
  const reportRows = db.prepare('SELECT * FROM reports ORDER BY created_at DESC').all();
  const reportsByVehicle = {};
  reportRows.forEach((r) => {
    if (!reportsByVehicle[r.vehicle_id]) reportsByVehicle[r.vehicle_id] = [];
    reportsByVehicle[r.vehicle_id].push({
      id: r.id,
      reporterName: r.reporter_name,
      reporterUserId: r.reporter_user_id,
      description: r.description,
      severity: r.severity,
      photo: r.photo,
      createdAt: r.created_at,
      resolved: !!r.resolved_work_order_id,
      workOrderId: r.resolved_work_order_id || null,
    });
  });

  const workOrderRows = db.prepare('SELECT * FROM work_orders ORDER BY completed_at DESC').all();
  const workOrdersByVehicle = {};
  workOrderRows.forEach((w) => {
    if (!workOrdersByVehicle[w.vehicle_id]) workOrdersByVehicle[w.vehicle_id] = [];
    workOrdersByVehicle[w.vehicle_id].push({
      id: w.id,
      number: w.seq,
      vehicleId: w.vehicle_id,
      unitNumber: w.unit_number,
      reportId: w.report_id,
      reporterName: w.reporter_name,
      reportedAt: w.reported_at,
      description: w.description,
      completedByUserId: w.completed_by_user_id,
      completedByName: w.completed_by_name,
      completedAt: w.completed_at,
    });
  });

  const maintLogRows = db.prepare('SELECT * FROM maintenance_logs ORDER BY completed_at DESC').all();
  const maintLogsByVehicle = {};
  maintLogRows.forEach((m) => {
    if (!maintLogsByVehicle[m.vehicle_id]) maintLogsByVehicle[m.vehicle_id] = [];
    maintLogsByVehicle[m.vehicle_id].push({
      id: m.id,
      vehicleId: m.vehicle_id,
      unitNumber: m.unit_number,
      type: m.type,
      completedByUserId: m.completed_by_user_id,
      completedByName: m.completed_by_name,
      completedAt: m.completed_at,
      notes: m.notes || '',
    });
  });

  const permits = db.prepare('SELECT * FROM work_permits ORDER BY requested_at DESC').all().map(permitToClient);

  let vehicles = vehicleRows.map((row) => {
    const parsed = JSON.parse(row.data);
    parsed.id = row.id;
    parsed.updatedAt = row.updated_at;
    parsed.reports = reportsByVehicle[row.id] || [];
    parsed.workOrders = workOrdersByVehicle[row.id] || [];
    parsed.maintenanceLogs = maintLogsByVehicle[row.id] || [];
    return parsed;
  });

  const scope = getAccessScope(req.user.sub);
  if (scope.restricted) vehicles = vehicles.filter((v) => v.location === scope.locationId);
  const visibleVehicleIds = new Set(vehicles.map((v) => v.id));

  const requesterCaps = getCapabilities(req.user.sub);
  if (!requesterCaps.can_view_parts) vehicles.forEach((v) => { v.parts = []; });

  let events = db.prepare('SELECT * FROM events ORDER BY date ASC').all().map((e) => ({
    id: e.id,
    vehicleId: e.vehicle_id,
    title: e.title,
    date: e.date,
    time: e.time || '',
    reminderDays: e.reminder_days,
    notes: e.notes || '',
    createdByUserId: e.created_by_user_id,
    createdAt: e.created_at,
  }));
  if (scope.restricted) events = events.filter((e) => !e.vehicleId || visibleVehicleIds.has(e.vehicleId));

  const logoRow = db.prepare("SELECT value FROM settings WHERE key = 'companyLogo'").get();
  const roles = db.prepare('SELECT * FROM roles ORDER BY created_at ASC').all().map(roleToClient);

  res.json({
    locations,
    subcategories,
    partCategories,
    vehicles,
    events,
    roles,
    permits,
    companyLogo: logoRow ? logoRow.value : null,
  });
});

/* =========================================================
   VEHICLES
   ========================================================= */
// Bulk upsert: the client sends the full vehicles array (minus `reports`,
// which is managed separately below) whenever anything about a vehicle changes.
// A vehicle update travels as one big JSON blob (photos, parts, tires,
// status, location — everything together), so field-level permissions have
// to be enforced by diffing against what's already stored and silently
// reverting any field the requester isn't allowed to touch, rather than
// rejecting the whole update (which would also block other, permitted
// changes bundled in the same save).
function sanitizeVehicleWrite(incoming, caps) {
  const existingRow = db.prepare('SELECT data FROM vehicles WHERE id = ?').get(incoming.id);
  const existing = existingRow ? JSON.parse(existingRow.data) : null;

  if (!existing) {
    return caps.can_manage_vehicles ? incoming : null; // creating a brand-new vehicle
  }

  const out = Object.assign({}, incoming);
  const differs = (a, b) => JSON.stringify(a) !== JSON.stringify(b);

  if (out.location !== existing.location && !caps.can_move_vehicle_location) {
    out.location = existing.location;
  }
  if (differs(out.photos, existing.photos) && !caps.can_manage_photos) {
    out.photos = existing.photos;
  }
  if (differs(out.parts, existing.parts) && !caps.can_manage_parts) {
    out.parts = existing.parts;
  }
  ['tires', 'maintenanceSchedule', 'repairs'].forEach((f) => {
    if (differs(out[f], existing[f]) && !caps.can_manage_maintenance) out[f] = existing[f];
  });
  const infoFields = ['unitNumber', 'vin', 'year', 'model', 'engineDisplacement', 'status', 'category', 'subcategory'];
  if (infoFields.some((f) => out[f] !== existing[f]) && !caps.can_edit_vehicle_info) {
    infoFields.forEach((f) => { out[f] = existing[f]; });
  }
  return out;
}

app.put('/api/vehicles', requireAuth, (req, res) => {
  let vehicles = Array.isArray(req.body.vehicles) ? req.body.vehicles : [];
  const scope = getAccessScope(req.user.sub);
  if (scope.restricted) {
    // A scoped Operator/Technician may only touch vehicles that are (and
    // remain) at their own location — blocks creating, editing, or moving a
    // unit into/out of another location, in addition to the read-side
    // filtering in GET /api/state.
    vehicles = vehicles.filter((v) => {
      if (v.location !== scope.locationId) return false;
      const existingLocation = vehicleLocationOf(v.id);
      return existingLocation === null || existingLocation === scope.locationId;
    });
  }
  const caps = getCapabilities(req.user.sub);
  vehicles = vehicles.map((v) => sanitizeVehicleWrite(v, caps)).filter(Boolean);

  const now = Date.now();
  const upsert = db.prepare(`
    INSERT INTO vehicles (id, data, updated_at) VALUES (?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at
  `);
  const txn = db.transaction((list) => {
    list.forEach((v) => {
      const { reports, ...rest } = v; // reports live in their own table
      upsert.run(v.id, JSON.stringify(rest), now);
    });
  });
  txn(vehicles);
  res.json({ ok: true, updatedAt: now });
});

app.delete('/api/vehicles/:id', requireAuth, requireCapability('can_manage_vehicles'), (req, res) => {
  if (!enforceVehicleAccess(req, res, req.params.id)) return;
  db.prepare('DELETE FROM vehicles WHERE id = ?').run(req.params.id);
  db.prepare('DELETE FROM reports WHERE vehicle_id = ?').run(req.params.id);
  db.prepare('DELETE FROM events WHERE vehicle_id = ?').run(req.params.id);
  db.prepare('DELETE FROM work_orders WHERE vehicle_id = ?').run(req.params.id);
  db.prepare('DELETE FROM maintenance_logs WHERE vehicle_id = ?').run(req.params.id);
  res.json({ ok: true });
});

/* =========================================================
   REPORTS (granular — safe for multiple users at once)
   ========================================================= */
app.post('/api/vehicles/:vehicleId/reports', requireAuth, (req, res) => {
  const { vehicleId } = req.params;
  const { description, severity, photo } = req.body || {};
  if (!description || !description.trim()) return res.status(400).json({ error: 'Description is required.' });

  const vehicle = db.prepare('SELECT id FROM vehicles WHERE id = ?').get(vehicleId);
  if (!vehicle) return res.status(404).json({ error: 'Vehicle not found.' });
  if (!enforceVehicleAccess(req, res, vehicleId)) return;

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.sub);
  const report = {
    id: uid(),
    vehicle_id: vehicleId,
    reporter_user_id: user ? user.id : null,
    reporter_name: user ? user.name : 'Unknown',
    description: description.trim(),
    severity: severity === 'major' ? 'major' : 'minor',
    photo: photo || null,
    created_at: Date.now(),
  };
  db.prepare(`
    INSERT INTO reports (id, vehicle_id, reporter_user_id, reporter_name, description, severity, photo, created_at)
    VALUES (@id, @vehicle_id, @reporter_user_id, @reporter_name, @description, @severity, @photo, @created_at)
  `).run(report);

  res.json({
    report: {
      id: report.id,
      reporterName: report.reporter_name,
      reporterUserId: report.reporter_user_id,
      description: report.description,
      severity: report.severity,
      photo: report.photo,
      createdAt: report.created_at,
    },
  });
});

app.patch('/api/reports/:id', requireAuth, requireCapability('can_manage_reports'), (req, res) => {
  const { severity } = req.body || {};
  if (severity !== 'major' && severity !== 'minor') return res.status(400).json({ error: 'severity must be major or minor.' });
  const report = db.prepare('SELECT vehicle_id FROM reports WHERE id = ?').get(req.params.id);
  if (!report) return res.status(404).json({ error: 'Report not found.' });
  if (!enforceVehicleAccess(req, res, report.vehicle_id)) return;
  db.prepare('UPDATE reports SET severity = ? WHERE id = ?').run(severity, req.params.id);
  res.json({ ok: true });
});

app.delete('/api/reports/:id', requireAuth, requireCapability('can_manage_reports'), (req, res) => {
  const report = db.prepare('SELECT vehicle_id FROM reports WHERE id = ?').get(req.params.id);
  if (report && !enforceVehicleAccess(req, res, report.vehicle_id)) return;
  db.prepare('DELETE FROM reports WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

/* =========================================================
   WORK ORDERS
   ========================================================= */
// Creating a work order always happens from an existing report: it captures
// who reported the issue and when, lets the repairing user write up what was
// done, and marks that report as resolved — linked to this work order.
app.post('/api/vehicles/:vehicleId/reports/:reportId/work-orders', requireAuth, requireCapability('can_create_work_orders'), (req, res) => {
  const { vehicleId, reportId } = req.params;
  const { description } = req.body || {};
  if (!description || !description.trim()) return res.status(400).json({ error: 'Repair description is required.' });
  if (!enforceVehicleAccess(req, res, vehicleId)) return;

  const report = db.prepare('SELECT * FROM reports WHERE id = ? AND vehicle_id = ?').get(reportId, vehicleId);
  if (!report) return res.status(404).json({ error: 'Report not found.' });
  if (report.resolved_work_order_id) return res.status(409).json({ error: 'This report already has a work order.' });

  const vehicleRow = db.prepare('SELECT data FROM vehicles WHERE id = ?').get(vehicleId);
  if (!vehicleRow) return res.status(404).json({ error: 'Vehicle not found.' });
  const vehicleData = JSON.parse(vehicleRow.data);

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.sub);

  const workOrder = {
    id: uid(),
    seq: nextWorkOrderNumber(),
    vehicle_id: vehicleId,
    unit_number: vehicleData.unitNumber || '',
    report_id: reportId,
    reporter_name: report.reporter_name,
    reported_at: report.created_at,
    description: description.trim(),
    completed_by_user_id: user ? user.id : null,
    completed_by_name: user ? user.name : 'Unknown',
    completed_at: Date.now(),
  };

  const txn = db.transaction(() => {
    db.prepare(`
      INSERT INTO work_orders (id, seq, vehicle_id, unit_number, report_id, reporter_name, reported_at, description, completed_by_user_id, completed_by_name, completed_at)
      VALUES (@id, @seq, @vehicle_id, @unit_number, @report_id, @reporter_name, @reported_at, @description, @completed_by_user_id, @completed_by_name, @completed_at)
    `).run(workOrder);
    db.prepare('UPDATE reports SET resolved_work_order_id = ? WHERE id = ?').run(workOrder.id, reportId);
  });
  txn();

  res.json({
    workOrder: {
      id: workOrder.id, number: workOrder.seq, vehicleId: workOrder.vehicle_id, unitNumber: workOrder.unit_number,
      reportId: workOrder.report_id, reporterName: workOrder.reporter_name, reportedAt: workOrder.reported_at,
      description: workOrder.description, completedByUserId: workOrder.completed_by_user_id,
      completedByName: workOrder.completed_by_name, completedAt: workOrder.completed_at,
    },
  });
});

// Global history across every unit, for the hamburger-menu Work Orders view.
app.get('/api/work-orders', requireAuth, (req, res) => {
  const scope = getAccessScope(req.user.sub);
  let rows = db.prepare('SELECT * FROM work_orders ORDER BY completed_at DESC').all();
  if (scope.restricted) rows = rows.filter((w) => vehicleLocationOf(w.vehicle_id) === scope.locationId);
  res.json({
    workOrders: rows.map((w) => ({
      id: w.id, number: w.seq, vehicleId: w.vehicle_id, unitNumber: w.unit_number,
      reportId: w.report_id, reporterName: w.reporter_name, reportedAt: w.reported_at,
      description: w.description, completedByUserId: w.completed_by_user_id,
      completedByName: w.completed_by_name, completedAt: w.completed_at,
    })),
  });
});

app.delete('/api/work-orders/:id', requireAuth, requireCapability('can_create_work_orders'), (req, res) => {
  const wo = db.prepare('SELECT * FROM work_orders WHERE id = ?').get(req.params.id);
  if (!wo) return res.status(404).json({ error: 'Work order not found.' });
  if (!enforceVehicleAccess(req, res, wo.vehicle_id)) return;
  const txn = db.transaction(() => {
    db.prepare('UPDATE reports SET resolved_work_order_id = NULL WHERE resolved_work_order_id = ?').run(wo.id);
    db.prepare('DELETE FROM work_orders WHERE id = ?').run(wo.id);
  });
  txn();
  res.json({ ok: true });
});

/* =========================================================
   MAINTENANCE LOGS (completed maintenance, real records)
   ========================================================= */
app.post('/api/vehicles/:vehicleId/maintenance-logs', requireAuth, requireCapability('can_manage_maintenance'), (req, res) => {
  const { vehicleId } = req.params;
  const { type, notes } = req.body || {};
  if (!type || !VALID_MAINTENANCE_TYPES.includes(type)) {
    return res.status(400).json({ error: 'A valid maintenance type is required.' });
  }
  const vehicleRow = db.prepare('SELECT data FROM vehicles WHERE id = ?').get(vehicleId);
  if (!vehicleRow) return res.status(404).json({ error: 'Vehicle not found.' });
  if (!enforceVehicleAccess(req, res, vehicleId)) return;
  const vehicleData = JSON.parse(vehicleRow.data);

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.sub);
  const log = {
    id: uid(),
    vehicle_id: vehicleId,
    unit_number: vehicleData.unitNumber || '',
    type,
    completed_by_user_id: user ? user.id : null,
    completed_by_name: user ? user.name : 'Unknown',
    completed_at: Date.now(),
    notes: (notes || '').trim(),
  };
  db.prepare(`
    INSERT INTO maintenance_logs (id, vehicle_id, unit_number, type, completed_by_user_id, completed_by_name, completed_at, notes)
    VALUES (@id, @vehicle_id, @unit_number, @type, @completed_by_user_id, @completed_by_name, @completed_at, @notes)
  `).run(log);

  res.json({
    log: {
      id: log.id, vehicleId: log.vehicle_id, unitNumber: log.unit_number, type: log.type,
      completedByUserId: log.completed_by_user_id, completedByName: log.completed_by_name,
      completedAt: log.completed_at, notes: log.notes,
    },
  });
});

// Global history across every unit, for the hamburger-menu Maintenance view.
app.get('/api/maintenance-logs', requireAuth, (req, res) => {
  const scope = getAccessScope(req.user.sub);
  let rows = db.prepare('SELECT * FROM maintenance_logs ORDER BY completed_at DESC').all();
  if (scope.restricted) rows = rows.filter((m) => vehicleLocationOf(m.vehicle_id) === scope.locationId);
  res.json({
    logs: rows.map((m) => ({
      id: m.id, vehicleId: m.vehicle_id, unitNumber: m.unit_number, type: m.type,
      completedByUserId: m.completed_by_user_id, completedByName: m.completed_by_name,
      completedAt: m.completed_at, notes: m.notes || '',
    })),
  });
});

app.delete('/api/maintenance-logs/:id', requireAuth, requireCapability('can_manage_maintenance'), (req, res) => {
  const log = db.prepare('SELECT vehicle_id FROM maintenance_logs WHERE id = ?').get(req.params.id);
  if (log && !enforceVehicleAccess(req, res, log.vehicle_id)) return;
  db.prepare('DELETE FROM maintenance_logs WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});
/* =========================================================
   WORK PERMITS (Hot Work, Enclosed Space, Height Work)
   ========================================================= */
const VALID_PERMIT_TYPES = ['hotwork', 'enclosedspace', 'heightwork'];

function permitToClient(p) {
  return {
    id: p.id,
    type: p.type,
    status: p.status,
    data: JSON.parse(p.data || '{}'),
    requestedByUserId: p.requested_by_user_id,
    requestedByName: p.requested_by_name,
    requestedAt: p.requested_at,
    approvedByUserId: p.approved_by_user_id,
    approvedByName: p.approved_by_name,
    approvedAt: p.approved_at,
    closedByUserId: p.closed_by_user_id,
    closedByName: p.closed_by_name,
    closedAt: p.closed_at,
  };
}

// Any authenticated user can request a permit — permits are standalone
// safety documents, not tied to any particular unit.
app.post('/api/permits', requireAuth, (req, res) => {
  const { type, data } = req.body || {};
  if (!VALID_PERMIT_TYPES.includes(type)) return res.status(400).json({ error: 'A valid permit type is required.' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.sub);

  const permit = {
    id: uid(),
    type,
    status: 'requested',
    data: JSON.stringify(data || {}),
    requested_by_user_id: user ? user.id : null,
    requested_by_name: user ? user.name : 'Unknown',
    requested_at: Date.now(),
  };
  db.prepare(`
    INSERT INTO work_permits (id, type, status, data, requested_by_user_id, requested_by_name, requested_at)
    VALUES (@id, @type, @status, @data, @requested_by_user_id, @requested_by_name, @requested_at)
  `).run(permit);

  res.json({ permit: permitToClient(db.prepare('SELECT * FROM work_permits WHERE id = ?').get(permit.id)) });
});

// Approve: fills in the preventive-measures checklist, attestation, and
// initial atmospheric reading. Supervisors, Fleet Managers, Admins only.
app.patch('/api/permits/:id/approve', requireAuth, requireCapability('can_approve_permits'), (req, res) => {
  const permit = db.prepare('SELECT * FROM work_permits WHERE id = ?').get(req.params.id);
  if (!permit) return res.status(404).json({ error: 'Permit not found.' });
  if (permit.status !== 'requested') return res.status(409).json({ error: 'This permit has already been approved.' });

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.sub);
  const merged = Object.assign({}, JSON.parse(permit.data || '{}'), req.body.data || {});
  db.prepare(`
    UPDATE work_permits SET status = 'approved', data = ?, approved_by_user_id = ?, approved_by_name = ?, approved_at = ?
    WHERE id = ?
  `).run(JSON.stringify(merged), user ? user.id : null, user ? user.name : 'Unknown', Date.now(), permit.id);

  res.json({ permit: permitToClient(db.prepare('SELECT * FROM work_permits WHERE id = ?').get(permit.id)) });
});

// Close: final control section (work completed, post-work monitoring done).
app.patch('/api/permits/:id/close', requireAuth, requireCapability('can_approve_permits'), (req, res) => {
  const permit = db.prepare('SELECT * FROM work_permits WHERE id = ?').get(req.params.id);
  if (!permit) return res.status(404).json({ error: 'Permit not found.' });
  if (permit.status !== 'approved') return res.status(409).json({ error: 'This permit must be approved before it can be closed.' });

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.sub);
  const merged = Object.assign({}, JSON.parse(permit.data || '{}'), req.body.data || {});
  db.prepare(`
    UPDATE work_permits SET status = 'closed', data = ?, closed_by_user_id = ?, closed_by_name = ?, closed_at = ?
    WHERE id = ?
  `).run(JSON.stringify(merged), user ? user.id : null, user ? user.name : 'Unknown', Date.now(), permit.id);

  res.json({ permit: permitToClient(db.prepare('SELECT * FROM work_permits WHERE id = ?').get(permit.id)) });
});

// Append one hourly atmospheric reading row (approved permits only).
app.post('/api/permits/:id/readings', requireAuth, requireCapability('can_approve_permits'), (req, res) => {
  const permit = db.prepare('SELECT * FROM work_permits WHERE id = ?').get(req.params.id);
  if (!permit) return res.status(404).json({ error: 'Permit not found.' });
  const data = JSON.parse(permit.data || '{}');
  data.hourlyReadings = data.hourlyReadings || [];
  data.hourlyReadings.push(Object.assign({}, req.body.reading || {}, { at: Date.now() }));
  db.prepare('UPDATE work_permits SET data = ? WHERE id = ?').run(JSON.stringify(data), permit.id);
  res.json({ permit: permitToClient(db.prepare('SELECT * FROM work_permits WHERE id = ?').get(permit.id)) });
});

app.delete('/api/permits/:id', requireAuth, requireCapability('can_approve_permits'), (req, res) => {
  db.prepare('DELETE FROM work_permits WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// Global history — permits are standalone, so every authenticated user sees
// the same full list (no per-unit location scoping applies anymore).
app.get('/api/permits', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM work_permits ORDER BY requested_at DESC').all();
  res.json({ permits: rows.map(permitToClient) });
});

/* =========================================================
   EVENTS / APPOINTMENTS
   ========================================================= */
app.post('/api/events', requireAuth, (req, res) => {
  const { title, date, time, vehicleId, reminderDays, notes } = req.body || {};
  if (!title || !title.trim()) return res.status(400).json({ error: 'Title is required.' });
  if (!date) return res.status(400).json({ error: 'Date is required.' });
  if (vehicleId && !enforceVehicleAccess(req, res, vehicleId)) return;

  const event = {
    id: uid(),
    vehicle_id: vehicleId || null,
    title: title.trim(),
    date,
    time: time || '',
    reminder_days: parseInt(reminderDays, 10) || 0,
    notes: (notes || '').trim(),
    created_by_user_id: req.user.sub,
    created_at: Date.now(),
  };
  db.prepare(`
    INSERT INTO events (id, vehicle_id, title, date, time, reminder_days, notes, created_by_user_id, created_at)
    VALUES (@id, @vehicle_id, @title, @date, @time, @reminder_days, @notes, @created_by_user_id, @created_at)
  `).run(event);

  res.json({
    event: {
      id: event.id, vehicleId: event.vehicle_id, title: event.title, date: event.date,
      time: event.time, reminderDays: event.reminder_days, notes: event.notes,
      createdByUserId: event.created_by_user_id, createdAt: event.created_at,
    },
  });
});

app.delete('/api/events/:id', requireAuth, (req, res) => {
  const ev = db.prepare('SELECT vehicle_id FROM events WHERE id = ?').get(req.params.id);
  if (ev && ev.vehicle_id && !enforceVehicleAccess(req, res, ev.vehicle_id)) return;
  db.prepare('DELETE FROM events WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

/* =========================================================
   LOCATIONS / SUBCATEGORIES / PART CATEGORIES (bulk replace)
   ========================================================= */
app.put('/api/locations', requireAuth, (req, res) => {
  const locations = Array.isArray(req.body.locations) ? req.body.locations : [];
  const txn = db.transaction((list) => {
    db.prepare('DELETE FROM locations').run();
    const ins = db.prepare('INSERT INTO locations (id, label) VALUES (?, ?)');
    list.forEach((l) => ins.run(l.id, l.label));
  });
  txn(locations);
  res.json({ ok: true });
});

app.put('/api/subcategories', requireAuth, requireCapability('can_manage_subcategories'), (req, res) => {
  const subcategories = req.body.subcategories || {};
  const txn = db.transaction((obj) => {
    db.prepare('DELETE FROM subcategories').run();
    const ins = db.prepare('INSERT INTO subcategories (id, category, label) VALUES (?, ?, ?)');
    Object.keys(obj).forEach((cat) => {
      (obj[cat] || []).forEach((s) => ins.run(s.id, cat, s.label));
    });
  });
  txn(subcategories);
  res.json({ ok: true });
});

app.put('/api/partCategories', requireAuth, requireCapability('can_manage_parts'), (req, res) => {
  const partCategories = Array.isArray(req.body.partCategories) ? req.body.partCategories : [];
  const txn = db.transaction((list) => {
    db.prepare('DELETE FROM part_categories').run();
    const ins = db.prepare('INSERT INTO part_categories (id, label) VALUES (?, ?)');
    list.forEach((c) => ins.run(c.id, c.label));
  });
  txn(partCategories);
  res.json({ ok: true });
});

app.put('/api/settings/logo', requireAuth, requireAdmin, (req, res) => {
  const { logo } = req.body || {};
  db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
    .run('companyLogo', logo || null);
  res.json({ ok: true });
});

/* =========================================================
   HEALTH CHECK
   ========================================================= */
app.get('/api/health', (req, res) => res.json({ ok: true, time: Date.now() }));

app.listen(PORT, () => {
  console.log(`[ezfleet] API listening on port ${PORT}`);
});
