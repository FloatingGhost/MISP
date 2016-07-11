-- --------------------------------------------------------

--
-- Table structure for table admin_settings
--

CREATE TABLE IF NOT EXISTS admin_settings (
  id bigserial NOT NULL,
  setting varchar(255) NOT NULL,
  value text NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table attributes
--

CREATE TABLE IF NOT EXISTS attributes (
  id bigserial NOT NULL,
  event_id bigint NOT NULL,
  category varchar(255) NOT NULL,
  type varchar(100) NOT NULL,
  value1 text NOT NULL,
  value2 text NOT NULL,
  to_ids smallint NOT NULL DEFAULT 1,
  uuid varchar(40) NOT NULL,
  timestamp bigint NOT NULL DEFAULT 0,
  distribution smallint NOT NULL DEFAULT 0,
  sharing_group_id bigint NOT NULL,
  comment text NOT NULL,
  deleted smallint NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  UNIQUE (uuid)
);
CREATE INDEX idx_attributes_event_id ON attributes (event_id);
CREATE INDEX idx_attributes_sharing_group_id ON attributes (sharing_group_id);
CREATE INDEX idx_attributes_value1 ON attributes (value1);
CREATE INDEX idx_attributes_value2 ON attributes (value2);

-- --------------------------------------------------------

--
-- Table structure for table bruteforces
--

CREATE TABLE IF NOT EXISTS bruteforces (
  ip varchar(255) NOT NULL,
  username varchar(255) NOT NULL,
  expire timestamp NOT NULL
);

-- --------------------------------------------------------

--
-- Table structure for table cake_sessions
--

CREATE TABLE IF NOT EXISTS cake_sessions (
  id varchar(255) NOT NULL DEFAULT '',
  data text NOT NULL,
  expires bigint NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table correlations
--

CREATE TABLE IF NOT EXISTS correlations (
  id bigserial NOT NULL,
  value text NOT NULL,
  "1_event_id" bigint NOT NULL,
  "1_attribute_id" bigint NOT NULL,
  event_id bigint NOT NULL,
  attribute_id bigint NOT NULL,
  org_id bigint NOT NULL,
  distribution smallint NOT NULL,
  a_distribution smallint NOT NULL,
  sharing_group_id bigint NOT NULL,
  a_sharing_group_id bigint NOT NULL,
  date date NOT NULL,
  info text NOT NULL,
  PRIMARY KEY (id)
);
CREATE INDEX idx_correlations_event_id ON correlations (event_id);
CREATE INDEX idx_correlations_1_event_id ON correlations ("1_event_id");
CREATE INDEX idx_correlations_attribute_id ON correlations (attribute_id);
CREATE INDEX idx_correlations_1_attribute_id ON correlations ("1_attribute_id");
CREATE INDEX idx_correlations_org_id ON correlations (org_id);
CREATE INDEX idx_correlations_sharing_group_id ON correlations (sharing_group_id);
CREATE INDEX idx_correlations_a_sharing_group_id ON correlations (a_sharing_group_id);

-- --------------------------------------------------------

--
-- Table structure for table events
--

CREATE TABLE IF NOT EXISTS events (
  id bigserial NOT NULL,
  org_id bigint NOT NULL,
  date date NOT NULL,
  info text NOT NULL,
  user_id bigint NOT NULL,
  uuid varchar(40) NOT NULL,
  published smallint NOT NULL DEFAULT 0,
  analysis smallint NOT NULL,
  attribute_count bigint CHECK (attribute_count >= 0) DEFAULT NULL,
  orgc_id bigint NOT NULL,
  timestamp bigint NOT NULL DEFAULT 0,
  distribution smallint NOT NULL DEFAULT 0,
  sharing_group_id bigint NOT NULL,
  proposal_email_lock smallint NOT NULL DEFAULT 0,
  locked smallint NOT NULL DEFAULT 0,
  threat_level_id bigint NOT NULL,
  publish_timestamp bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  UNIQUE (uuid)
);
CREATE INDEX idx_events_info ON events (info);
CREATE INDEX idx_events_sharing_group_id ON events (sharing_group_id);
CREATE INDEX idx_events_org_id ON events (org_id);
CREATE INDEX idx_events_orgc_id ON events (orgc_id);

-- -------------------------------------------------------

--
-- Table structure for event_delegations
--

CREATE TABLE IF NOT EXISTS event_delegations (
  id bigserial NOT NULL,
  org_id bigint NOT NULL,
  requester_org_id bigint NOT NULL,
  event_id bigint NOT NULL,
  message text,
  distribution smallint NOT NULL DEFAULT -1,
  sharing_group_id bigint,
  PRIMARY KEY (id)
);
CREATE INDEX idx_event_delegations_org_id ON event_delegations (org_id);
CREATE INDEX idx_event_delegations_event_id ON event_delegations (event_id);

-- -------------------------------------------------------

--
-- Table structure for event_tags
--

CREATE TABLE IF NOT EXISTS event_tags (
  id bigserial NOT NULL,
  event_id bigint NOT NULL,
  tag_id bigint NOT NULL,
  PRIMARY KEY (id)
);
CREATE INDEX idx_event_tags_event_id ON event_tags (event_id);
CREATE INDEX idx_event_tags_tag_id ON event_tags (tag_id);

-- -------------------------------------------------------

--
-- Table structure for favourite_tags
--

CREATE TABLE IF NOT EXISTS favourite_tags (
  id bigserial NOT NULL,
  tag_id bigint NOT NULL,
  user_id bigint NOT NULL,
  PRIMARY KEY (id)
);
CREATE INDEX idx_favourite_tags_user_id ON favourite_tags (user_id);
CREATE INDEX idx_favourite_tags_tag_id ON favourite_tags (tag_id);

-- -------------------------------------------------------

--
-- Table structure for feeds
--

CREATE TABLE IF NOT EXISTS feeds (
  id bigserial NOT NULL,
  name varchar(255) NOT NULL,
  provider varchar(255) NOT NULL,
  url varchar(255) NOT NULL,
  rules text DEFAULT NULL,
  enabled smallint NOT NULL,
  distribution smallint NOT NULL,
  sharing_group_id bigint NOT NULL DEFAULT 0,
  tag_id bigint NOT NULL DEFAULT 0,
  "default" smallint NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table jobs
--

CREATE TABLE IF NOT EXISTS jobs (
  id bigserial NOT NULL,
  worker varchar(32) NOT NULL,
  job_type varchar(32) NOT NULL,
  job_input text NOT NULL,
  status smallint NOT NULL DEFAULT 0,
  retries bigint NOT NULL DEFAULT 0,
  message text NOT NULL,
  progress bigint NOT NULL DEFAULT 0,
  org_id bigint NOT NULL DEFAULT 0,
  process_id varchar(32) DEFAULT NULL,
  date_created timestamp NOT NULL,
  date_modified timestamp NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table logs
--

CREATE TABLE IF NOT EXISTS logs (
  id bigserial NOT NULL,
  title text DEFAULT NULL,
  created timestamp NOT NULL,
  model varchar(20) NOT NULL,
  model_id bigint NOT NULL,
  action varchar(20) NOT NULL,
  user_id bigint NOT NULL,
  change text DEFAULT NULL,
  email varchar(255) NOT NULL,
  org varchar(255) NOT NULL,
  description text DEFAULT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table news
--

CREATE TABLE IF NOT EXISTS news (
  id bigserial NOT NULL,
  message text NOT NULL,
  title text NOT NULL,
  user_id bigint NOT NULL,
  date_created bigint NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table organisations
--

CREATE TABLE organisations (
  id bigserial NOT NULL,
  name varchar(255) NOT NULL,
  date_created timestamp NOT NULL,
  date_modified timestamp NOT NULL,
  description text,
  type varchar(255),
  nationality varchar(255),
  sector varchar(255),
  created_by bigint NOT NULL DEFAULT 0,
  uuid varchar(40) DEFAULT NULL,
  contacts text,
  local smallint NOT NULL DEFAULT 0,
  landingpage text,
  PRIMARY KEY (id)
);
CREATE INDEX idx_organisations_uuid ON organisations (uuid);
CREATE INDEX idx_organisations_name ON organisations (name);

-- --------------------------------------------------------

--
-- Table structure for table posts
--

CREATE TABLE IF NOT EXISTS posts (
  id bigserial NOT NULL,
  date_created timestamp NOT NULL,
  date_modified timestamp NOT NULL,
  user_id bigint NOT NULL,
  contents text NOT NULL,
  post_id bigint NOT NULL DEFAULT 0,
  thread_id bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (id)
);
CREATE INDEX idx_posts_post_id ON posts (post_id);
CREATE INDEX idx_posts_thread_id ON posts (thread_id);

-- --------------------------------------------------------

--
-- Table structure for table regexp
--

CREATE TABLE IF NOT EXISTS regexp (
  id bigserial NOT NULL,
  regexp varchar(255) NOT NULL,
  replacement varchar(255) NOT NULL,
  type varchar(100) NOT NULL DEFAULT 'ALL',
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table roles
--

CREATE TABLE IF NOT EXISTS roles (
  id bigserial NOT NULL,
  name varchar(100) NOT NULL,
  created timestamp DEFAULT NULL,
  modified timestamp DEFAULT NULL,
  perm_add smallint DEFAULT NULL,
  perm_modify smallint DEFAULT NULL,
  perm_modify_org smallint DEFAULT NULL,
  perm_publish smallint DEFAULT NULL,
  perm_delegate smallint NOT NULL DEFAULT 0,
  perm_sync smallint DEFAULT NULL,
  perm_admin smallint DEFAULT NULL,
  perm_audit smallint DEFAULT NULL,
  perm_full smallint DEFAULT NULL,
  perm_auth smallint NOT NULL DEFAULT 0,
  perm_site_admin smallint NOT NULL DEFAULT 0,
  perm_regexp_access smallint NOT NULL DEFAULT 0,
  perm_tagger smallint NOT NULL DEFAULT 0,
  perm_template smallint NOT NULL DEFAULT 0,
  perm_sharing_group smallint NOT NULL DEFAULT 0,
  perm_tag_editor smallint NOT NULL DEFAULT 0,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table servers
--

CREATE TABLE IF NOT EXISTS servers (
  id bigserial NOT NULL,
  name varchar(255) NOT NULL,
  url varchar(255) NOT NULL,
  authkey varchar(40) NOT NULL,
  org_id bigint NOT NULL,
  push smallint NOT NULL,
  pull smallint NOT NULL,
  lastpulledid bigint DEFAULT NULL,
  lastpushedid bigint DEFAULT NULL,
  organization varchar(10) DEFAULT NULL,
  remote_org_id bigint NOT NULL,
  self_signed smallint NOT NULL,
  pull_rules text NOT NULL,
  push_rules text NOT NULL,
  cert_file varchar(255) DEFAULT NULL,
  PRIMARY KEY (id)
);
CREATE INDEX idx_servers_org_id ON servers (org_id);
CREATE INDEX idx_servers_remote_org_id ON servers (remote_org_id);

-- --------------------------------------------------------

--
-- Table structure for table shadow_attributes
--

CREATE TABLE IF NOT EXISTS shadow_attributes (
  id bigserial NOT NULL,
  old_id bigint NOT NULL,
  event_id bigint NOT NULL,
  type varchar(100) NOT NULL,
  category varchar(255) NOT NULL,
  value1 text,
  to_ids smallint NOT NULL DEFAULT 1,
  uuid varchar(40) NOT NULL,
  value2 text,
  org_id bigint NOT NULL,
  email varchar(255) NOT NULL,
  event_org_id bigint NOT NULL,
  comment text NOT NULL,
  event_uuid varchar(40) NOT NULL,
  deleted smallint NOT NULL DEFAULT 0,
  timestamp bigint NOT NULL DEFAULT 0,
  proposal_to_delete BOOLEAN NOT NULL,
  PRIMARY KEY (id)
);
CREATE INDEX idx_shadow_attributes_event_id ON shadow_attributes (event_id);
CREATE INDEX idx_shadow_attributes_event_uuid ON shadow_attributes (event_uuid);
CREATE INDEX idx_shadow_attributes_event_org_id ON shadow_attributes (event_org_id);
CREATE INDEX idx_shadow_attributes_uuid ON shadow_attributes (uuid);
CREATE INDEX idx_shadow_attributes_old_id ON shadow_attributes (old_id);
CREATE INDEX idx_shadow_attributes_value1 ON shadow_attributes (value1);
CREATE INDEX idx_shadow_attributes_value2 ON shadow_attributes (value2);

-- --------------------------------------------------------

--
-- Table structure for table shadow_attribute_correlations
--

CREATE TABLE IF NOT EXISTS shadow_attribute_correlations (
  id bigserial NOT NULL,
  org_id bigint NOT NULL,
  value text NOT NULL,
  distribution smallint NOT NULL,
  a_distribution smallint NOT NULL,
  sharing_group_id bigint,
  a_sharing_group_id bigint,
  attribute_id bigint NOT NULL,
  "1_shadow_attribute_id" bigint NOT NULL,
  event_id bigint NOT NULL,
  "1_event_id" bigint NOT NULL,
  info text NOT NULL,
  PRIMARY KEY (id)
);
CREATE INDEX idx_shadow_attribute_correlations_org_id ON shadow_attribute_correlations (org_id);
CREATE INDEX idx_shadow_attribute_correlations_attribute_id ON shadow_attribute_correlations (attribute_id);
CREATE INDEX idx_shadow_attribute_correlations_a_sharing_group_id ON shadow_attribute_correlations (a_sharing_group_id);
CREATE INDEX idx_shadow_attribute_correlations_event_id ON shadow_attribute_correlations (event_id);
CREATE INDEX idx_shadow_attribute_correlations_1_event_id ON shadow_attribute_correlations ("1_event_id");
CREATE INDEX idx_shadow_attribute_correlations_sharing_group_id ON shadow_attribute_correlations (sharing_group_id);
CREATE INDEX idx_shadow_attribute_correlations_1_shadow_attribute_id ON shadow_attribute_correlations ("1_shadow_attribute_id");

-- --------------------------------------------------------

--
-- Table structure for table sharing_group_orgs
--

CREATE TABLE sharing_group_orgs (
  id bigserial NOT NULL,
  sharing_group_id bigint NOT NULL,
  org_id bigint NOT NULL,
  extend smallint NOT NULL DEFAULT 0,
  PRIMARY KEY (id)
);
CREATE INDEX idx_sharing_group_orgs_org_id ON sharing_group_orgs (org_id);
CREATE INDEX idx_sharing_group_orgs_sharing_group_id ON sharing_group_orgs (sharing_group_id);

-- --------------------------------------------------------

--
-- Table structure for table sharing_group_servers
--

CREATE TABLE sharing_group_servers (
  id bigserial NOT NULL,
  sharing_group_id bigint NOT NULL,
  server_id bigint NOT NULL,
  all_orgs smallint NOT NULL,
  PRIMARY KEY (id)
);
CREATE INDEX idx_sharing_group_servers_server_id ON sharing_group_servers (server_id);
CREATE INDEX idx_sharing_group_servers_sharing_group_id ON sharing_group_servers (sharing_group_id);

-- --------------------------------------------------------

--
-- Table structure for table sharing_groups
--

CREATE TABLE sharing_groups (
  id bigserial NOT NULL,
  name varchar(255) NOT NULL,
  releasability text NOT NULL,
  description text NOT NULL,
  uuid varchar(40) NOT NULL,
  organisation_uuid varchar(40) NOT NULL,
  org_id bigint NOT NULL,
  sync_user_id bigint NOT NULL DEFAULT 0,
  active smallint NOT NULL,
  created timestamp NOT NULL,
  modified timestamp NOT NULL,
  local smallint NOT NULL,
  PRIMARY KEY (id),
  UNIQUE (uuid)
);
CREATE INDEX idx_sharing_groups_org_id ON sharing_groups (org_id);
CREATE INDEX idx_sharing_groups_sync_user_id ON sharing_groups (sync_user_id);
CREATE INDEX idx_sharing_groups_organisation_uuid ON sharing_groups (organisation_uuid);

-- --------------------------------------------------------

--
-- Table structure for table tags
--

CREATE TABLE IF NOT EXISTS tags (
  id bigserial NOT NULL,
  name varchar(255) NOT NULL,
  colour varchar(7) NOT NULL,
  exportable smallint NOT NULL,
  PRIMARY KEY (id)
);


-- --------------------------------------------------------

--
-- Table structure for table tasks
--

CREATE TABLE IF NOT EXISTS tasks (
  id bigserial NOT NULL,
  type varchar(100) NOT NULL,
  timer bigint NOT NULL,
  scheduled_time varchar(8) NOT NULL DEFAULT '6:00',
  job_id bigint NOT NULL,
  description varchar(255) NOT NULL,
  next_execution_time bigint NOT NULL,
  message varchar(255) NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table taxonomies
--

CREATE TABLE IF NOT EXISTS taxonomies (
  id bigserial NOT NULL,
  namespace varchar(255) NOT NULL,
  description text NOT NULL,
  version bigint NOT NULL,
  enabled smallint NOT NULL DEFAULT 0,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table taxonomy_entries
--

CREATE TABLE IF NOT EXISTS taxonomy_entries (
  id bigserial NOT NULL,
  taxonomy_predicate_id bigint NOT NULL,
  value text NOT NULL,
  expanded text,
  PRIMARY KEY (id)
);
CREATE INDEX idx_taxonomy_entries_taxonomy_predicate_id ON taxonomy_entries (taxonomy_predicate_id);

-- --------------------------------------------------------

--
-- Table structure for table taxonomy_predicates
--

CREATE TABLE IF NOT EXISTS taxonomy_predicates (
  id bigserial NOT NULL,
  taxonomy_id bigint NOT NULL,
  value text NOT NULL,
  expanded text,
  PRIMARY KEY (id)
);
CREATE INDEX idx_taxonomy_predicates_taxonomy_id ON taxonomy_predicates (taxonomy_id);

-- --------------------------------------------------------

--
-- Table structure for table templates
--

CREATE TABLE IF NOT EXISTS templates (
  id bigserial NOT NULL,
  name varchar(255) NOT NULL,
  description varchar(255) NOT NULL,
  org varchar(255) NOT NULL,
  share smallint NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table template_elements
--

CREATE TABLE IF NOT EXISTS template_elements (
  id bigserial NOT NULL,
  template_id bigint NOT NULL,
  position bigint NOT NULL,
  element_definition varchar(255) NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table template_element_attributes
--

CREATE TABLE IF NOT EXISTS template_element_attributes (
  id bigserial NOT NULL,
  template_element_id bigint NOT NULL,
  name varchar(255) NOT NULL,
  description text NOT NULL,
  to_ids smallint NOT NULL DEFAULT 1,
  category varchar(255) NOT NULL,
  complex smallint NOT NULL,
  type varchar(255) NOT NULL,
  mandatory smallint NOT NULL,
  batch smallint NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table template_element_files
--

CREATE TABLE IF NOT EXISTS template_element_files (
  id bigserial NOT NULL,
  template_element_id bigint NOT NULL,
  name varchar(255) NOT NULL,
  description text NOT NULL,
  category varchar(255) NOT NULL,
  malware smallint NOT NULL,
  mandatory smallint NOT NULL,
  batch smallint NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table template_element_texts
--

CREATE TABLE IF NOT EXISTS template_element_texts (
  id bigserial NOT NULL,
  name varchar(255) NOT NULL,
  template_element_id bigint NOT NULL,
  text text NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table template_tags
--

CREATE TABLE IF NOT EXISTS template_tags (
  id bigserial NOT NULL,
  template_id bigint NOT NULL,
  tag_id bigint NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table threads
--

CREATE TABLE IF NOT EXISTS threads (
  id bigserial NOT NULL,
  date_created timestamp NOT NULL,
  date_modified timestamp NOT NULL,
  distribution smallint NOT NULL,
  user_id bigint NOT NULL,
  post_count bigint NOT NULL,
  event_id bigint NOT NULL,
  title varchar(255) NOT NULL,
  org_id bigint NOT NULL,
  sharing_group_id bigint NOT NULL,
  PRIMARY KEY (id)
);
CREATE INDEX idx_threads_user_id ON threads (user_id);
CREATE INDEX idx_threads_event_id ON threads (event_id);
CREATE INDEX idx_threads_org_id ON threads (org_id);
CREATE INDEX idx_threads_sharing_group_id ON threads (sharing_group_id);

-- --------------------------------------------------------

--
-- Table structure for table threat_levels
--

CREATE TABLE IF NOT EXISTS threat_levels (
  id bigserial NOT NULL,
  name varchar(50) NOT NULL,
  description varchar(255) DEFAULT NULL,
  form_description varchar(255) NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table users
--

CREATE TABLE IF NOT EXISTS users (
  id bigserial NOT NULL,
  password varchar(40) NOT NULL,
  org_id bigint NOT NULL,
  server_id bigint NOT NULL DEFAULT 0,
  email varchar(255) NOT NULL,
  autoalert smallint NOT NULL DEFAULT 0,
  authkey varchar(40) DEFAULT NULL,
  invited_by bigint NOT NULL DEFAULT 0,
  gpgkey text,
  certif_public text NOT NULL DEFAULT '',
  nids_sid bigint NOT NULL DEFAULT 0,
  termsaccepted smallint NOT NULL DEFAULT 0,
  newsread bigint DEFAULT 0,
  role_id bigint NOT NULL DEFAULT 0,
  change_pw smallint NOT NULL DEFAULT 0,
  contactalert smallint NOT NULL DEFAULT 0,
  disabled BOOLEAN NOT NULL DEFAULT false,
  expiration timestamp DEFAULT NULL,
  current_login bigint DEFAULT 0,
  last_login bigint DEFAULT 0,
  force_logout smallint NOT NULL DEFAULT 0,
  PRIMARY KEY (id)
);
CREATE INDEX idx_users_email ON users (email);
CREATE INDEX idx_users_org_id ON users (org_id);
CREATE INDEX idx_users_server_id ON users (server_id);

-- --------------------------------------------------------

--
-- Table structure for table warninglists
--

CREATE TABLE IF NOT EXISTS warninglists (
  id bigserial NOT NULL,
  name varchar(255) NOT NULL,
  type varchar(255) NOT NULL DEFAULT 'string',
  description text NOT NULL,
  version bigint NOT NULL DEFAULT '1',
  enabled smallint NOT NULL DEFAULT '0',
  warninglist_entry_count bigint DEFAULT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table warninglist_entries
--

CREATE TABLE IF NOT EXISTS warninglist_entries (
  id bigserial NOT NULL,
  value text NOT NULL,
  warninglist_id bigint NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table warninglist_types
--

CREATE TABLE IF NOT EXISTS warninglist_types (
  id bigserial NOT NULL,
  type varchar(255) NOT NULL,
  warninglist_id bigint NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Table structure for table whitelist
--

CREATE TABLE IF NOT EXISTS whitelist (
  id bigserial NOT NULL,
  name text NOT NULL,
  PRIMARY KEY (id)
);

-- --------------------------------------------------------

--
-- Default values for initial installation
--

INSERT INTO admin_settings (id, setting, value) VALUES
(1, 'db_version', '2.4.48');
SELECT setval('admin_settings_id_seq', (SELECT max(id) FROM admin_settings));

INSERT INTO feeds (id, provider, name, url, distribution, "default", enabled) VALUES
(1, 'CIRCL', 'CIRCL OSINT Feed', 'https://www.circl.lu/doc/misp/feed-osint', 3, 1, 0),
(2, 'Botvrij.eu', 'The Botvrij.eu Data', 'http://www.botvrij.eu/data/feed-osint', 3, 1, 0);
SELECT setval('feeds_id_seq', (SELECT max(id) FROM feeds));

 INSERT INTO regexp (id, regexp, replacement, type) VALUES
 (1, '/.:.ProgramData./i', '%ALLUSERSPROFILE%\\\\', 'ALL'),
 (2, '/.:.Documents and Settings.All Users./i', '%ALLUSERSPROFILE%\\\\', 'ALL'),
 (3, '/.:.Program Files.Common Files./i', '%COMMONPROGRAMFILES%\\\\', 'ALL'),
 (4, '/.:.Program Files (x86).Common Files./i', '%COMMONPROGRAMFILES(x86)%\\\\', 'ALL'),
 (5, '/.:.Users\\\\(.*?)\\\\AppData.Local.Temp./i', '%TEMP%\\\\', 'ALL'),
 (6, '/.:.ProgramData./i', '%PROGRAMDATA%\\\\', 'ALL'),
 (7, '/.:.Program Files./i', '%PROGRAMFILES%\\\\', 'ALL'),
 (8, '/.:.Program Files (x86)./i', '%PROGRAMFILES(X86)%\\\\', 'ALL'),
 (9, '/.:.Users.Public./i', '%PUBLIC%\\\\', 'ALL'),
 (10, '/.:.Documents and Settings\\\\(.*?)\\\\Local Settings.Temp./i', '%TEMP%\\\\', 'ALL'),
 (11, '/.:.Users\\\\(.*?)\\\\AppData.Local.Temp./i', '%TEMP%\\\\', 'ALL'),
 (12, '/.:.Users\\\\(.*?)\\\\AppData.Local./i', '%LOCALAPPDATA%\\\\', 'ALL'),
 (13, '/.:.Users\\\\(.*?)\\\\AppData.Roaming./i', '%APPDATA%\\\\', 'ALL'),
 (14, '/.:.Users\\\\(.*?)\\\\Application Data./i', '%APPDATA%\\\\', 'ALL'),
 (15, '/.:.Windows\\\\(.*?)\\\\Application Data./i', '%APPDATA%\\\\', 'ALL'),
 (16, '/.:.Users\\\\(.*?)\\\\/i', '%USERPROFILE%\\\\', 'ALL'),
 (17, '/.:.DOCUME~1.\\\\(.*?)\\\\/i', '%USERPROFILE%\\\\', 'ALL'),
 (18, '/.:.Documents and Settings\\\\(.*?)\\\\/i', '%USERPROFILE%\\\\', 'ALL'),
 (19, '/.:.Windows./i', '%WINDIR%\\\\', 'ALL'),
 (20, '/.:.Windows./i', '%WINDIR%\\\\', 'ALL'),
 (21, '/.REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{9}){1}(-[0-9]{10}){1}-[0-9]{9}-[0-9]{4}/i', 'HKCU', 'ALL'),
 (22, '/.REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{10}){2}-[0-9]{9}-[0-9]{4}/i', 'HKCU', 'ALL'),
 (23, '/.REGISTRY.USER.S(-[0-9]{1}){2}-[0-9]{2}(-[0-9]{10}){3}-[0-9]{4}/i', 'HKCU', 'ALL'),
 (24, '/.REGISTRY.MACHINE./i', 'HKLM\\\\', 'ALL'),
 (25, '/.Registry.Machine./i', 'HKLM\\\\', 'ALL'),
 (26, '/%USERPROFILE%.Application Data.Microsoft.UProof/i', '', 'ALL'),
 (27, '/%USERPROFILE%.Local Settings.History/i', '', 'ALL'),
 (28, '/%APPDATA%.Microsoft.UProof/i ', '', 'ALL'),
 (29, '/%LOCALAPPDATA%.Microsoft.Windows.Temporary Internet Files/i', '', 'ALL');
SELECT setval('regexp_id_seq', (SELECT max(id) FROM regexp));

-- --------------------------------------------------------

--
-- Creating initial roles
--
-- 1. Admin - has full access
-- 2. Org Admin - read/write/publish/audit/admin/sync/auth/tagger
-- 3. User - User - Read / Write, no other permissions (default)
-- 4. Publisher
-- 5. Sync user - read/write/publish/sync/auth
-- 6. Automation user - read/write/publish/auth
-- 7. Read Only - read
--

INSERT INTO roles (id ,name ,created ,modified ,perm_add ,perm_modify ,perm_modify_org ,perm_publish ,perm_sync ,perm_admin ,perm_audit ,perm_full ,perm_auth, perm_regexp_access, perm_tagger, perm_site_admin, perm_template, perm_sharing_group, perm_tag_editor)
VALUES ('1', 'admin', NOW() , NOW() , '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1');

INSERT INTO roles (id ,name ,created ,modified ,perm_add ,perm_modify ,perm_modify_org ,perm_publish ,perm_sync ,perm_admin ,perm_audit ,perm_full ,perm_auth, perm_regexp_access, perm_tagger, perm_site_admin, perm_template, perm_sharing_group, perm_tag_editor)
VALUES ('2', 'Org Admin', NOW() , NOW() , '1', '1', '1' , '1', '1', '1', '1', '0' , '1', '0', '1', '0', '1', '1', '1');

INSERT INTO roles (id ,name ,created ,modified ,perm_add ,perm_modify ,perm_modify_org ,perm_publish ,perm_sync ,perm_admin ,perm_audit ,perm_full ,perm_auth, perm_regexp_access, perm_tagger, perm_site_admin, perm_template, perm_sharing_group, perm_tag_editor)
VALUES ('3', 'User', NOW() , NOW() , '1', '1', '1' , '0' , '0' , '0' , '0' , '0' , '0', '0', '0', '0', '0', '0', '0');

INSERT INTO roles (id ,name ,created ,modified ,perm_add ,perm_modify ,perm_modify_org ,perm_publish ,perm_sync ,perm_admin ,perm_audit ,perm_full ,perm_auth, perm_regexp_access, perm_tagger, perm_site_admin, perm_template, perm_sharing_group, perm_tag_editor)
VALUES ('4', 'Publisher', NOW() , NOW() , '1', '1', '1' , '1' , '0' , '0' , '0' , '0' , '0', '0', '0', '0', '0', '0', '0');

INSERT INTO roles (id, name, created, modified, perm_add, perm_modify, perm_modify_org, perm_publish, perm_sync, perm_admin, perm_audit, perm_full, perm_auth, perm_regexp_access, perm_tagger, perm_site_admin, perm_template, perm_sharing_group, perm_tag_editor)
VALUES ('5', 'Sync user', NOW(), NOW(), '1', '1', '1', '1', '1', '0', '0', '0', '1', '0', '0', '0', '0', '1', '0');

INSERT INTO roles (id, name, created, modified, perm_add, perm_modify, perm_modify_org, perm_publish, perm_sync, perm_admin, perm_audit, perm_full, perm_auth, perm_regexp_access, perm_tagger, perm_site_admin, perm_template, perm_sharing_group, perm_tag_editor)
VALUES ('6', 'Automation user', NOW(), NOW(), '1', '1', '1', '1', '0', '0', '0', '0', '1', '0', '0', '0', '0', '0', '0');

INSERT INTO roles (id, name, created, modified, perm_add, perm_modify, perm_modify_org, perm_publish, perm_sync, perm_admin, perm_audit, perm_full, perm_auth, perm_regexp_access, perm_tagger, perm_site_admin, perm_template, perm_sharing_group, perm_tag_editor)
VALUES ('7', 'Read Only', NOW(), NOW(), '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0');

SELECT setval('roles_id_seq', (SELECT max(id) FROM roles));

-- --------------------------------------------------------

--
-- Initial threat levels
--

INSERT INTO threat_levels (id, name, description, form_description)
VALUES
  (1,'High','*high* means sophisticated APT malware or 0-day attack','Sophisticated APT malware or 0-day attack'),
  (2,'Medium','*medium* means APT malware','APT malware'),
  (3,'Low','*low* means mass-malware','Mass-malware'),
  (4,'Undefined','*undefined* no risk','No risk');
SELECT setval('threat_levels_id_seq', (SELECT max(id) FROM threat_levels));

-- --------------------------------------------------------

--
-- Default templates
--

INSERT INTO templates (id, name, description, org, share) VALUES
(1, 'Phishing E-mail', 'Create a MISP event about a Phishing E-mail.', 'MISP', 1),
(2, 'Phishing E-mail with malicious attachment', 'A MISP event based on Spear-phishing containing a malicious attachment. This event can include anything from the description of the e-mail itself, the malicious attachment and its description as well as the results of the analysis done on the malicious f', 'MISP', 1),
(3, 'Malware Report', 'This is a template for a generic malware report. ', 'MISP', 1),
(4, 'Indicator List', 'A simple template for indicator lists.', 'MISP', 1);
SELECT setval('templates_id_seq', (SELECT max(id) FROM templates));

INSERT INTO template_elements (id, template_id, position, element_definition) VALUES
(1, 1, 2, 'attribute'),
(2, 1, 3, 'attribute'),
(3, 1, 1, 'text'),
(4, 1, 4, 'attribute'),
(5, 1, 5, 'text'),
(6, 1, 6, 'attribute'),
(7, 1, 7, 'attribute'),
(8, 1, 8, 'attribute'),
(11, 2, 1, 'text'),
(12, 2, 2, 'attribute'),
(13, 2, 3, 'text'),
(14, 2, 4, 'file'),
(15, 2, 5, 'attribute'),
(16, 2, 10, 'text'),
(17, 2, 6, 'attribute'),
(18, 2, 7, 'attribute'),
(19, 2, 8, 'attribute'),
(20, 2, 9, 'attribute'),
(21, 2, 11, 'file'),
(22, 2, 12, 'attribute'),
(23, 2, 13, 'attribute'),
(24, 2, 14, 'attribute'),
(25, 2, 15, 'attribute'),
(26, 2, 16, 'attribute'),
(27, 2, 17, 'attribute'),
(28, 2, 18, 'attribute'),
(29, 3, 1, 'text'),
(30, 3, 2, 'file'),
(31, 3, 4, 'text'),
(32, 3, 9, 'text'),
(33, 3, 11, 'text'),
(34, 3, 10, 'attribute'),
(35, 3, 12, 'attribute'),
(36, 3, 3, 'attribute'),
(37, 3, 5, 'attribute'),
(38, 3, 6, 'attribute'),
(39, 3, 7, 'attribute'),
(40, 3, 8, 'file'),
(41, 3, 13, 'text'),
(42, 3, 14, 'attribute'),
(43, 3, 15, 'attribute'),
(44, 3, 16, 'attribute'),
(45, 4, 1, 'text'),
(46, 4, 2, 'attribute'),
(47, 4, 3, 'attribute');
SELECT setval('template_elements_id_seq', (SELECT max(id) FROM template_elements));

INSERT INTO template_element_attributes (id, template_element_id, name, description, to_ids, category, complex, type, mandatory, batch) VALUES
(1, 1, 'From address', 'The source address from which the e-mail was sent.', 1, 'Payload delivery', 0, 'email-src', 1, 1),
(2, 2, 'Malicious url', 'The malicious url in the e-mail body.', 1, 'Payload delivery', 0, 'url', 1, 1),
(3, 4, 'E-mail subject', 'The subject line of the e-mail.', 0, 'Payload delivery', 0, 'email-subject', 1, 0),
(4, 6, 'Spoofed source address', 'If an e-mail address was spoofed, specify which.', 1, 'Payload delivery', 0, 'email-src', 0, 0),
(5, 7, 'Source IP', 'The source IP from which the e-mail was sent', 1, 'Payload delivery', 0, 'ip-src', 0, 1),
(6, 8, 'X-mailer header', 'It could be useful to capture which application and which version thereof was used to send the message, as described by the X-mailer header.', 1, 'Payload delivery', 0, 'text', 0, 1),
(7, 12, 'From address', 'The source address from which the e-mail was sent', 1, 'Payload delivery', 0, 'email-src', 1, 1),
(8, 15, 'Spoofed From Address', 'The spoofed source address from which the e-mail appears to be sent.', 1, 'Payload delivery', 0, 'email-src', 0, 1),
(9, 17, 'E-mail Source IP', 'The IP address from which the e-mail was sent.', 1, 'Payload delivery', 0, 'ip-src', 0, 1),
(10, 18, 'X-mailer header', 'It could be useful to capture which application and which version thereof was used to send the message, as described by the X-mailer header.', 1, 'Payload delivery', 0, 'text', 0, 0),
(11, 19, 'Malicious URL in the e-mail', 'If there was a malicious URL (or several), please specify it here', 1, 'Payload delivery', 0, 'ip-dst', 0, 1),
(12, 20, 'Exploited vulnerablity', 'The vulnerabilities exploited during the payload delivery.', 0, 'Payload delivery', 0, 'vulnerability', 0, 1),
(13, 22, 'C2 information', 'Command and Control information detected during the analysis.', 1, 'Network activity', 1, 'CnC', 0, 1),
(14, 23, 'Artifacts dropped (File)', 'Any information about the files dropped during the analysis', 1, 'Artifacts dropped', 1, 'File', 0, 1),
(15, 24, 'Artifacts dropped (Registry key)', 'Any registry keys touched during the analysis', 1, 'Artifacts dropped', 0, 'regkey', 0, 1),
(16, 25, 'Artifacts dropped (Registry key + value)', 'Any registry keys created or altered together with the value.', 1, 'Artifacts dropped', 0, 'regkey|value', 0, 1),
(17, 26, 'Persistance mechanism (filename)', 'Filenames (or filenames with filepaths) used as a persistence mechanism', 1, 'Persistence mechanism', 0, 'regkey|value', 0, 1),
(18, 27, 'Persistence mechanism (Registry key)', 'Any registry keys touched as part of the persistence mechanism during the analysis ', 1, 'Persistence mechanism', 0, 'regkey', 0, 1),
(19, 28, 'Persistence mechanism (Registry key + value)', 'Any registry keys created or modified together with their values used by the persistence mechanism', 1, 'Persistence mechanism', 0, 'regkey|value', 0, 1),
(20, 34, 'C2 Information', 'You can drop any urls, domains, hostnames or IP addresses that were detected as the Command and Control during the analysis here. ', 1, 'Network activity', 1, 'CnC', 0, 1),
(21, 35, 'Other Network Activity', 'Drop any applicable information about other network activity here. The attributes created here will NOT be marked for IDS exports.', 0, 'Network activity', 1, 'CnC', 0, 1),
(22, 36, 'Vulnerability', 'The vulnerability or vulnerabilities that the sample exploits', 0, 'Payload delivery', 0, 'vulnerability', 0, 1),
(23, 37, 'Artifacts Dropped (File)', 'Insert any data you have on dropped files here.', 1, 'Artifacts dropped', 1, 'File', 0, 1),
(24, 38, 'Artifacts dropped (Registry key)', 'Any registry keys touched during the analysis', 1, 'Artifacts dropped', 0, 'regkey', 0, 1),
(25, 39, 'Artifacts dropped (Registry key + value)', 'Any registry keys created or altered together with the value.', 1, 'Artifacts dropped', 0, 'regkey|value', 0, 1),
(26, 42, 'Persistence mechanism (filename)', 'Insert any filenames used by the persistence mechanism.', 1, 'Persistence mechanism', 0, 'filename', 0, 1),
(27, 43, 'Persistence Mechanism (Registry key)', 'Paste any registry keys that were created or modified as part of the persistence mechanism', 1, 'Persistence mechanism', 0, 'regkey', 0, 1),
(28, 44, 'Persistence Mechanism (Registry key and value)', 'Paste any registry keys together with the values contained within created or modified by the persistence mechanism', 1, 'Persistence mechanism', 0, 'regkey|value', 0, 1),
(29, 46, 'Network Indicators', 'Paste any combination of IP addresses, hostnames, domains or URL', 1, 'Network activity', 1, 'CnC', 0, 1),
(30, 47, 'File Indicators', 'Paste any file hashes that you have (MD5, SHA1, SHA256) or filenames below. You can also add filename and hash pairs by using the following syntax for each applicable column: filename|hash ', 1, 'Payload installation', 1, 'File', 0, 1);
SELECT setval('template_element_attributes_id_seq', (SELECT max(id) FROM template_element_attributes));

INSERT INTO template_element_files (id, template_element_id, name, description, category, malware, mandatory, batch) VALUES
(1, 14, 'Malicious Attachment', 'The file (or files) that was (were) attached to the e-mail itself.', 'Payload delivery', 1, 0, 1),
(2, 21, 'Payload installation', 'Payload installation detected during the analysis', 'Payload installation', 1, 0, 1),
(3, 30, 'Malware sample', 'The sample that the report is based on', 'Payload delivery', 1, 0, 0),
(4, 40, 'Artifacts dropped (Sample)', 'Upload any files that were dropped during the analysis.', 'Artifacts dropped', 1, 0, 1);
SELECT setval('template_element_files_id_seq', (SELECT max(id) FROM template_element_files));

INSERT INTO template_element_texts (id, name, template_element_id, text) VALUES
(1, 'Required fields', 3, 'The fields below are mandatory.'),
(2, 'Optional information', 5, 'All of the fields below are optional, please fill out anything that''s applicable.'),
(4, 'Required Fields', 11, 'The following fields are mandatory'),
(5, 'Optional information about the payload delivery', 13, 'All of the fields below are optional, please fill out anything that''s applicable. This section describes the payload delivery, including the e-mail itself, the attached file, the vulnerability it is exploiting and any malicious urls in the e-mail.'),
(6, 'Optional information obtained from analysing the malicious file', 16, 'Information about the analysis of the malware (if applicable). This can include C2 information, artifacts dropped during the analysis, persistance mechanism, etc.'),
(7, 'Malware Sample', 29, 'If you can, please upload the sample that the report revolves around.'),
(8, 'Dropped Artifacts', 31, 'Describe any dropped artifacts that you have encountered during your analysis'),
(9, 'C2 Information', 32, 'The following field deals with Command and Control information obtained during the analysis. All fields are optional.'),
(10, 'Other Network Activity', 33, 'If any other Network activity (such as an internet connection test) was detected during the analysis, please specify it using the following fields'),
(11, 'Persistence mechanism', 41, 'The following fields allow you to describe the persistence mechanism used by the malware'),
(12, 'Indicators', 45, 'Just paste your list of indicators based on type into the appropriate field. All of the fields are optional, so inputting a list of IP addresses into the Network indicator field for example is sufficient to complete this template.');
SELECT setval('template_element_texts_id_seq', (SELECT max(id) FROM template_element_texts));

-- --------------------------------------------------------

--
-- Default tasks
--

INSERT INTO tasks (id, type, timer, scheduled_time, job_id, description, next_execution_time, message) VALUES
(1, 'cache_exports', 0, '12:00', 0, 'Generates export caches for every export type and for every organisation. This process is heavy, schedule so it might be a good idea to schedule this outside of working hours and before your daily automatic imports on connected services are scheduled.', 1391601600, 'Not scheduled yet.'),
(2, 'pull_all', 0, '12:00', 0, 'Initiates a full pull for all eligible instances.', 1391601600, 'Not scheduled yet.'),
(3, 'push_all', 0, '12:00', 0, 'Initiates a full push for all eligible instances.', 1391601600, 'Not scheduled yet.');
SELECT setval('tasks_id_seq', (SELECT max(id) FROM tasks));
