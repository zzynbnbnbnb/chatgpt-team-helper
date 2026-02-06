-- ============================================================
-- ChatGPT Team 统一数据库 Schema
-- 版本: v1.0
-- 创建时间: 2026-02-07
-- 说明: 整合新系统、老系统和本地工具的数据库
-- ============================================================

-- ============================================================
-- 1. 账号表 (accounts) - 核心表
-- ============================================================
CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  
  -- 基础信息
  email TEXT UNIQUE NOT NULL,
  password TEXT,                        -- 本地工具使用，服务器端不存储明文密码
  
  -- ChatGPT API 认证信息
  access_token TEXT,
  refresh_token TEXT,
  account_uuid TEXT,                    -- chatgpt_account_id / workspace_uuid
  cookies_json TEXT,                    -- Cookies数组JSON字符串
  
  -- 车位管理
  member_count INTEGER DEFAULT 0,       -- 当前成员数
  member_limit INTEGER DEFAULT 5,       -- 车位上限
  invite_count INTEGER DEFAULT 0,       -- 累计邀请数
  
  -- 优先级和状态
  priority INTEGER DEFAULT 0,           -- 优先级（数值越大越优先使用）
  status TEXT DEFAULT 'active',         -- 'active' / 'inactive' / 'expired' / 'banned'
  is_demoted BOOLEAN DEFAULT 0,         -- 是否被降级（Plus→Free）
  is_active BOOLEAN DEFAULT 1,          -- 是否启用
  
  -- 工作区信息 (本地工具)
  workspace_id TEXT,
  workspace_name TEXT,
  workspace_uuid TEXT,
  
  -- 临时邮箱相关 (本地工具)
  email_token TEXT,                     -- 临时邮箱API Token
  totp_secret TEXT,                     -- 2FA密钥（otpauth://格式）
  
  -- 时间戳
  expire_at DATETIME,                   -- Token过期时间
  last_sync DATETIME,                   -- 最后同步时间
  last_check DATETIME,                  -- 最后检查时间
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_accounts_email ON accounts(email);
CREATE INDEX IF NOT EXISTS idx_accounts_priority ON accounts(priority DESC);
CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status);
CREATE INDEX IF NOT EXISTS idx_accounts_active ON accounts(is_active);

-- ============================================================
-- 2. 用户表 (users) - 新增，用于前端注册登录
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  
  -- 基础信息
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,          -- bcrypt hash (12轮)
  role TEXT DEFAULT 'user',             -- 'super_admin' / 'admin' / 'user'
  
  -- 扩展信息
  display_name TEXT,                    -- 显示名称
  avatar_url TEXT,                      -- 头像URL
  bio TEXT,                             -- 简介
  
  -- 邀请统计
  invited_count INTEGER DEFAULT 0,      -- 该用户邀请的总人数
  referral_code TEXT UNIQUE,            -- 推荐码
  referred_by INTEGER,                  -- 推荐人ID
  
  -- 积分系统 (可选，未来扩展)
  credits INTEGER DEFAULT 0,
  
  -- Linux DO 集成
  linuxdo_user_id TEXT,
  linuxdo_username TEXT,
  linuxdo_trust_level INTEGER,
  
  -- 状态
  is_active BOOLEAN DEFAULT 1,
  is_banned BOOLEAN DEFAULT 0,
  email_verified BOOLEAN DEFAULT 0,
  email_verify_token TEXT,
  
  -- 登录相关
  last_login_at DATETIME,
  last_login_ip TEXT,
  login_count INTEGER DEFAULT 0,
  
  -- 时间戳
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  
  FOREIGN KEY (referred_by) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);

-- ============================================================
-- 3. 提交记录表 (submissions) - 合并新老系统
-- ============================================================
CREATE TABLE IF NOT EXISTS submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  
  -- 用户信息
  user_id INTEGER,                      -- 关联users表 (如果已登录)
  email TEXT NOT NULL,                  -- 提交的邮箱
  
  -- 账号和凭证
  account_id INTEGER,                   -- 使用的accounts表ID
  redemption_code_id INTEGER,           -- 使用的兑换码ID (新系统)
  key_code TEXT,                        -- 卡密 (老系统)
  
  -- 渠道信息
  channel TEXT DEFAULT 'general',       -- 'general' / 'xiaohongshu' / 'xianyu' / 'linuxdo' / 'key'
  order_number TEXT,                    -- 订单号 (小红书/闲鱼)
  
  -- 状态和结果
  status TEXT DEFAULT 'pending',        -- 'pending' / 'queued' / 'invited' / 'failed'
  error_message TEXT,                   -- 失败原因
  invite_response JSON,                 -- ChatGPT API响应JSON
  
  -- 元数据
  ip_address TEXT,                      -- 提交IP
  user_agent TEXT,                      -- User Agent
  
  -- 时间戳
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  invited_at DATETIME,                  -- 成功邀请的时间
  
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
  FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE SET NULL,
  FOREIGN KEY (redemption_code_id) REFERENCES redemption_codes(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_submissions_email ON submissions(email);
CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions(status);
CREATE INDEX IF NOT EXISTS idx_submissions_user_id ON submissions(user_id);
CREATE INDEX IF NOT EXISTS idx_submissions_created_at ON submissions(created_at DESC);

-- ============================================================
-- 4. 兑换码表 (redemption_codes)
-- ============================================================
CREATE TABLE IF NOT EXISTS redemption_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  
  -- 兑换码信息
  code TEXT UNIQUE NOT NULL,            -- 格式: XXXX-XXXX-XXXX
  account_id INTEGER NOT NULL,          -- 关联的账号
  
  -- 渠道和类型
  channel TEXT DEFAULT 'general',       -- 'general' / 'xiaohongshu' / 'xianyu' / 'purchase'
  product_type TEXT,                    -- 商品类型 (standard / no_warranty / anti_ban)
  
  -- 使用限制
  max_redemptions INTEGER DEFAULT 1,   -- 最大兑换次数
  current_redemptions INTEGER DEFAULT 0, -- 当前已兑换次数
  
  -- 状态
  is_active BOOLEAN DEFAULT 1,
  is_deleted BOOLEAN DEFAULT 0,
  
  -- 时间控制
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME,                  -- 过期时间
  
  -- 创建者
  created_by_user_id INTEGER,
  
  FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
  FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_redemption_codes_code ON redemption_codes(code);
CREATE INDEX IF NOT EXISTS idx_redemption_codes_active ON redemption_codes(is_active);
CREATE INDEX IF NOT EXISTS idx_redemption_codes_account_id ON redemption_codes(account_id);

-- ============================================================
-- 5. 卡密表 (keys) - 老系统兼容
-- ============================================================
CREATE TABLE IF NOT EXISTS keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  
  code TEXT UNIQUE NOT NULL,            -- 格式: sk-team-XXXX
  status TEXT DEFAULT 'active',         -- 'active' / 'used' / 'revoked'
  
  -- 使用信息
  used_by_email TEXT,
  used_by_user_id INTEGER,
  used_at DATETIME,
  
  -- 关联信息
  linked_redemption_code_id INTEGER,    -- 关联到新系统兑换码
  
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  
  FOREIGN KEY (used_by_user_id) REFERENCES users(id),
  FOREIGN KEY (linked_redemption_code_id) REFERENCES redemption_codes(id)
);

CREATE INDEX IF NOT EXISTS idx_keys_code ON keys(code);
CREATE INDEX IF NOT EXISTS idx_keys_status ON keys(status);

-- ============================================================
-- 6. 已邀请邮箱表 (invited_emails) - 防重复
-- ============================================================
CREATE TABLE IF NOT EXISTS invited_emails (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  
  email TEXT UNIQUE NOT NULL,           -- 邮箱 (小写存储)
  
  -- 邀请来源
  invited_by_account_id INTEGER,        -- 哪个账号发送的
  invited_by_user_id INTEGER,           -- 哪个用户触发的
  submission_id INTEGER,                -- 关联的提交记录
  
  -- 渠道
  channel TEXT DEFAULT 'general',
  
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  
  FOREIGN KEY (invited_by_account_id) REFERENCES accounts(id) ON DELETE SET NULL,
  FOREIGN KEY (invited_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
  FOREIGN KEY (submission_id) REFERENCES submissions(id) ON DELETE SET NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_invited_emails_email ON invited_emails(LOWER(email));
CREATE INDEX IF NOT EXISTS idx_invited_emails_created_at ON invited_emails(created_at DESC);

-- ============================================================
-- 7. 设置表 (settings) - KV存储
-- ============================================================
CREATE TABLE IF NOT EXISTS settings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  
  key TEXT UNIQUE NOT NULL,
  value TEXT,                           -- JSON字符串或普通文本
  value_type TEXT DEFAULT 'string',     -- 'string' / 'number' / 'boolean' / 'json'
  description TEXT,                     -- 设置说明
  category TEXT DEFAULT 'general',      -- 分类: general / ui / api / notification
  
  is_public BOOLEAN DEFAULT 0,          -- 是否公开给前端
  is_editable BOOLEAN DEFAULT 1,        -- 是否可编辑
  
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_by_user_id INTEGER,
  
  FOREIGN KEY (updated_by_user_id) REFERENCES users(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_settings_key ON settings(key);
CREATE INDEX IF NOT EXISTS idx_settings_category ON settings(category);

-- ============================================================
-- 8. 公告表 (announcements)
-- ============================================================
CREATE TABLE IF NOT EXISTS announcements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  type TEXT DEFAULT 'info',             -- 'info' / 'warning' / 'success' / 'error'
  
  -- 显示控制
  is_active BOOLEAN DEFAULT 1,
  priority INTEGER DEFAULT 0,           -- 优先级，用于排序
  
  -- 显示位置
  show_on_home BOOLEAN DEFAULT 1,       -- 首页显示
  show_on_admin BOOLEAN DEFAULT 0,      -- 管理后台显示
  
  -- 时间控制
  start_at DATETIME,                    -- 开始显示时间
  end_at DATETIME,                      -- 结束显示时间
  
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  created_by_user_id INTEGER,
  
  FOREIGN KEY (created_by_user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_announcements_active ON announcements(is_active);
CREATE INDEX IF NOT EXISTS idx_announcements_priority ON announcements(priority DESC);

-- ============================================================
-- 9. 操作日志表 (audit_logs) - 新增
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  
  -- 操作主体
  user_id INTEGER,
  username TEXT,
  ip_address TEXT,
  
  -- 操作内容
  action TEXT NOT NULL,                 -- 'create' / 'update' / 'delete' / 'login'
  resource_type TEXT,                   -- 'account' / 'user' / 'submission' / 'key'
  resource_id INTEGER,
  
  -- 操作详情
  changes JSON,                         -- 变更内容JSON
  description TEXT,
  
  -- 元数据
  user_agent TEXT,
  request_path TEXT,
  request_method TEXT,
  
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);

-- ============================================================
-- 初始化默认数据
-- ============================================================

-- 默认设置
INSERT OR IGNORE INTO settings (key, value, value_type, description, category, is_public) VALUES
-- UI 设置
('site_title', 'ChatGPT Team 车位邀请系统', 'string', '网站标题', 'ui', 1),
('site_description', '快速获取ChatGPT Team账号邀请', 'string', '网站描述', 'ui', 1),
('show_announcement', '1', 'boolean', '是否显示公告', 'ui', 1),
('show_seat_display', '1', 'boolean', '是否显示车位展示', 'ui', 1),
('enable_registration', '1', 'boolean', '是否启用注册功能', 'ui', 1),
('enable_login', '1', 'boolean', '是否启用登录功能', 'ui', 1),
('enable_key_system', '1', 'boolean', '是否启用卡密系统', 'ui', 1),

-- 业务设置
('invited_count_display', '500', 'number', '显示的邀请人数', 'general', 1),
('auto_generate_codes_count', '4', 'number', '自动生成兑换码数量', 'general', 0),
('default_member_limit', '5', 'number', '默认车位上限', 'general', 0),
('code_expire_days', '30', 'number', '兑换码默认有效期(天)', 'general', 0),

-- API 设置
('api_rate_limit_per_minute', '60', 'number', 'API速率限制(次/分钟)', 'api', 0),
('invite_cooldown_seconds', '10', 'number', '邀请冷却时间(秒)', 'api', 0);

-- 默认公告
INSERT OR IGNORE INTO announcements (id, title, content, type, is_active, priority) VALUES
(1, '欢迎使用ChatGPT Team车位邀请系统', '请输入邮箱和卡密/兑换码获取邀请。如遇问题请联系管理员。', 'info', 1, 100);

-- ============================================================
-- 数据库版本
-- ============================================================
CREATE TABLE IF NOT EXISTS schema_version (
  version TEXT PRIMARY KEY,
  applied_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  description TEXT
);

INSERT OR REPLACE INTO schema_version (version, description) VALUES
('1.0.0', '统一数据库初始版本 - 整合新系统、老系统和本地工具');

-- ============================================================
-- 触发器 (自动更新 updated_at)
-- ============================================================

-- accounts 表
CREATE TRIGGER IF NOT EXISTS update_accounts_timestamp 
AFTER UPDATE ON accounts
FOR EACH ROW
BEGIN
  UPDATE accounts SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- users 表
CREATE TRIGGER IF NOT EXISTS update_users_timestamp 
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
  UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- submissions 表
CREATE TRIGGER IF NOT EXISTS update_submissions_timestamp 
AFTER UPDATE ON submissions
FOR EACH ROW
BEGIN
  UPDATE submissions SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- announcements 表
CREATE TRIGGER IF NOT EXISTS update_announcements_timestamp 
AFTER UPDATE ON announcements
FOR EACH ROW
BEGIN
  UPDATE announcements SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- settings 表
CREATE TRIGGER IF NOT EXISTS update_settings_timestamp 
AFTER UPDATE ON settings
FOR EACH ROW
BEGIN
  UPDATE settings SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- ============================================================
-- 视图 (便捷查询)
-- ============================================================

-- 可用账号视图
CREATE VIEW IF NOT EXISTS v_available_accounts AS
SELECT 
  id,
  email,
  member_count,
  member_limit,
  (member_limit - member_count) as remaining_seats,
  priority,
  status,
  CASE 
    WHEN member_count >= member_limit THEN 'full'
    WHEN member_count >= member_limit * 0.8 THEN 'warning'
    ELSE 'available'
  END as seat_status,
  last_sync,
  created_at
FROM accounts
WHERE is_active = 1 
  AND status = 'active'
  AND member_count < member_limit
ORDER BY priority DESC, id ASC;

-- 统计视图
CREATE VIEW IF NOT EXISTS v_stats AS
SELECT
  (SELECT COUNT(*) FROM accounts WHERE is_active = 1) as total_accounts,
  (SELECT COUNT(*) FROM accounts WHERE is_active = 1 AND status = 'active') as active_accounts,
  (SELECT SUM(member_limit) FROM accounts WHERE is_active = 1) as total_capacity,
  (SELECT SUM(member_count) FROM accounts WHERE is_active = 1) as total_used,
  (SELECT SUM(member_limit - member_count) FROM accounts WHERE is_active = 1 AND member_count < member_limit) as total_remaining,
  (SELECT COUNT(*) FROM users WHERE is_active = 1) as total_users,
  (SELECT COUNT(*) FROM submissions WHERE status = 'invited') as total_invited,
  (SELECT COUNT(*) FROM redemption_codes WHERE is_active = 1) as total_active_codes;

-- ============================================================
-- 完成
-- ============================================================
-- Schema 创建完成，数据库版本: 1.0.0
