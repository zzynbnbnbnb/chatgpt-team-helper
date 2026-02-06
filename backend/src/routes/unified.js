/**
 * 统一API路由
 * 功能: 整合所有核心API,包括认证、邀请、账号管理等
 * 版本: 1.0
 */

const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Database } = require('better-sqlite3');
const cloudscraper = require('cloudscraper');

// 数据库连接
const db = new Database(process.env.DATABASE_PATH || './database/unified_database.db');

// JWT密钥
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// ============================================================
// 中间件
// ============================================================

/**
 * 验证JWT Token
 */
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.replace('Bearer ', '');

    if (!token) {
        return res.status(401).json({ success: false, error: '未授权' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ success: false, error: 'Token无效或已过期' });
    }
};

/**
 * 速率限制 (简单实现)
 */
const rateLimitMap = new Map();
const rateLimit = (limit = 60, window = 60000) => {
    return (req, res, next) => {
        const ip = req.ip || req.connection.remoteAddress;
        const now = Date.now();
        const record = rateLimitMap.get(ip) || { count: 0, resetTime: now + window };

        if (now > record.resetTime) {
            record.count = 0;
            record.resetTime = now + window;
        }

        record.count++;
        rateLimitMap.set(ip, record);

        if (record.count > limit) {
            return res.status(429).json({
                success: false,
                error: '请求过于频繁,请稍后再试'
            });
        }

        next();
    };
};

// ============================================================
// 认证API
// ============================================================

/**
 * POST /api/unified/auth/register
 * 用户注册
 */
router.post('/auth/register', rateLimit(10, 60000), async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // 验证输入
        if (!username || !email || !password) {
            return res.status(400).json({
                success: false,
                error: '请填写所有必填字段'
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                success: false,
                error: '密码长度至少8位'
            });
        }

        // 检查用户是否存在
        const existing = db.prepare(
            'SELECT id FROM users WHERE email = ? OR username = ?'
        ).get(email, username);

        if (existing) {
            return res.status(400).json({
                success: false,
                error: '用户名或邮箱已存在'
            });
        }

        // 密码加密
        const passwordHash = await bcrypt.hash(password, 12);

        // 生成推荐码
        const referralCode = `REF${Date.now().toString(36)}${Math.random().toString(36).substr(2, 5)}`.toUpperCase();

        // 创建用户
        const result = db.prepare(`
      INSERT INTO users (username, email, password_hash, referral_code, is_active, email_verified)
      VALUES (?, ?, ?, ?, 1, 0)
    `).run(username, email, passwordHash, referralCode);

        // 生成JWT
        const token = jwt.sign(
            { userId: result.lastInsertRowid, username, role: 'user' },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        // 记录审计日志
        db.prepare(`
      INSERT INTO audit_logs (user_id, username, ip_address, action, resource_type, description)
      VALUES (?, ?, ?, 'create', 'user', '用户注册')
    `).run(result.lastInsertRowid, username, req.ip);

        res.json({
            success: true,
            token,
            user: {
                id: result.lastInsertRowid,
                username,
                email,
                role: 'user',
                referralCode
            }
        });

    } catch (error) {
        console.error('注册失败:', error);
        res.status(500).json({ success: false, error: '服务器错误' });
    }
});

/**
 * POST /api/unified/auth/login
 * 用户登录
 */
router.post('/auth/login', rateLimit(20, 60000), async (req, res) => {
    try {
        const { email, password } = req.body;

        // 查找用户
        const user = db.prepare(
            'SELECT * FROM users WHERE email = ?'
        ).get(email);

        if (!user) {
            return res.status(401).json({
                success: false,
                error: '邮箱或密码错误'
            });
        }

        if (!user.is_active) {
            return res.status(403).json({
                success: false,
                error: '账号已被禁用,请联系管理员'
            });
        }

        // 验证密码
        const isValid = await bcrypt.compare(password, user.password_hash);
        if (!isValid) {
            return res.status(401).json({
                success: false,
                error: '邮箱或密码错误'
            });
        }

        // 更新登录信息
        db.prepare(`
      UPDATE users 
      SET last_login_at = CURRENT_TIMESTAMP,
          last_login_ip = ?,
          login_count = login_count + 1
      WHERE id = ?
    `).run(req.ip, user.id);

        // 生成JWT
        const token = jwt.sign(
            { userId: user.id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        // 记录审计日志
        db.prepare(`
      INSERT INTO audit_logs (user_id, username, ip_address, action, description)
      VALUES (?, ?, ?, 'login', '用户登录')
    `).run(user.id, user.username, req.ip);

        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role,
                displayName: user.display_name,
                referralCode: user.referral_code
            }
        });

    } catch (error) {
        console.error('登录失败:', error);
        res.status(500).json({ success: false, error: '服务器错误' });
    }
});

// ============================================================
// 车位查询API
// ============================================================

/**
 * GET /api/unified/accounts/available
 * 获取可用车位列表
 */
router.get('/accounts/available', async (req, res) => {
    try {
        // 获取所有可用账号
        const accounts = db.prepare(`
      SELECT 
        id,
        email,
        member_count,
        member_limit,
        priority,
        status,
        (member_limit - member_count) as remaining
      FROM accounts
      WHERE is_active = 1
        AND status = 'active'
      ORDER BY priority DESC, id ASC
    `).all();

        // 计算统计信息
        const stats = {
            totalAccounts: accounts.length,
            totalRemaining: accounts.reduce((sum, acc) => sum + acc.remaining, 0),
            totalCapacity: accounts.reduce((sum, acc) => sum + acc.member_limit, 0),
            totalUsed: accounts.reduce((sum, acc) => sum + acc.member_count, 0)
        };

        // 脱敏邮箱并标记状态
        const maskedAccounts = accounts.map(acc => {
            const percentage = (acc.member_count / acc.member_limit) * 100;
            return {
                id: acc.id,
                email: acc.email.substring(0, 15) + '***',
                used: acc.member_count,
                total: acc.member_limit,
                remaining: acc.remaining,
                priority: acc.priority,
                status: percentage >= 100 ? 'full' : percentage >= 80 ? 'warning' : 'available'
            };
        });

        res.json({
            success: true,
            accounts: maskedAccounts,
            stats
        });

    } catch (error) {
        console.error('获取车位信息失败:', error);
        res.status(500).json({ success: false, error: '服务器错误' });
    }
});

// ============================================================
// 邀请API
// ============================================================

/**
 * 检查邮箱是否已被邀请
 */
const checkEmailInvited = (email) => {
    const result = db.prepare(
        'SELECT id FROM invited_emails WHERE LOWER(email) = LOWER(?)'
    ).get(email);
    return !!result;
};

/**
 * 验证卡密
 */
const validateKeyCode = (keyCode) => {
    const key = db.prepare(
        'SELECT * FROM keys WHERE code = ? AND status = \'active\''
    ).get(keyCode);
    return key;
};

/**
 * 验证兑换码
 */
const validateRedemptionCode = (redemptionCode) => {
    const code = db.prepare(`
    SELECT * FROM redemption_codes 
    WHERE code = ? 
      AND is_active = 1 
      AND current_redemptions < max_redemptions
      AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
  `).get(redemptionCode);
    return code;
};

/**
 * 选择可用账号
 */
const selectAvailableAccount = (accountId = null) => {
    if (accountId) {
        // 使用指定账号
        return db.prepare(`
      SELECT * FROM accounts 
      WHERE id = ? 
        AND is_active = 1 
        AND status = 'active' 
        AND member_count < member_limit
    `).get(accountId);
    } else {
        // 按优先级选择
        return db.prepare(`
      SELECT * FROM accounts
      WHERE is_active = 1
        AND status = 'active'
        AND member_count < member_limit
      ORDER BY priority DESC, member_count ASC
      LIMIT 1
    `).get();
    }
};

/**
 * 发送ChatGPT邀请
 */
const sendChatGPTInvite = async (account, email) => {
    try {
        const scraper = cloudscraper.create({
            browser: { browser: 'chrome', platform: 'windows', mobile: false }
        });

        const inviteUrl = `https://chatgpt.com/backend-api/accounts/${account.account_uuid}/invites`;

        const headers = {
            'Authorization': `Bearer ${account.access_token}`,
            'Content-Type': 'application/json',
            'chatgpt-account-id': account.account_uuid,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        };

        const payload = {
            email_addresses: [email],
            role: 'standard-user',
            resend_emails: false
        };

        const response = await scraper.post(inviteUrl, {
            headers,
            json: payload,
            timeout: 20000
        });

        if (response.statusCode === 201 || response.statusCode === 200) {
            return { success: true, message: '邀请发送成功' };
        } else {
            return {
                success: false,
                error: `邀请失败: HTTP ${response.statusCode}`
            };
        }

    } catch (error) {
        return {
            success: false,
            error: error.message || '网络请求失败'
        };
    }
};

/**
 * POST /api/unified/invite
 * 统一邀请接口
 */
router.post('/invite', rateLimit(30, 60000), async (req, res) => {
    const { email, keyCode, redemptionCode, userId } = req.body;

    try {
        // 1. 验证邮箱格式
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.json({ success: false, error: '邮箱格式无效' });
        }

        // 2. 检查是否已邀请
        if (checkEmailInvited(email)) {
            return res.json({ success: false, error: '该邮箱已被邀请过' });
        }

        // 3. 验证卡密或兑换码
        let account = null;
        let channel = 'general';
        let codeId = null;

        if (keyCode) {
            const key = validateKeyCode(keyCode);
            if (!key) {
                return res.json({ success: false, error: '无效的卡密或已使用' });
            }
            channel = 'key';
        }

        if (redemptionCode) {
            const code = validateRedemptionCode(redemptionCode);
            if (!code) {
                return res.json({ success: false, error: '无效的兑换码、已用完或已过期' });
            }
            account = selectAvailableAccount(code.account_id);
            channel = code.channel;
            codeId = code.id;
        }

        // 4. 如果没有指定账号,选择可用账号
        if (!account) {
            account = selectAvailableAccount();
        }

        if (!account) {
            return res.json({ success: false, error: '当前无可用车位,请稍后再试' });
        }

        // 5. 发送邀请
        const inviteResult = await sendChatGPTInvite(account, email);

        // 6. 记录提交
        const submissionResult = db.prepare(`
      INSERT INTO submissions (
        user_id, email, account_id, redemption_code_id, key_code,
        channel, status, error_message, ip_address, user_agent,
        invited_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
            userId || null,
            email,
            account.id,
            codeId,
            keyCode || null,
            channel,
            inviteResult.success ? 'invited' : 'failed',
            inviteResult.error || null,
            req.ip,
            req.headers['user-agent'],
            inviteResult.success ? new Date().toISOString() : null
        );

        // 7. 如果成功,更新相关数据
        if (inviteResult.success) {
            // 更新车位计数
            db.prepare(`
        UPDATE accounts 
        SET member_count = member_count + 1,
            invite_count = invite_count + 1,
            last_sync = CURRENT_TIMESTAMP
        WHERE id = ?
      `).run(account.id);

            // 记录已邀请邮箱
            db.prepare(`
        INSERT INTO invited_emails (email, invited_by_account_id, invited_by_user_id, submission_id, channel)
        VALUES (?, ?, ?, ?, ?)
      `).run(email, account.id, userId || null, submissionResult.lastInsertRowid, channel);

            // 更新兑换码使用次数
            if (codeId) {
                db.prepare(`
          UPDATE redemption_codes 
          SET current_redemptions = current_redemptions + 1
          WHERE id = ?
        `).run(codeId);
            }

            // 更新卡密状态
            if (keyCode) {
                db.prepare(`
          UPDATE keys 
          SET status = 'used',
              used_by_email = ?,
              used_by_user_id = ?,
              used_at = CURRENT_TIMESTAMP
          WHERE code = ?
        `).run(email, userId || null, keyCode);
            }
        }

        res.json({
            success: inviteResult.success,
            message: inviteResult.success ? '邀请已发送,请查收邮箱' : inviteResult.error,
            account: inviteResult.success ? {
                email: account.email.substring(0, 10) + '***',
                remaining: account.member_limit - account.member_count - 1
            } : null
        });

    } catch (error) {
        console.error('邀请失败:', error);
        res.status(500).json({ success: false, error: '服务器错误' });
    }
});

// ============================================================
// 导出路由
// ============================================================

module.exports = router;
