# 系统整合部署指南

> 📅 更新时间: 2026-02-07  
> 🎯 目标: 将三个系统整合并部署

---

## 🔧 准备工作

### 1. 服务器环境检查

```bash
# SSH登录服务器
ssh root@43.134.78.126

# 检查已安装软件
node --version    # 应该 >= 18.x
python3 --version # 应该 >= 3.10
docker --version
pm2 --version
nginx -v

# 创建工作目录
mkdir -p /var/www/unified-system
cd /var/www/unified-system
```

### 2. 备份现有数据库

```bash
# 执行备份脚本
cd /var/www/chatgpt-team-helper/backend/database
python3 migrate.py --help

# 查看参数后执行备份
python3 migrate.py \
  --unified-db /var/www/unified-system/database/unified.db \
  --new-system-db /var/www/chatgpt-team-helper/db/database.sqlite \
  --old-system-db /var/www/team-invite/dev.db \
  --old-python-db /var/www/team-invite/data/team_manager.db \
  --local-db /root/local_accounts.db \
  --backup-dir /root/backups/$(date +%Y%m%d_%H%M%S) \
  --admin-username admin \
  --admin-email admin@lumizyi.store \
  --admin-password <设置强密码>
```

---

## 📦 文件部署

### 1. 上传新文件到服务器

**在本地执行**:

```powershell
# 方法1: 使用SCP (推荐)
scp -r C:\Users\86133\Desktop\chatgpt-team-helper-local\backend\database\* root@43.134.78.126:/var/www/chatgpt-team-helper/backend/database/

scp -r C:\Users\86133\Desktop\team-invite\components\* root@43.134.78.126:/var/www/team-invite/components/

scp -r C:\Users\86133\Desktop\team-invite\app\*.css root@43.134.78.126:/var/www/team-invite/app/

# 方法2: 使用SFTP
sftp root@43.134.78.126
put -r backend/database
put -r components
exit
```

### 2. 安装新依赖

```bash
# 新系统后端
cd /var/www/chatgpt-team-helper/backend
npm install bcrypt jsonwebtoken better-sqlite3 cloudscraper

# 老系统前端
cd /var/www/team-invite
npm install framer-motion

# Python依赖
pip3 install bcrypt
```

---

## 🗄️ 数据库迁移

### 1. 执行迁移脚本

```bash
cd /var/www/chatgpt-team-helper/backend/database

# 执行迁移
python3 migrate.py \
  --unified-db /var/www/chatgpt-team-helper/db/unified_database.db \
  --new-system-db /var/www/chatgpt-team-helper/db/database.sqlite \
  --old-system-db /var/www/team-invite/dev.db \
  --old-python-db /var/www/team-invite/data/team_manager.db \
  --local-db /tmp/local_accounts.db \
  --backup-dir /root/backups/migration_$(date +%Y%m%d) \
  --admin-username admin \
  --admin-email admin@lumizyi.store \
  --admin-password YourSecurePassword123!
```

### 2. 验证迁移结果

```bash
# 进入数据库
sqlite3 /var/www/chatgpt-team-helper/db/unified_database.db

-- 检查数据
SELECT COUNT(*) FROM accounts;
SELECT COUNT(*) FROM users;
SELECT COUNT(*) FROM submissions;
SELECT COUNT(*) FROM keys;
SELECT COUNT(*) FROM invited_emails;

-- 查看统计视图
SELECT * FROM v_stats;

-- 查看可用账号
SELECT * FROM v_available_accounts;

.quit
```

---

## 🔌 API整合

### 1. 更新新系统后端配置

**编辑 `/var/www/chatgpt-team-helper/backend/server.js`**:

```javascript
// 顶部添加
const unifiedRouter = require('./src/routes/unified');

// 在其他路由之前添加
app.use('/api/unified', unifiedRouter);

// 确保CORS配置包含老系统
app.use(cors({
  origin: ['https://lumizyi.store', 'http://localhost:3000'],
  credentials: true
}));
```

### 2. 更新环境变量

**编辑 `/var/www/chatgpt-team-helper/backend/.env`**:

```env
# 数据库路径(更新为统一数据库)
DATABASE_PATH=/var/www/chatgpt-team-helper/db/unified_database.db

# JWT密钥(生成新密钥)
JWT_SECRET=<运行: openssl rand -base64 64>

# API密钥
AUTO_BOARDING_API_KEY=86f0a0c8de45ca9183cb055477603feece4be5d187bd3296e985697ac2964676

# 端口
PORT=5173
```

---

## 🎨 前端改造

### 1. 修改老系统主页

**编辑 `/var/www/team-invite/app/page.tsx`**:

```tsx
import SeatsDisplay from '@/components/SeatsDisplay';
import AuthModal from '@/components/AuthModal';
import { useState } from 'react';
import '@/app/seats-display.css';
import '@/app/auth-modal.css';

export default function Home() {
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');
  
  return (
    <main>
      {/* 原有的Hero区域 */}
      {/* ... */}
      
      {/* 新增: 车位展示区 */}
      <SeatsDisplay />
      
      {/* 原有的邀请表单 */}
      {/* ... */}
      
      {/* 新增: 注册登录模态框 */}
      <AuthModal 
        isOpen={authModalOpen}
        onClose={() => setAuthModalOpen(false)}
        mode={authMode}
        onModeSwitch={() => setAuthMode(mode => mode === 'login' ? 'register' : 'login')}
      />
      
      {/* 顶部添加登录/注册按钮 */}
      <div className="header-actions">
        <button onClick={() => {setAuthMode('login'); setAuthModalOpen(true)}}>
          登录
        </button>
        <button onClick={() => {setAuthMode('register'); setAuthModalOpen(true)}}>
          注册
        </button>
      </div>
    </main>
  );
}
```

### 2. 更新邀请表单API调用

**编辑邀请表单的提交逻辑**:

```tsx
const handleSubmit = async (e: FormEvent) => {
  e.preventDefault();
  setLoading(true);
  
  try {
    // 调用新的统一API
    const response = await fetch('/api/unified/invite', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        // 如果已登录,添加token
        ...(localStorage.getItem('authToken') && {
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`
        })
      },
      body: JSON.stringify({
        email: formData.email,
        keyCode: formData.keyCode,
        redemptionCode: formData.redemptionCode,
        userId: JSON.parse(localStorage.getItem('user') || '{}').id
      })
    });
    
    const data = await response.json();
    
    if (data.success) {
      setMessage('✅ ' + data.message);
    } else {
      setMessage('❌ ' + data.message);
    }
  } catch (error) {
    setMessage('❌ 网络错误,请稍后再试');
  } finally {
    setLoading(false);
  }
};
```

### 3. 构建前端

```bash
cd /var/www/team-invite
npm run build
```

---

## 🚀 服务启动

### 1. 重启新系统Docker容器

```bash
cd /var/www/chatgpt-team-helper

# 停止容器
docker-compose down

# 修改docker-compose.yml,确保使用统一数据库
vim docker-compose.yml
# 修改volumes:
#   - ./db/unified_database.db:/app/db/database.sqlite

# 重新构建并启动
docker-compose up -d --build

# 查看日志
docker-compose logs -f
```

### 2. 重启老系统服务

```bash
# Next.js前端
pm2 restart team-invite

# 查看日志
pm2 logs team-invite
```

### 3. 重启Nginx

```bash
# 测试配置
nginx -t

# 如果有错误,检查配置文件
# vim /etc/nginx/conf.d/lumizyi.conf

# 重启Nginx
systemctl restart nginx

# 检查状态
systemctl status nginx
```

---

## ✅ 验证部署

### 1. 测试API

```bash
# 测试车位查询API
curl https://lumizyi.store/api/unified/accounts/available

# 测试注册API
curl -X POST https://lumizyi.store/api/unified/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@example.com","password":"Test123456"}'

# 测试登录API
curl -X POST https://lumizyi.store/api/unified/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@lumizyi.store","password":"YourSecurePassword123!"}'
```

### 2. 浏览器测试

访问: `https://lumizyi.store`

- [x] 车位展示区是否正常显示
- [x] 3D动画是否流畅
- [x] 注册功能是否正常
- [x] 登录功能是否正常
- [x] 邀请功能是否正常

### 3. 检查数据同步

```bash
# 查看数据库最新记录
sqlite3 /var/www/chatgpt-team-helper/db/unified_database.db

SELECT * FROM submissions ORDER BY created_at DESC LIMIT 5;
SELECT * FROM users ORDER BY created_at DESC LIMIT 5;
SELECT * FROM invited_emails ORDER BY created_at DESC LIMIT 5;

.quit
```

---

## 🔍 故障排查

### 问题1: API 404错误

```bash
# 检查路由是否正确注册
cd /var/www/chatgpt-team-helper/backend
grep -r "unified" server.js

# 检查Docker容器日志
docker-compose logs backend
```

### 问题2: 数据库连接失败

```bash
# 检查数据库文件权限
ls -la /var/www/chatgpt-team-helper/db/unified_database.db

# 修改权限
chmod 664 /var/www/chatgpt-team-helper/db/unified_database.db
chown www-data:www-data /var/www/chatgpt-team-helper/db/unified_database.db
```

### 问题3: 前端组件不显示

```bash
# 检查Next.js构建日志
pm2 logs team-invite

# 重新构建
cd /var/www/team-invite
npm run build
pm2 restart team-invite
```

### 问题4: CORS跨域错误

**编辑 `/var/www/chatgpt-team-helper/backend/server.js`**:

```javascript
app.use(cors({
  origin: function(origin, callback) {
    const allowedOrigins = [
      'https://lumizyi.store',
      'http://localhost:3000',
      'http://43.134.78.126:3000'
    ];
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));
```

---

## 📊 性能优化

### 1. 数据库优化

```bash
sqlite3 /var/www/chatgpt-team-helper/db/unified_database.db

-- 执行VACUUM优化
VACUUM;

-- 分析查询性能
ANALYZE;

-- 启用WAL模式(提高并发)
PRAGMA journal_mode=WAL;

.quit
```

### 2. Nginx缓存配置

**编辑 `/etc/nginx/conf.d/lumizyi.conf`**:

```nginx
# 静态资源缓存
location ~* \.(jpg|jpeg|png|gif|ico|css|js|woff2)$ {
  expires 30d;
  add_header Cache-Control "public, immutable";
}

# API接口不缓存
location /api/ {
  add_header Cache-Control "no-cache, no-store, must-revalidate";
  proxy_pass http://localhost:5173;
}
```

---

## 🎉 部署完成检查清单

- [ ] 数据库迁移成功
- [ ] 统一API可正常访问
- [ ] 3D车位展示正常
- [ ] 注册登录功能正常
- [ ] 邀请功能正常
- [ ] 所有服务自动重启配置完成
- [ ] 备份脚本定时任务设置
- [ ] 监控告警配置完成

---

**部署成功后,建议观察2-3天,确保系统稳定运行。**

**遇到问题请及时查看日志: `pm2 logs` 和 `docker-compose logs`**
