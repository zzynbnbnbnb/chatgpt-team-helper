#!/bin/bash
# ========================================
# 服务器部署脚本 - 一键部署
# ========================================

set -e  # 遇到错误立即退出

echo "========================================="
echo "  ChatGPT Team 系统整合部署脚本"
echo "========================================="
echo ""

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ========================================
# 步骤1: 检查环境
# ========================================
echo "📋 步骤1: 检查服务器环境..."

if ! command -v node &> /dev/null; then
    echo -e "${RED}❌ Node.js 未安装${NC}"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python3 未安装${NC}"
    exit 1
fi

if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker 未安装${NC}"
    exit 1
fi

echo -e "${GREEN}✅ 环境检查通过${NC}"
echo ""

# ========================================
# 步骤2: 从GitHub拉取最新代码
# ========================================
echo "📦 步骤2: 从GitHub拉取最新代码..."

cd /var/www/chatgpt-team-helper
git pull origin main
echo -e "${GREEN}✅ chatgpt-team-helper 更新完成${NC}"

cd /var/www/team-invite
git pull origin main
echo -e "${GREEN}✅ team-invite 更新完成${NC}"

echo ""

# ========================================
# 步骤3: 安装依赖
# ========================================
echo "📚 步骤3: 安装依赖..."

# 新系统后端依赖
cd /var/www/chatgpt-team-helper/backend
npm install bcrypt jsonwebtoken better-sqlite3 cloudscraper
echo -e "${GREEN}✅ 新系统依赖安装完成${NC}"

# 老系统前端依赖
cd /var/www/team-invite
npm install framer-motion
echo -e "${GREEN}✅ 老系统依赖安装完成${NC}"

# Python依赖
pip3 install bcrypt schedule
echo -e "${GREEN}✅ Python依赖安装完成${NC}"

echo ""

# ========================================
# 步骤4: 备份现有数据库
# ========================================
echo "💾 步骤4: 备份现有数据库..."

BACKUP_DIR="/root/backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p $BACKUP_DIR

# 备份新系统数据库
if [ -f "/var/www/chatgpt-team-helper/db/database.sqlite" ]; then
    cp /var/www/chatgpt-team-helper/db/database.sqlite $BACKUP_DIR/
    echo -e "${GREEN}✅ 新系统数据库已备份${NC}"
fi

# 备份老系统数据库
if [ -f "/var/www/team-invite/dev.db" ]; then
    cp /var/www/team-invite/dev.db $BACKUP_DIR/
    echo -e "${GREEN}✅ 老系统Prisma数据库已备份${NC}"
fi

if [ -f "/var/www/team-invite/data/team_manager.db" ]; then
    cp /var/www/team-invite/data/team_manager.db $BACKUP_DIR/
    echo -e "${GREEN}✅ 老系统Python数据库已备份${NC}"
fi

echo -e "${YELLOW}📂 备份位置: $BACKUP_DIR${NC}"
echo ""

# ========================================
# 步骤5: 创建统一数据库
# ========================================
echo "🗄️  步骤5: 创建统一数据库..."

cd /var/www/chatgpt-team-helper/backend/database

# 如果统一数据库已存在,先备份
if [ -f "/var/www/chatgpt-team-helper/db/unified_database.db" ]; then
    cp /var/www/chatgpt-team-helper/db/unified_database.db $BACKUP_DIR/
    echo -e "${YELLOW}⚠️  统一数据库已存在,已备份${NC}"
fi

# 执行Schema创建
sqlite3 /var/www/chatgpt-team-helper/db/unified_database.db < unified_schema.sql
echo -e "${GREEN}✅ 统一数据库Schema创建完成${NC}"

echo ""

# ========================================
# 步骤6: 执行数据迁移
# ========================================
echo "🔄 步骤6: 执行数据迁移..."

# 提示用户输入管理员密码
echo -e "${YELLOW}请输入管理员密码 (至少8位):${NC}"
read -s ADMIN_PASSWORD

if [ ${#ADMIN_PASSWORD} -lt 8 ]; then
    echo -e "${RED}❌ 密码长度不足8位${NC}"
    exit 1
fi

python3 migrate.py \
  --unified-db /var/www/chatgpt-team-helper/db/unified_database.db \
  --new-system-db /var/www/chatgpt-team-helper/db/database.sqlite \
  --old-system-db /var/www/team-invite/dev.db \
  --old-python-db /var/www/team-invite/data/team_manager.db \
  --local-db /tmp/local_accounts.db \
  --backup-dir $BACKUP_DIR \
  --admin-username admin \
  --admin-email admin@lumizyi.store \
  --admin-password "$ADMIN_PASSWORD"

echo -e "${GREEN}✅ 数据迁移完成${NC}"
echo ""

# ========================================
# 步骤7: 更新配置文件
# ========================================
echo "⚙️  步骤7: 更新配置文件..."

# 更新新系统环境变量
cd /var/www/chatgpt-team-helper/backend
if ! grep -q "DATABASE_PATH=/var/www/chatgpt-team-helper/db/unified_database.db" .env; then
    sed -i 's|DATABASE_PATH=.*|DATABASE_PATH=/var/www/chatgpt-team-helper/db/unified_database.db|' .env
    echo -e "${GREEN}✅ 新系统.env已更新${NC}"
fi

# 确保unified.js被引入到server.js
if ! grep -q "unified" server.js; then
    echo -e "${YELLOW}⚠️  需要手动更新server.js,添加unified路由${NC}"
fi

echo ""

# ========================================
# 步骤8: 构建前端
# ========================================
echo "🏗️  步骤8: 构建前端..."

cd /var/www/team-invite
npm run build
echo -e "${GREEN}✅ 老系统前端构建完成${NC}"

echo ""

# ========================================
# 步骤9: 重启服务
# ========================================
echo "🔄 步骤9: 重启服务..."

# 重启新系统Docker
cd /var/www/chatgpt-team-helper
docker-compose down
docker-compose up -d --build
echo -e "${GREEN}✅ 新系统Docker已重启${NC}"

# 重启老系统PM2
pm2 restart team-invite
echo -e "${GREEN}✅ 老系统PM2已重启${NC}"

# 重启Nginx
nginx -t && systemctl restart nginx
echo -e "${GREEN}✅ Nginx已重启${NC}"

echo ""

# ========================================
# 步骤10: 验证部署
# ========================================
echo "✅ 步骤10: 验证部署..."

sleep 5  # 等待服务启动

# 测试车位查询API
echo "测试API..."
API_RESPONSE=$(curl -s https://lumizyi.store/api/unified/accounts/available)

if [[ $API_RESPONSE == *"success"* ]]; then
    echo -e "${GREEN}✅ API测试通过${NC}"
else
    echo -e "${RED}❌ API测试失败${NC}"
fi

echo ""

# ========================================
# 完成
# ========================================
echo "========================================="
echo -e "${GREEN}🎉 部署完成！${NC}"
echo "========================================="
echo ""
echo "访问: https://lumizyi.store"
echo "管理后台: https://lumizyi.store/admin"
echo "管理员账号: admin"
echo "管理员邮箱: admin@lumizyi.store"
echo ""
echo "📊 查看日志:"
echo "  - Docker: docker-compose logs -f"
echo "  - PM2: pm2 logs team-invite"
echo "  - Nginx: tail -f /var/log/nginx/error.log"
echo ""
echo -e "${YELLOW}备份位置: $BACKUP_DIR${NC}"
echo ""
