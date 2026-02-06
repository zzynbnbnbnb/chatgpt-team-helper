#!/usr/bin/env python3
"""
数据库迁移脚本
功能: 将新系统、老系统和本地工具的数据迁移到统一数据库
版本: 1.0
创建时间: 2026-02-07
"""

import sqlite3
import json
import os
import shutil
from datetime import datetime
from typing import Dict, List, Tuple

class DatabaseMigration:
    def __init__(self, 
                 unified_db_path: str,
                 new_system_db: str,
                 old_system_db: str,
                 old_system_python_db: str,
                 local_tool_db: str):
        """
        初始化数据库迁移工具
        
        Args:
            unified_db_path: 统一数据库路径
            new_system_db: 新系统数据库路径
            old_system_db: 老系统Prisma数据库路径
            old_system_python_db: 老系统Python服务数据库路径
            local_tool_db: 本地工具数据库路径
        """
        self.unified_db_path = unified_db_path
        self.new_system_db = new_system_db
        self.old_system_db = old_system_db
        self.old_system_python_db = old_system_python_db
        self.local_tool_db = local_tool_db
        
        self.stats = {
            'accounts': 0,
            'users': 0,
            'submissions': 0,
            'redemption_codes': 0,
            'keys': 0,
            'invited_emails': 0,
            'settings': 0
        }
    
    def backup_databases(self, backup_dir: str):
        """备份所有数据库"""
        print("=" * 60)
        print("第一步: 备份现有数据库")
        print("=" * 60)
        
        os.makedirs(backup_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        databases = {
            '新系统': self.new_system_db,
            '老系统Prisma': self.old_system_db,
            '老系统Python': self.old_system_python_db,
            '本地工具': self.local_tool_db
        }
        
        for name, db_path in databases.items():
            if os.path.exists(db_path):
                backup_path = os.path.join(
                    backup_dir, 
                    f"{name.replace(' ', '_')}_{timestamp}.db"
                )
                shutil.copy2(db_path, backup_path)
                print(f"✅ {name}数据库已备份: {backup_path}")
            else:
                print(f"⚠️  {name}数据库不存在: {db_path}")
        
        print()
    
    def create_unified_database(self):
        """创建统一数据库"""
        print("=" * 60)
        print("第二步: 创建统一数据库")
        print("=" * 60)
        
        # 读取schema文件
        schema_path = os.path.join(
            os.path.dirname(__file__), 
            'unified_schema.sql'
        )
        
        with open(schema_path, 'r', encoding='utf-8') as f:
            schema_sql = f.read()
        
        # 创建数据库
        conn = sqlite3.connect(self.unified_db_path)
        conn.executescript(schema_sql)
        conn.commit()
        conn.close()
        
        print(f"✅ 统一数据库已创建: {self.unified_db_path}")
        print()
    
    def migrate_accounts(self):
        """迁移账号数据"""
        print("=" * 60)
        print("第三步: 迁移账号数据")
        print("=" * 60)
        
        unified_conn = sqlite3.connect(self.unified_db_path)
        unified_cursor = unified_conn.cursor()
        
        migrated = 0
        
        # 1. 从新系统迁移
        if os.path.exists(self.new_system_db):
            print("📦 迁移新系统账号...")
            new_conn = sqlite3.connect(self.new_system_db)
            new_cursor = new_conn.cursor()
            
            try:
                new_cursor.execute("""
                    SELECT 
                        email, token, refreshToken, chatgptAccountId,
                        userCount, inviteCount, maxUsers, isDemoted,
                        isActive, expireAt, createdAt, updatedAt
                    FROM gpt_accounts
                """)
                
                for row in new_cursor.fetchall():
                    try:
                        unified_cursor.execute("""
                            INSERT OR IGNORE INTO accounts (
                                email, access_token, refresh_token, account_uuid,
                                member_count, invite_count, member_limit, is_demoted,
                                is_active, expire_at, created_at, updated_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, row)
                        migrated += 1
                    except Exception as e:
                        print(f"  ⚠️  迁移失败: {row[0]} - {e}")
                
                print(f"  ✅ 新系统: {migrated} 个账号")
            except Exception as e:
                print(f"  ❌ 新系统迁移出错: {e}")
            finally:
                new_conn.close()
        
        # 2. 从老系统Python服务迁移
        if os.path.exists(self.old_system_python_db):
            print("📦 迁移老系统Python服务账号...")
            old_count = 0
            old_conn = sqlite3.connect(self.old_system_python_db)
            old_cursor = old_conn.cursor()
            
            try:
                old_cursor.execute("""
                    SELECT 
                        email, access_token, account_uuid, cookies_json,
                        member_count, member_limit, priority, last_sync
                    FROM accounts
                """)
                
                for row in old_cursor.fetchall():
                    try:
                        # 检查是否已存在
                        existing = unified_cursor.execute(
                            "SELECT id FROM accounts WHERE email = ?", 
                            (row[0],)
                        ).fetchone()
                        
                        if existing:
                            # 更新现有记录
                            unified_cursor.execute("""
                                UPDATE accounts SET
                                    access_token = COALESCE(?, access_token),
                                    account_uuid = COALESCE(?, account_uuid),
                                    cookies_json = COALESCE(?, cookies_json),
                                    member_count = COALESCE(?, member_count),
                                    member_limit = COALESCE(?, member_limit),
                                    priority = COALESCE(?, priority),
                                    last_sync = COALESCE(?, last_sync)
                                WHERE email = ?
                            """, (*row[1:], row[0]))
                        else:
                            # 插入新记录
                            unified_cursor.execute("""
                                INSERT INTO accounts (
                                    email, access_token, account_uuid, cookies_json,
                                    member_count, member_limit, priority, last_sync
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """, row)
                            migrated += 1
                        
                        old_count += 1
                    except Exception as e:
                        print(f"  ⚠️  迁移失败: {row[0]} - {e}")
                
                print(f"  ✅ 老系统Python: {old_count} 个账号")
            except Exception as e:
                print(f"  ❌ 老系统Python迁移出错: {e}")
            finally:
                old_conn.close()
        
        # 3. 从本地工具迁移
        if os.path.exists(self.local_tool_db):
            print("📦 迁移本地工具账号...")
            local_count = 0
            local_conn = sqlite3.connect(self.local_tool_db)
            local_cursor = local_conn.cursor()
            
            try:
                local_cursor.execute("""
                    SELECT 
                        email, password, workspace_id, workspace_name,
                        status, access_token, account_uuid, cookies_json,
                        email_token, totp_secret, last_check, created_at
                    FROM accounts
                """)
                
                for row in local_cursor.fetchall():
                    try:
                        # 检查是否已存在
                        existing = unified_cursor.execute(
                            "SELECT id FROM accounts WHERE email = ?", 
                            (row[0],)
                        ).fetchone()
                        
                        if existing:
                            # 更新本地工具特有字段
                            unified_cursor.execute("""
                                UPDATE accounts SET
                                    password = COALESCE(?, password),
                                    workspace_id = COALESCE(?, workspace_id),
                                    workspace_name = COALESCE(?, workspace_name),
                                    email_token = COALESCE(?, email_token),
                                    totp_secret = COALESCE(?, totp_secret),
                                    last_check = COALESCE(?, last_check)
                                WHERE email = ?
                            """, (row[1], row[2], row[3], row[8], row[9], row[10], row[0]))
                        else:
                            # 插入新记录
                            unified_cursor.execute("""
                                INSERT INTO accounts (
                                    email, password, workspace_id, workspace_name,
                                    status, access_token, account_uuid, cookies_json,
                                    email_token, totp_secret, last_check, created_at
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """, row)
                            migrated += 1
                        
                        local_count += 1
                    except Exception as e:
                        print(f"  ⚠️  迁移失败: {row[0]} - {e}")
                
                print(f"  ✅ 本地工具: {local_count} 个账号")
            except Exception as e:
                print(f"  ❌ 本地工具迁移出错: {e}")
            finally:
                local_conn.close()
        
        unified_conn.commit()
        
        # 统计
        total = unified_cursor.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
        self.stats['accounts'] = total
        print(f"\n📊 账号迁移完成: 共 {total} 个账号")
        
        unified_conn.close()
        print()
    
    def migrate_submissions(self):
        """迁移提交记录"""
        print("=" * 60)
        print("第四步: 迁移提交记录")
        print("=" * 60)
        
        unified_conn = sqlite3.connect(self.unified_db_path)
        unified_cursor = unified_conn.cursor()
        
        migrated = 0
        
        # 从老系统Prisma迁移
        if os.path.exists(self.old_system_db):
            print("📦 迁移老系统提交记录...")
            old_conn = sqlite3.connect(self.old_system_db)
            old_cursor = old_conn.cursor()
            
            try:
                old_cursor.execute("""
                    SELECT email, keyCode, status, createdAt, updatedAt
                    FROM Submission
                """)
                
                for row in old_cursor.fetchall():
                    try:
                        unified_cursor.execute("""
                            INSERT INTO submissions (
                                email, key_code, status, channel,
                                created_at, updated_at
                            ) VALUES (?, ?, ?, 'key', ?, ?)
                        """, row)
                        migrated += 1
                    except Exception as e:
                        print(f"  ⚠️  迁移失败: {row[0]} - {e}")
                
                print(f"  ✅ 老系统: {migrated} 条记录")
            except Exception as e:
                print(f"  ❌ 老系统迁移出错: {e}")
            finally:
                old_conn.close()
        
        unified_conn.commit()
        
        total = unified_cursor.execute("SELECT COUNT(*) FROM submissions").fetchone()[0]
        self.stats['submissions'] = total
        print(f"\n📊 提交记录迁移完成: 共 {total} 条记录")
        
        unified_conn.close()
        print()
    
    def migrate_keys(self):
        """迁移卡密"""
        print("=" * 60)
        print("第五步: 迁移卡密")
        print("=" * 60)
        
        unified_conn = sqlite3.connect(self.unified_db_path)
        unified_cursor = unified_conn.cursor()
        
        migrated = 0
        
        if os.path.exists(self.old_system_db):
            print("📦 迁移老系统卡密...")
            old_conn = sqlite3.connect(self.old_system_db)
            old_cursor = old_conn.cursor()
            
            try:
                old_cursor.execute("""
                    SELECT code, status, usedBy, usedAt, createdAt
                    FROM Key
                """)
                
                for row in old_cursor.fetchall():
                    try:
                        unified_cursor.execute("""
                            INSERT INTO keys (
                                code, status, used_by_email, used_at, created_at
                            ) VALUES (?, ?, ?, ?, ?)
                        """, row)
                        migrated += 1
                    except Exception as e:
                        print(f"  ⚠️  迁移失败: {row[0]} - {e}")
                
                print(f"  ✅ 老系统: {migrated} 个卡密")
            except Exception as e:
                print(f"  ❌ 老系统卡密迁移出错: {e}")
            finally:
                old_conn.close()
        
        unified_conn.commit()
        
        total = unified_cursor.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
        self.stats['keys'] = total
        print(f"\n📊 卡密迁移完成: 共 {total} 个卡密")
        
        unified_conn.close()
        print()
    
    def migrate_invited_emails(self):
        """迁移已邀请邮箱"""
        print("=" * 60)
        print("第六步: 迁移已邀请邮箱")
        print("=" * 60)
        
        unified_conn = sqlite3.connect(self.unified_db_path)
        unified_cursor = unified_conn.cursor()
        
        migrated = 0
        
        if os.path.exists(self.old_system_python_db):
            print("📦 迁移已邀请邮箱...")
            old_conn = sqlite3.connect(self.old_system_python_db)
            old_cursor = old_conn.cursor()
            
            try:
                old_cursor.execute("""
                    SELECT email, invited_by, invited_at
                    FROM invited_emails
                """)
                
                for row in old_cursor.fetchall():
                    try:
                        # 查找账号ID
                        account_id = unified_cursor.execute(
                            "SELECT id FROM accounts WHERE email = ?",
                            (row[1],)
                        ).fetchone()
                        
                        account_id = account_id[0] if account_id else None
                        
                        unified_cursor.execute("""
                            INSERT OR IGNORE INTO invited_emails (
                                email, invited_by_account_id, created_at
                            ) VALUES (?, ?, ?)
                        """, (row[0], account_id, row[2]))
                        migrated += 1
                    except Exception as e:
                        print(f"  ⚠️  迁移失败: {row[0]} - {e}")
                
                print(f"  ✅ 已邀请邮箱: {migrated} 条记录")
            except Exception as e:
                print(f"  ❌ 已邀请邮箱迁移出错: {e}")
            finally:
                old_conn.close()
        
        unified_conn.commit()
        
        total = unified_cursor.execute("SELECT COUNT(*) FROM invited_emails").fetchone()[0]
        self.stats['invited_emails'] = total
        print(f"\n📊 已邀请邮箱迁移完成: 共 {total} 条记录")
        
        unified_conn.close()
        print()
    
    def create_default_admin(self, username: str, email: str, password: str):
        """创建默认管理员"""
        print("=" * 60)
        print("第七步: 创建默认管理员")
        print("=" * 60)
        
        import bcrypt
        
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
        
        unified_conn = sqlite3.connect(self.unified_db_path)
        unified_cursor = unified_conn.cursor()
        
        try:
            unified_cursor.execute("""
                INSERT OR IGNORE INTO users (
                    username, email, password_hash, role, is_active, email_verified
                ) VALUES (?, ?, ?, 'super_admin', 1, 1)
            """, (username, email, password_hash.decode()))
            
            unified_conn.commit()
            print(f"✅ 管理员创建成功: {username} ({email})")
        except Exception as e:
            print(f"❌ 管理员创建失败: {e}")
        finally:
            unified_conn.close()
        
        print()
    
    def print_summary(self):
        """打印迁移总结"""
        print("=" * 60)
        print("迁移总结")
        print("=" * 60)
        print(f"✅ 账号: {self.stats['accounts']} 个")
        print(f"✅ 用户: {self.stats['users']} 个")
        print(f"✅ 提交记录: {self.stats['submissions']} 条")
        print(f"✅ 兑换码: {self.stats['redemption_codes']} 个")
        print(f"✅ 卡密: {self.stats['keys']} 个")
        print(f"✅ 已邀请邮箱: {self.stats['invited_emails']} 条")
        print("=" * 60)
        print("🎉 数据库迁移完成！")
        print()
    
    def run(self, backup_dir: str, admin_username: str, admin_email: str, admin_password: str):
        """执行完整迁移流程"""
        print("\n")
        print("╔" + "═" * 58 + "╗")
        print("║" + " " * 15 + "数据库迁移工具 v1.0" + " " * 23 + "║")
        print("╚" + "═" * 58 + "╝")
        print()
        
        self.backup_databases(backup_dir)
        self.create_unified_database()
        self.migrate_accounts()
        self.migrate_submissions()
        self.migrate_keys()
        self.migrate_invited_emails()
        self.create_default_admin(admin_username, admin_email, admin_password)
        self.print_summary()


# ============================================================
# 主程序
# ============================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='数据库迁移工具')
    parser.add_argument('--unified-db', required=True, help='统一数据库路径')
    parser.add_argument('--new-system-db', required=True, help='新系统数据库路径')
    parser.add_argument('--old-system-db', required=True, help='老系统Prisma数据库路径')
    parser.add_argument('--old-python-db', required=True, help='老系统Python数据库路径')
    parser.add_argument('--local-db', required=True, help='本地工具数据库路径')
    parser.add_argument('--backup-dir', default='./backup', help='备份目录')
    parser.add_argument('--admin-username', default='admin', help='管理员用户名')
    parser.add_argument('--admin-email', default='admin@example.com', help='管理员邮箱')
    parser.add_argument('--admin-password', default='Admin@123456', help='管理员密码')
    
    args = parser.parse_args()
    
    # 运行迁移
    migration = DatabaseMigration(
        unified_db_path=args.unified_db,
        new_system_db=args.new_system_db,
        old_system_db=args.old_system_db,
        old_system_python_db=args.old_python_db,
        local_tool_db=args.local_db
    )
    
    migration.run(
        backup_dir=args.backup_dir,
        admin_username=args.admin_username,
        admin_email=args.admin_email,
        admin_password=args.admin_password
    )
