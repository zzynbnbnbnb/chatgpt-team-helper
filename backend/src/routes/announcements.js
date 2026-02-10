/**
 * 公告管理路由
 */
import express from 'express'
import { getDatabase, saveDatabase } from '../database/init.js'
import { authenticateToken } from '../middleware/auth.js'
import { requireMenu } from '../middleware/rbac.js'

const router = express.Router()

// 管理员：获取公告列表
router.get('/admin/announcements', authenticateToken, requireMenu('announcements'), async (req, res) => {
    try {
        const db = getDatabase()
        const announcements = db.data.announcements || []
        res.json({ success: true, data: announcements.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)) })
    } catch (error) {
        res.status(500).json({ success: false, message: '获取公告列表失败' })
    }
})

// 管理员：创建公告
router.post('/admin/announcements', authenticateToken, requireMenu('announcements'), async (req, res) => {
    try {
        const { title, content, isActive = true } = req.body
        if (!title || !content) {
            return res.status(400).json({ success: false, message: '标题和内容不能为空' })
        }
        const db = getDatabase()
        if (!db.data.announcements) db.data.announcements = []
        const announcement = {
            id: Date.now(),
            title: title.trim(),
            content: content.trim(),
            isActive,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        }
        db.data.announcements.push(announcement)
        await saveDatabase()
        res.json({ success: true, data: announcement })
    } catch (error) {
        res.status(500).json({ success: false, message: '创建公告失败' })
    }
})

// 管理员：更新公告
router.put('/admin/announcements/:id', authenticateToken, requireMenu('announcements'), async (req, res) => {
    try {
        const { id } = req.params
        const { title, content, isActive } = req.body
        const db = getDatabase()
        const announcements = db.data.announcements || []
        const index = announcements.findIndex(a => a.id === Number(id))
        if (index === -1) return res.status(404).json({ success: false, message: '公告不存在' })
        if (title !== undefined) announcements[index].title = title.trim()
        if (content !== undefined) announcements[index].content = content.trim()
        if (isActive !== undefined) announcements[index].isActive = isActive
        announcements[index].updatedAt = new Date().toISOString()
        await saveDatabase()
        res.json({ success: true, data: announcements[index] })
    } catch (error) {
        res.status(500).json({ success: false, message: '更新公告失败' })
    }
})

// 管理员：删除公告
router.delete('/admin/announcements/:id', authenticateToken, requireMenu('announcements'), async (req, res) => {
    try {
        const { id } = req.params
        const db = getDatabase()
        const announcements = db.data.announcements || []
        const index = announcements.findIndex(a => a.id === Number(id))
        if (index === -1) return res.status(404).json({ success: false, message: '公告不存在' })
        announcements.splice(index, 1)
        await saveDatabase()
        res.json({ success: true, message: '删除成功' })
    } catch (error) {
        res.status(500).json({ success: false, message: '删除公告失败' })
    }
})

// 公开：获取最新公告
router.get('/announcements/latest', async (req, res) => {
    try {
        const db = getDatabase()
        const announcements = db.data.announcements || []
        const activeAnnouncements = announcements
            .filter(a => a.isActive)
            .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
        const latest = activeAnnouncements[0] || null
        res.json({ success: true, data: latest })
    } catch (error) {
        res.status(500).json({ success: false, message: '获取公告失败' })
    }
})

// 公开：获取所有激活的公告
router.get('/announcements', async (req, res) => {
    try {
        const db = getDatabase()
        const announcements = db.data.announcements || []
        const activeAnnouncements = announcements
            .filter(a => a.isActive)
            .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
        res.json({ success: true, data: activeAnnouncements })
    } catch (error) {
        res.status(500).json({ success: false, message: '获取公告失败' })
    }
})

// ============ 老系统公告代理接口 ============
// 通过内网直连老系统 Next.js（localhost:3000），读写老系统数据库中的 Settings 表

const OLD_SYSTEM_URL = process.env.OLD_SYSTEM_URL || 'http://127.0.0.1:3000'
const INTERNAL_API_KEY = process.env.OLD_SYSTEM_API_KEY
    || process.env.INVITE_SERVICE_SECRET
    || 'znQq35u1xhEZhcKp7D8vW4RcFgvyrhll'

// 管理员：获取老系统公告
router.get('/admin/old-system-announcement', authenticateToken, async (req, res) => {
    try {
        const response = await fetch(`${OLD_SYSTEM_URL}/api/internal/settings?key=announcement`, {
            headers: { 'x-api-key': INTERNAL_API_KEY }
        })
        const data = await response.json()
        if (data.success) {
            res.json({ success: true, data: { announcement: data.data?.value || '' } })
        } else {
            res.status(response.status).json({ success: false, message: data.message || '获取失败' })
        }
    } catch (error) {
        console.error('[OldSystem] 获取公告失败:', error?.message || error)
        res.status(502).json({ success: false, message: '无法连接老系统服务' })
    }
})

// 管理员：更新老系统公告
router.put('/admin/old-system-announcement', authenticateToken, async (req, res) => {
    try {
        const { announcement } = req.body || {}
        if (announcement === undefined) {
            return res.status(400).json({ success: false, message: '公告内容不能为空' })
        }
        const response = await fetch(`${OLD_SYSTEM_URL}/api/internal/settings`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': INTERNAL_API_KEY
            },
            body: JSON.stringify({ key: 'announcement', value: String(announcement) })
        })
        const data = await response.json()
        if (data.success) {
            res.json({ success: true, message: '公告更新成功', data: { announcement: data.data?.value || announcement } })
        } else {
            res.status(response.status).json({ success: false, message: data.message || '更新失败' })
        }
    } catch (error) {
        console.error('[OldSystem] 更新公告失败:', error?.message || error)
        res.status(502).json({ success: false, message: '无法连接老系统服务' })
    }
})

export default router
