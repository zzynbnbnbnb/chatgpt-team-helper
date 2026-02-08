<script setup lang="ts">
import { onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { authService } from '@/services/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

const router = useRouter()
const route = useRoute()

const email = ref('')
const code = ref('')
const password = ref('')
const confirmPassword = ref('')
const inviteCode = ref('')
const inviteLocked = ref(false)

const error = ref('')
const success = ref('')
const loading = ref(false)
const sendingCode = ref(false)
const countdown = ref(0)

let countdownTimer: number | null = null

const startCountdown = (seconds: number) => {
  if (countdownTimer) {
    window.clearInterval(countdownTimer)
    countdownTimer = null
  }
  countdown.value = seconds
  countdownTimer = window.setInterval(() => {
    countdown.value = Math.max(0, countdown.value - 1)
    if (countdown.value <= 0 && countdownTimer) {
      window.clearInterval(countdownTimer)
      countdownTimer = null
    }
  }, 1000)
}

onUnmounted(() => {
  if (countdownTimer) {
    window.clearInterval(countdownTimer)
    countdownTimer = null
  }
})

const applyInviteFromQuery = () => {
  const raw = route.query.invite ?? route.query.inviteCode ?? route.query.code
  const value = Array.isArray(raw) ? raw[0] : raw
  const normalized = typeof value === 'string' ? value.trim() : ''
  if (normalized) {
    inviteCode.value = normalized
    inviteLocked.value = true
  } else {
    inviteLocked.value = false
  }
}

onMounted(() => {
  applyInviteFromQuery()
})

watch(() => route.query, () => applyInviteFromQuery(), { deep: true })

const handleSendCode = async () => {
  error.value = ''
  success.value = ''

  const trimmedEmail = email.value.trim().toLowerCase()
  if (!trimmedEmail) {
    error.value = '请输入邮箱'
    return
  }

  sendingCode.value = true
  try {
    await authService.sendRegisterCode(trimmedEmail)
    success.value = '验证码已发送，请检查邮箱'
    startCountdown(60)
  } catch (err: any) {
    error.value = err.response?.data?.error || '发送验证码失败，请重试'
  } finally {
    sendingCode.value = false
  }
}

const handleRegister = async () => {
  error.value = ''
  success.value = ''
  loading.value = true

  try {
    const trimmedEmail = email.value.trim().toLowerCase()
    if (!trimmedEmail) {
      error.value = '请输入邮箱'
      return
    }
    if (!code.value.trim()) {
      error.value = '请输入验证码'
      return
    }
    if (!password.value || password.value.length < 6) {
      error.value = '密码至少需要 6 个字符'
      return
    }
    if (password.value !== confirmPassword.value) {
      error.value = '两次输入的密码不一致'
      return
    }

    await authService.register({
      email: trimmedEmail,
      code: code.value.trim(),
      password: password.value,
      ...(inviteCode.value.trim() ? { inviteCode: inviteCode.value.trim() } : {}),
    })

    router.push('/admin')
  } catch (err: any) {
    error.value = err.response?.data?.error || '注册失败，请重试'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="min-h-screen w-full overflow-hidden flex items-center justify-center font-sans tech-bg">
    
    <!-- 动态粒子/流星背景效果 -->
    <div class="absolute inset-0 overflow-hidden pointer-events-none">
      <!-- 渐变光晕 -->
      <div class="absolute top-[10%] right-[20%] w-[400px] h-[400px] bg-amber-500/10 rounded-full filter blur-[100px]"></div>
      <div class="absolute bottom-[10%] left-[20%] w-[400px] h-[400px] bg-cyan-500/10 rounded-full filter blur-[100px]"></div>
      <!-- 扫描线效果 -->
      <div class="absolute inset-0 bg-[linear-gradient(transparent_50%,rgba(0,0,0,0.1)_50%)] bg-[length:100%_4px] pointer-events-none opacity-30"></div>
    </div>

    <!-- 注册卡片 -->
    <div class="relative z-10 w-full max-w-[440px] mx-4">
      <div class="glass-panel rounded-xl p-8 md:p-10 border-t-2 border-t-accent-gold transition-all duration-500 hover:shadow-[0_0_30px_rgba(251,191,36,0.15)]">
        
        <!-- 标题区域 -->
        <div class="mb-8 text-center">
          <h1 class="text-3xl font-bold text-white tracking-tight mb-2 font-cinzel">
            <span class="text-accent-gold">创建</span>
            <span class="text-accent-cyan">账号</span>
          </h1>
          <p class="text-sm text-slate-400 font-mono">使用邮箱完成注册 • Join Us</p>
        </div>

        <form @submit.prevent="handleRegister" class="space-y-5">
          <div class="space-y-2">
            <Label for="email" class="text-xs font-medium text-slate-400 ml-1 uppercase tracking-wider">邮箱</Label>
            <Input
              id="email"
              v-model="email"
              type="email"
              placeholder="name@example.com"
              required
              class="h-12 rounded-lg tech-input"
            />
          </div>

          <div class="space-y-2">
            <Label for="code" class="text-xs font-medium text-slate-400 ml-1 uppercase tracking-wider">验证码</Label>
            <div class="flex gap-3">
              <Input
                id="code"
                v-model="code"
                type="text"
                inputmode="numeric"
                placeholder="6 位数字"
                required
                class="h-12 rounded-lg tech-input flex-1"
              />
              <Button
                type="button"
                class="h-12 rounded-lg bg-gradient-to-r from-accent-gold to-orange-600 hover:from-amber-400 hover:to-orange-500 text-gray-900 font-bold px-4 whitespace-nowrap shadow-lg shadow-amber-500/20"
                :disabled="sendingCode || countdown > 0"
                @click="handleSendCode"
              >
                {{ countdown > 0 ? `${countdown}s` : (sendingCode ? '发送中...' : '发送验证码') }}
              </Button>
            </div>
          </div>

          <div class="space-y-2">
            <Label for="password" class="text-xs font-medium text-slate-400 ml-1 uppercase tracking-wider">密码</Label>
            <Input
              id="password"
              v-model="password"
              type="password"
              placeholder="至少 6 个字符"
              required
              class="h-12 rounded-lg tech-input"
            />
          </div>

          <div class="space-y-2">
            <Label for="confirmPassword" class="text-xs font-medium text-slate-400 ml-1 uppercase tracking-wider">确认密码</Label>
            <Input
              id="confirmPassword"
              v-model="confirmPassword"
              type="password"
              placeholder="再次输入密码"
              required
              class="h-12 rounded-lg tech-input"
            />
          </div>

          <div class="space-y-2">
            <Label for="inviteCode" class="text-xs font-medium text-slate-400 ml-1 uppercase tracking-wider">
              邀请码{{ inviteLocked ? '（来自邀请链接）' : '（可选）' }}
            </Label>
            <Input
              id="inviteCode"
              v-model="inviteCode"
              type="text"
              :readonly="inviteLocked"
              placeholder="填写邀请码可关联邀请人"
              class="h-12 rounded-lg tech-input"
            />
            <div v-if="inviteLocked" class="text-xs text-slate-500 ml-1">
              已从邀请链接自动填写，无法修改。
            </div>
          </div>

          <div v-if="error" class="text-sm text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3">
            {{ error }}
          </div>

          <div v-if="success" class="text-sm text-green-400 bg-green-500/10 border border-green-500/30 rounded-lg px-4 py-3">
            {{ success }}
          </div>

          <Button
            type="submit"
            class="w-full h-12 rounded-lg bg-gradient-to-r from-accent-gold to-orange-600 hover:from-amber-400 hover:to-orange-500 text-gray-900 font-bold text-[15px] shadow-lg shadow-amber-500/20 hover:shadow-xl hover:scale-[1.02] active:scale-[0.98] transition-all duration-300 mt-2"
            :disabled="loading"
          >
            <span v-if="loading" class="mr-2 w-4 h-4 border-2 border-gray-900/20 border-t-gray-900 rounded-full animate-spin"></span>
            {{ loading ? '正在注册...' : '注 册' }}
          </Button>

          <div class="text-center text-sm text-slate-400 font-medium pt-2">
            已有账号？
            <router-link to="/login" class="text-accent-cyan hover:text-cyan-300 hover:underline transition-colors">去登录</router-link>
          </div>
        </form>
      </div>

      <!-- 底部版权 -->
      <div class="mt-8 text-center">
        <p class="text-xs text-slate-600 font-mono">© 2026 Team Invite System</p>
      </div>
    </div>
  </div>
</template>

<style scoped>
.tech-bg {
  background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
}

.glass-panel {
  background: rgba(30, 41, 59, 0.8);
  backdrop-filter: blur(16px);
  border: 1px solid rgba(255, 255, 255, 0.08);
}

.tech-input {
  background: rgba(15, 23, 42, 0.6);
  border: 1px solid rgba(51, 65, 85, 0.8);
  color: #f8fafc;
  transition: all 0.3s ease;
}

.tech-input:hover {
  border-color: rgba(251, 191, 36, 0.4);
  background: rgba(15, 23, 42, 0.8);
}

.tech-input:focus {
  border-color: rgba(251, 191, 36, 0.6);
  box-shadow: 0 0 0 3px rgba(251, 191, 36, 0.1);
  background: rgba(15, 23, 42, 0.9);
}

.tech-input::placeholder {
  color: #64748b;
}

.font-cinzel {
  font-family: 'Cinzel', serif;
}

.text-accent-cyan {
  color: #22d3ee;
}

.text-accent-gold {
  color: #fbbf24;
}

.from-accent-gold {
  --tw-gradient-from: #fbbf24;
}

.to-orange-600 {
  --tw-gradient-to: #ea580c;
}

.border-t-accent-gold {
  border-top-color: #fbbf24;
}
</style>
