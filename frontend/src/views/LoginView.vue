<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { authService } from '@/services/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

const router = useRouter()
const username = ref('')
const password = ref('')
const error = ref('')
const loading = ref(false)

const handleLogin = async () => {
  error.value = ''
  loading.value = true

  try {
    await authService.login(username.value, password.value)
    router.push('/admin')
  } catch (err: any) {
    error.value = err.response?.data?.error || '登录失败，请重试'
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
      <div class="absolute top-[10%] left-[20%] w-[400px] h-[400px] bg-cyan-500/10 rounded-full filter blur-[100px]"></div>
      <div class="absolute bottom-[10%] right-[20%] w-[400px] h-[400px] bg-amber-500/10 rounded-full filter blur-[100px]"></div>
      <!-- 扫描线效果 -->
      <div class="absolute inset-0 bg-[linear-gradient(transparent_50%,rgba(0,0,0,0.1)_50%)] bg-[length:100%_4px] pointer-events-none opacity-30"></div>
    </div>

    <!-- 登录卡片 -->
    <div class="relative z-10 w-full max-w-[420px] mx-4">
      <div class="glass-panel rounded-xl p-8 md:p-10 border-t-2 border-t-accent-cyan transition-all duration-500 hover:shadow-[0_0_30px_rgba(34,211,238,0.15)]">
        
        <!-- 标题区域 -->
        <div class="mb-10 text-center">
          <h1 class="text-3xl font-bold text-white tracking-tight mb-2 font-cinzel">
            <span class="text-accent-cyan">Team</span>
            <span class="text-accent-gold">车位</span>
          </h1>
          <p class="text-sm text-slate-400 font-mono">请登录以继续 • Secure Access</p>
        </div>

        <form @submit.prevent="handleLogin" class="space-y-6">
          <div class="space-y-2">
            <Label for="username" class="text-xs font-medium text-slate-400 ml-1 uppercase tracking-wider">账号</Label>
            <Input
              id="username"
              v-model="username"
              type="text"
              placeholder="请输入用户名或邮箱"
              required
              class="h-12 rounded-lg tech-input"
            />
          </div>

          <div class="space-y-2">
            <Label for="password" class="text-xs font-medium text-slate-400 ml-1 uppercase tracking-wider">密码</Label>
            <Input
              id="password"
              v-model="password"
              type="password"
              placeholder="请输入密码"
              required
              class="h-12 rounded-lg tech-input"
            />
          </div>

          <div v-if="error" class="text-sm text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3">
            {{ error }}
          </div>

          <Button 
            type="submit" 
            class="w-full h-12 rounded-lg bg-gradient-to-r from-accent-cyan to-cyan-600 hover:from-cyan-400 hover:to-cyan-500 text-gray-900 font-bold text-[15px] shadow-lg shadow-cyan-500/20 hover:shadow-xl hover:scale-[1.02] active:scale-[0.98] transition-all duration-300 mt-4"
            :disabled="loading"
          >
            <span v-if="loading" class="mr-2 w-4 h-4 border-2 border-gray-900/20 border-t-gray-900 rounded-full animate-spin"></span>
            {{ loading ? '正在登录...' : '登 录' }}
          </Button>

          <div class="text-center text-sm text-slate-400 font-medium pt-2">
            没有账号？
            <router-link to="/register" class="text-accent-gold hover:text-amber-300 hover:underline transition-colors">去注册</router-link>
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
  border-color: rgba(34, 211, 238, 0.4);
  background: rgba(15, 23, 42, 0.8);
}

.tech-input:focus {
  border-color: rgba(34, 211, 238, 0.6);
  box-shadow: 0 0 0 3px rgba(34, 211, 238, 0.1);
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

.from-accent-cyan {
  --tw-gradient-from: #22d3ee;
}

.to-cyan-600 {
  --tw-gradient-to: #0891b2;
}

.border-t-accent-cyan {
  border-top-color: #22d3ee;
}
</style>
