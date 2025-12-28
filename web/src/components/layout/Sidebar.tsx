import { Link, useLocation, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard,
  Server,
  Users,
  Shield,
  Key,
  Settings,
  FileText,
  Activity,
  Network,
  ChevronLeft,
  ChevronRight,
  LogOut,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { useAuthStore } from '@/stores/auth'
import { useTranslation } from '@/i18n/useTranslation'
import { useState } from 'react'

export function Sidebar() {
  const location = useLocation()
  const navigate = useNavigate()
  const { logout, identity } = useAuthStore()
  const { t } = useTranslation()
  const [collapsed, setCollapsed] = useState(false)

  const navigation = [
    { name: t('nav.dashboard'), href: '/', icon: LayoutDashboard },
    { name: t('nav.devices'), href: '/devices', icon: Server },
    { name: t('nav.identities'), href: '/identities', icon: Users },
    { name: t('nav.policies'), href: '/policies', icon: Shield },
    { name: t('nav.capabilities'), href: '/capabilities', icon: Key },
    { name: t('nav.configs'), href: '/configs', icon: Settings },
    { name: t('nav.topology'), href: '/topology', icon: Network },
    { name: t('nav.audit'), href: '/audit', icon: FileText },
    { name: t('nav.monitoring'), href: '/monitoring', icon: Activity },
  ]

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  return (
    <div
      className={cn(
        'flex h-screen flex-col border-r bg-card transition-all duration-300',
        collapsed ? 'w-16' : 'w-64'
      )}
    >
      <div className="flex h-16 items-center justify-between border-b px-4">
        {!collapsed && (
          <div className="flex items-center gap-2">
            <Shield className="h-8 w-8 text-primary" />
            <span className="text-lg font-bold">ZT-NMS</span>
          </div>
        )}
        {collapsed && <Shield className="h-8 w-8 text-primary mx-auto" />}
        <Button
          variant="ghost"
          size="icon"
          onClick={() => setCollapsed(!collapsed)}
          className={cn(collapsed && 'mx-auto')}
        >
          {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
        </Button>
      </div>

      <ScrollArea className="flex-1 py-4">
        <nav className="space-y-1 px-2">
          {navigation.map((item) => {
            const isActive = location.pathname === item.href
            return (
              <Link
                key={item.name}
                to={item.href}
                className={cn(
                  'flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors',
                  isActive
                    ? 'bg-primary text-primary-foreground'
                    : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground',
                  collapsed && 'justify-center'
                )}
                title={collapsed ? item.name : undefined}
              >
                <item.icon className="h-5 w-5 shrink-0" />
                {!collapsed && <span>{item.name}</span>}
              </Link>
            )
          })}
        </nav>
      </ScrollArea>

      <div className="border-t p-4">
        {!collapsed && identity && (
          <div className="mb-3 truncate text-sm">
            <p className="font-medium">
              {(identity.attributes as { username?: string })?.username || 'User'}
            </p>
            <p className="text-xs text-muted-foreground">
              {(identity.attributes as { email?: string })?.email}
            </p>
          </div>
        )}
        <Button
          variant="ghost"
          className={cn('w-full justify-start gap-3', collapsed && 'justify-center px-0')}
          onClick={handleLogout}
        >
          <LogOut className="h-5 w-5" />
          {!collapsed && <span>{t('nav.logout')}</span>}
        </Button>
      </div>
    </div>
  )
}
