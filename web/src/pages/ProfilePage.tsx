import { useState } from 'react'
import { User, Mail, Shield, Key, Calendar, Clock, Lock } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { useAuthStore } from '@/stores/auth'
import { useTranslation } from '@/i18n/useTranslation'

export function ProfilePage() {
  const { t } = useTranslation()
  const { identity } = useAuthStore()
  const [showPasswordForm, setShowPasswordForm] = useState(false)
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [passwordError, setPasswordError] = useState<string | null>(null)
  const [passwordSuccess, setPasswordSuccess] = useState(false)

  const attributes = identity?.attributes as {
    username?: string
    email?: string
    display_name?: string
    role?: string
  } | undefined

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault()
    setPasswordError(null)
    setPasswordSuccess(false)

    if (newPassword !== confirmPassword) {
      setPasswordError(t('profile.passwordMismatch'))
      return
    }

    // TODO: Implement password change API call
    // For now, just show success
    setPasswordSuccess(true)
    setCurrentPassword('')
    setNewPassword('')
    setConfirmPassword('')
    setShowPasswordForm(false)
  }

  const formatDate = (dateString?: string) => {
    if (!dateString) return '-'
    return new Date(dateString).toLocaleString()
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">{t('profile.title')}</h1>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        {/* Personal Information */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <User className="h-5 w-5" />
              {t('profile.personalInfo')}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center gap-3">
              <div className="flex h-16 w-16 items-center justify-center rounded-full bg-primary/10">
                <span className="text-2xl font-bold text-primary">
                  {attributes?.username?.slice(0, 2).toUpperCase() || 'U'}
                </span>
              </div>
              <div>
                <p className="text-lg font-semibold">{attributes?.display_name || attributes?.username}</p>
                <p className="text-sm text-muted-foreground">@{attributes?.username}</p>
              </div>
            </div>

            <Separator />

            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <Mail className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm text-muted-foreground">{t('profile.email')}:</span>
                <span className="text-sm">{attributes?.email || '-'}</span>
              </div>

              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm text-muted-foreground">{t('profile.role')}:</span>
                <Badge variant="secondary">{attributes?.role || 'user'}</Badge>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-sm text-muted-foreground">{t('profile.status')}:</span>
                <Badge variant={identity?.status === 'active' ? 'default' : 'destructive'}>
                  {identity?.status || 'unknown'}
                </Badge>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Account Details */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Key className="h-5 w-5" />
              {t('profile.security')}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <span className="text-sm text-muted-foreground">{t('common.id')}:</span>
                <code className="rounded bg-muted px-2 py-1 text-xs">{identity?.id}</code>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-sm text-muted-foreground">{t('common.type')}:</span>
                <Badge variant="outline">{identity?.type}</Badge>
              </div>

              <div className="flex items-center gap-2">
                <Calendar className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm text-muted-foreground">{t('profile.createdAt')}:</span>
                <span className="text-sm">{formatDate(identity?.created_at)}</span>
              </div>

              <div className="flex items-center gap-2">
                <Clock className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm text-muted-foreground">{t('common.updatedAt')}:</span>
                <span className="text-sm">{formatDate(identity?.updated_at)}</span>
              </div>
            </div>

            <Separator />

            <div>
              <Button
                variant="outline"
                className="w-full"
                onClick={() => setShowPasswordForm(!showPasswordForm)}
              >
                <Lock className="mr-2 h-4 w-4" />
                {t('profile.changePassword')}
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Change Password Form */}
        {showPasswordForm && (
          <Card className="md:col-span-2">
            <CardHeader>
              <CardTitle>{t('profile.changePassword')}</CardTitle>
              <CardDescription>
                {t('profile.security')}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handlePasswordChange} className="space-y-4">
                <div className="grid gap-4 md:grid-cols-3">
                  <div className="space-y-2">
                    <Label htmlFor="current-password">{t('profile.currentPassword')}</Label>
                    <Input
                      id="current-password"
                      type="password"
                      value={currentPassword}
                      onChange={(e) => setCurrentPassword(e.target.value)}
                      required
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="new-password">{t('profile.newPassword')}</Label>
                    <Input
                      id="new-password"
                      type="password"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      required
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="confirm-password">{t('profile.confirmPassword')}</Label>
                    <Input
                      id="confirm-password"
                      type="password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      required
                    />
                  </div>
                </div>

                {passwordError && (
                  <p className="text-sm text-destructive">{passwordError}</p>
                )}

                {passwordSuccess && (
                  <p className="text-sm text-green-600">{t('profile.passwordUpdated')}</p>
                )}

                <div className="flex gap-2">
                  <Button type="submit">{t('common.save')}</Button>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => setShowPasswordForm(false)}
                  >
                    {t('common.cancel')}
                  </Button>
                </div>
              </form>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  )
}
