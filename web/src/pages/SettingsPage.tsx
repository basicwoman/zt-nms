import { Settings, Globe, Palette, Bell } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Separator } from '@/components/ui/separator'
import { useSettingsStore, Language, Theme } from '@/stores/settings'
import { useTranslation } from '@/i18n/useTranslation'

export function SettingsPage() {
  const { t } = useTranslation()
  const { language, theme, setLanguage, setTheme } = useSettingsStore()

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">{t('settings.title')}</h1>
      </div>

      <div className="grid gap-6">
        {/* General Settings */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Settings className="h-5 w-5" />
              {t('settings.general')}
            </CardTitle>
            <CardDescription>
              {t('settings.appearance')}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Language Selection */}
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Globe className="h-5 w-5 text-muted-foreground" />
                <div>
                  <Label className="text-base">{t('settings.language')}</Label>
                  <p className="text-sm text-muted-foreground">
                    {t('languages.' + language)}
                  </p>
                </div>
              </div>
              <Select value={language} onValueChange={(value) => setLanguage(value as Language)}>
                <SelectTrigger className="w-40">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ru">
                    <span className="flex items-center gap-2">
                      🇷🇺 Русский
                    </span>
                  </SelectItem>
                  <SelectItem value="en">
                    <span className="flex items-center gap-2">
                      🇬🇧 English
                    </span>
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>

            <Separator />

            {/* Theme Selection */}
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Palette className="h-5 w-5 text-muted-foreground" />
                <div>
                  <Label className="text-base">{t('settings.theme')}</Label>
                  <p className="text-sm text-muted-foreground">
                    {theme === 'light' && t('settings.lightTheme')}
                    {theme === 'dark' && t('settings.darkTheme')}
                    {theme === 'system' && t('settings.systemTheme')}
                  </p>
                </div>
              </div>
              <Select value={theme} onValueChange={(value) => setTheme(value as Theme)}>
                <SelectTrigger className="w-40">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="light">{t('settings.lightTheme')}</SelectItem>
                  <SelectItem value="dark">{t('settings.darkTheme')}</SelectItem>
                  <SelectItem value="system">{t('settings.systemTheme')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </CardContent>
        </Card>

        {/* Notification Settings */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Bell className="h-5 w-5" />
              {t('settings.notifications')}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <Label className="text-base">{t('settings.emailNotifications')}</Label>
                <p className="text-sm text-muted-foreground">
                  {t('profile.email')}
                </p>
              </div>
              <Switch defaultChecked />
            </div>

            <Separator />

            <div className="flex items-center justify-between">
              <div>
                <Label className="text-base">{t('settings.pushNotifications')}</Label>
                <p className="text-sm text-muted-foreground">
                  {t('header.notifications')}
                </p>
              </div>
              <Switch defaultChecked />
            </div>

            <Separator />

            <div className="flex items-center justify-between">
              <div>
                <Label className="text-base">{t('settings.securityAlerts')}</Label>
                <p className="text-sm text-muted-foreground">
                  {t('profile.security')}
                </p>
              </div>
              <Switch defaultChecked />
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
