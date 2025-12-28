import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Key, Fingerprint, Loader2, Globe } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { useAuthStore } from '@/stores/auth'
import { useSettingsStore } from '@/stores/settings'
import { useTranslation } from '@/i18n/useTranslation'
import { authApi } from '@/api/client'

export function LoginPage() {
  const navigate = useNavigate()
  const { login } = useAuthStore()
  const { language, setLanguage } = useSettingsStore()
  const { t } = useTranslation()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [mfaRequired, setMfaRequired] = useState(false)
  const [mfaCode, setMfaCode] = useState('')

  // For demo purposes - in production would use actual crypto
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [privateKey, setPrivateKey] = useState('')

  const handlePasswordLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)

    try {
      const result = await authApi.login({ username, password })

      if (result.access_token) {
        login(result.access_token, result.identity)
        navigate('/')
      }
    } catch (err) {
      console.error('Login error:', err)
      setError(t('auth.authFailed'))
    } finally {
      setLoading(false)
    }
  }

  const handleKeyLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)

    try {
      const { challenge } = await authApi.getChallenge()

      // Parse private key and sign challenge
      // In production, use actual Ed25519 signing
      const encoder = new TextEncoder()
      const keyData = encoder.encode(privateKey)
      const challengeData = encoder.encode(challenge)
      const combined = new Uint8Array([...keyData.slice(0, 32), ...challengeData.slice(0, 32)])
      const hashBuffer = await crypto.subtle.digest('SHA-256', combined)
      const signature = btoa(String.fromCharCode(...new Uint8Array(hashBuffer)))

      // Extract public key from private key (demo)
      const publicKey = btoa(String.fromCharCode(...new Uint8Array(keyData.slice(0, 32))))

      const result = await authApi.authenticate({
        public_key: publicKey,
        challenge,
        signature,
      })

      if (result.access_token) {
        login(result.access_token, result.identity)
        navigate('/')
      }
    } catch (err) {
      console.error('Login error:', err)
      setError(t('auth.authFailed'))
    } finally {
      setLoading(false)
    }
  }

  const handleMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    // In production, verify MFA code
    setMfaRequired(false)
    setLoading(false)
  }

  if (mfaRequired) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-slate-900 to-slate-800">
        {/* Language selector */}
        <div className="absolute right-4 top-4">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="icon">
                <Globe className="h-5 w-5" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={() => setLanguage('ru')}>
                <span className={language === 'ru' ? 'font-bold' : ''}>🇷🇺 Русский</span>
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => setLanguage('en')}>
                <span className={language === 'en' ? 'font-bold' : ''}>🇬🇧 English</span>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>

        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-primary/10">
              <Fingerprint className="h-8 w-8 text-primary" />
            </div>
            <CardTitle className="text-2xl">{t('auth.twoFactor')}</CardTitle>
            <CardDescription>{t('auth.enterCode')}</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleMfaSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="mfa-code">{t('auth.authCode')}</Label>
                <Input
                  id="mfa-code"
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value)}
                  placeholder="000000"
                  maxLength={6}
                  className="text-center text-2xl tracking-widest"
                />
              </div>
              {error && <p className="text-sm text-destructive">{error}</p>}
              <Button type="submit" className="w-full" disabled={loading}>
                {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {t('auth.verify')}
              </Button>
              <Button
                type="button"
                variant="link"
                className="w-full"
                onClick={() => setMfaRequired(false)}
              >
                {t('auth.backToLogin')}
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-slate-900 to-slate-800">
      {/* Language selector */}
      <div className="absolute right-4 top-4">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" size="icon">
              <Globe className="h-5 w-5" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={() => setLanguage('ru')}>
              <span className={language === 'ru' ? 'font-bold' : ''}>🇷🇺 Русский</span>
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => setLanguage('en')}>
              <span className={language === 'en' ? 'font-bold' : ''}>🇬🇧 English</span>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-primary/10">
            <Shield className="h-8 w-8 text-primary" />
          </div>
          <CardTitle className="text-2xl">ZT-NMS</CardTitle>
          <CardDescription>Zero Trust Network Management System</CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="password" className="w-full">
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="password">{t('auth.passwordTab')}</TabsTrigger>
              <TabsTrigger value="key">{t('auth.keyTab')}</TabsTrigger>
            </TabsList>

            <TabsContent value="password">
              <form onSubmit={handlePasswordLogin} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="username">{t('auth.username')}</Label>
                  <Input
                    id="username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder={t('auth.username')}
                    required
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="password">{t('auth.password')}</Label>
                  <Input
                    id="password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder={t('auth.password')}
                    required
                  />
                </div>
                {error && <p className="text-sm text-destructive">{error}</p>}
                <Button type="submit" className="w-full" disabled={loading}>
                  {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  {t('auth.signIn')}
                </Button>
              </form>
            </TabsContent>

            <TabsContent value="key">
              <form onSubmit={handleKeyLogin} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="private-key">{t('auth.privateKey')}</Label>
                  <div className="relative">
                    <Key className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                    <textarea
                      id="private-key"
                      value={privateKey}
                      onChange={(e) => setPrivateKey(e.target.value)}
                      placeholder={t('auth.privateKey')}
                      className="min-h-[100px] w-full rounded-md border border-input bg-background px-3 py-2 pl-10 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                      required
                    />
                  </div>
                </div>
                {error && <p className="text-sm text-destructive">{error}</p>}
                <Button type="submit" className="w-full" disabled={loading}>
                  {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  {t('auth.authenticate')}
                </Button>
              </form>
            </TabsContent>
          </Tabs>

          <div className="mt-6 text-center text-sm text-muted-foreground">
            <p>{t('auth.zeroTrust')}</p>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
