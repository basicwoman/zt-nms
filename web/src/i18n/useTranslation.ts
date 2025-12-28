import { useSettingsStore } from '@/stores/settings'
import { translations } from './translations'

export function useTranslation() {
  const language = useSettingsStore((state) => state.language)

  const t = (path: string, params?: Record<string, string | number>): string => {
    const keys = path.split('.')
    let value: unknown = translations[language]

    for (const key of keys) {
      if (value && typeof value === 'object' && key in value) {
        value = (value as Record<string, unknown>)[key]
      } else {
        console.warn(`Translation missing for: ${path}`)
        return path
      }
    }

    if (typeof value !== 'string') {
      console.warn(`Translation value is not a string for: ${path}`)
      return path
    }

    if (params) {
      return Object.entries(params).reduce(
        (result, [key, val]) => result.replace(new RegExp(`{{${key}}}`, 'g'), String(val)),
        value
      )
    }

    return value
  }

  return { t, language }
}
