import { defineStore } from 'pinia'
import { ref } from 'vue'

interface BrandingConfig {
  brandName: string
  brandTitle: string
  documentTitle: string
  logoUrl: string
  faviconUrl: string
}

const defaults: BrandingConfig = {
  brandName: 'VPN Access Control',
  brandTitle: 'VPN 管理后台',
  documentTitle: 'VPN Access Control - VPN 管理后台',
  logoUrl: '/branding/logo.svg',
  faviconUrl: '/branding/logo.svg',
}

function stringValue(value: unknown, fallback: string): string {
  return typeof value === 'string' && value.trim() ? value.trim() : fallback
}

function optionalString(value: unknown, fallback: string): string {
  return typeof value === 'string' ? value.trim() : fallback
}

function applyFavicon(url: string) {
  let link = document.querySelector<HTMLLinkElement>('link[rel="icon"]')
  if (!link) {
    link = document.createElement('link')
    link.rel = 'icon'
    document.head.appendChild(link)
  }
  link.href = url
  if (url.endsWith('.svg')) {
    link.type = 'image/svg+xml'
  }
}

export const useBrandingStore = defineStore('branding', () => {
  const brandName = ref(defaults.brandName)
  const brandTitle = ref(defaults.brandTitle)
  const documentTitle = ref(defaults.documentTitle)
  const logoUrl = ref(defaults.logoUrl)
  const faviconUrl = ref(defaults.faviconUrl)
  const loaded = ref(false)

  async function load() {
    try {
      const response = await fetch(
        `${import.meta.env.BASE_URL}branding.json`,
        { cache: 'no-store' },
      )
      if (!response.ok) {
        throw new Error(`branding request failed: ${response.status}`)
      }
      const data = (await response.json()) as Partial<BrandingConfig>
      brandName.value = stringValue(data.brandName, defaults.brandName)
      brandTitle.value = stringValue(data.brandTitle, defaults.brandTitle)
      documentTitle.value = stringValue(
        data.documentTitle,
        `${brandName.value} - ${brandTitle.value}`,
      )
      logoUrl.value = optionalString(data.logoUrl, defaults.logoUrl)
      faviconUrl.value = optionalString(data.faviconUrl, defaults.faviconUrl)
    } catch {
      brandName.value = defaults.brandName
      brandTitle.value = defaults.brandTitle
      documentTitle.value = defaults.documentTitle
      logoUrl.value = defaults.logoUrl
      faviconUrl.value = defaults.faviconUrl
    }

    document.title =
      documentTitle.value || `${brandName.value} - ${brandTitle.value}`
    if (faviconUrl.value) {
      applyFavicon(faviconUrl.value)
    }
    loaded.value = true
  }

  return {
    brandName,
    brandTitle,
    documentTitle,
    logoUrl,
    faviconUrl,
    loaded,
    load,
  }
})