import { api } from './client'

export async function downloadCsv(
  path: string,
  params: Record<string, unknown>,
  filename: string,
) {
  const response = await api.get(path, {
    params,
    responseType: 'blob',
  })
  const blob = new Blob([response.data], {
    type: 'text/csv;charset=utf-8',
  })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}