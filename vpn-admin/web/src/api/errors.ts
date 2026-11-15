import axios from 'axios'

export function apiErrorMessage(error: unknown): string {
  if (axios.isAxiosError(error)) {
    const data = error.response?.data as
      | { error?: { message?: string } }
      | undefined
    return data?.error?.message ?? error.message
  }
  return error instanceof Error ? error.message : '请求失败'
}