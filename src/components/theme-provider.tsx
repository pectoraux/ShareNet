'use client'

import * as React from 'react'
import { ThemeProvider as NextThemesProvider } from 'next-themes'

/**
 * Thin client wrapper around next-themes so the server-rendered layout can
 * mount the theme context. Mounted with `attribute="class"` so the `.dark`
 * Tailwind variant activates on `<html>`.
 */
export function ThemeProvider({
  children,
  ...props
}: React.ComponentProps<typeof NextThemesProvider>) {
  return <NextThemesProvider {...props}>{children}</NextThemesProvider>
}
