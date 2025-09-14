"use client"

import { useAuth } from "@/hooks/use-auth"
import { WelcomeScreen } from "@/components/welcome-screen"
import { AuthLoadingScreen } from "@/components/auth-loading-screen"

export default function HomePage() {
  const { user, isLoading, isAuthenticated } = useAuth()

  // Show loading screen while checking auth
  if (isLoading) {
    return <AuthLoadingScreen message="Checking authentication..." />
  }

  // Show loading if not authenticated (middleware will redirect)
  if (!isAuthenticated || !user) {
    return <AuthLoadingScreen message="Loading..." />
  }

  // Determine user access based on permissions
  const userAccess = user.permissions.length > 0 ? "granted" : "denied"

  return (
    <main className="min-h-screen bg-background">
      <WelcomeScreen userAccess={userAccess} userName={user.name} onRetry={() => window.location.reload()} />
    </main>
  )
}
