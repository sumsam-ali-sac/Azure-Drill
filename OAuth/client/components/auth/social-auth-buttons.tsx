"use client"

import { Button } from "@/components/ui/button"
import { useState } from "react"
import { Loader2 } from "lucide-react"
import { useAuth } from "@/hooks/use-auth"
import { useRouter } from "next/navigation"

export function SocialAuthButtons() {
  const [loadingProvider, setLoadingProvider] = useState<string | null>(null)
  const { socialLogin } = useAuth()
  const router = useRouter()

  const handleSocialAuth = async (provider: "google" | "azure") => {
    setLoadingProvider(provider)

    try {
      const result = await socialLogin(provider)

      if (result.success) {
        router.push("/")
      } else {
        alert(result.error || "Social login failed")
      }
    } catch (error) {
      console.error("Social auth error:", error)
      alert("Authentication failed. Please try again.")
    } finally {
      setLoadingProvider(null)
    }
  }

  return (
    <div className="grid grid-cols-2 gap-4">
      <Button
        variant="outline"
        onClick={() => handleSocialAuth("google")}
        disabled={loadingProvider !== null}
        className="relative h-12 bg-card/50 border-border/60 hover:bg-accent/10 hover:border-primary/30 transition-all duration-200 group"
      >
        {loadingProvider === "google" ? (
          <Loader2 className="h-4 w-4 animate-spin" />
        ) : (
          <>
            <svg className="mr-2 h-5 w-5 group-hover:scale-110 transition-transform" viewBox="0 0 24 24">
              <path
                fill="#4285F4"
                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
              />
              <path
                fill="#34A853"
                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
              />
              <path
                fill="#FBBC05"
                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
              />
              <path
                fill="#EA4335"
                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
              />
            </svg>
            <span className="font-medium">Google</span>
          </>
        )}
      </Button>

      <Button
        variant="outline"
        onClick={() => handleSocialAuth("azure")}
        disabled={loadingProvider !== null}
        className="relative h-12 bg-card/50 border-border/60 hover:bg-accent/10 hover:border-primary/30 transition-all duration-200 group"
      >
        {loadingProvider === "azure" ? (
          <Loader2 className="h-4 w-4 animate-spin" />
        ) : (
          <>
            <svg className="mr-2 h-5 w-5 group-hover:scale-110 transition-transform" viewBox="0 0 24 24">
              <path fill="#0078D4" d="M0 0h11v11H0zm13 0h11v11H13zM0 13h11v11H0zm13 0h11v11H13z" />
            </svg>
            <span className="font-medium">Azure</span>
          </>
        )}
      </Button>
    </div>
  )
}
